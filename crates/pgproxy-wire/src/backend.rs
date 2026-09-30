//! Connecting to a PostgreSQL backend as a *client*.
//!
//! Every other part of this crate speaks protocol-server; this is the mirror image. It is
//! needed the moment the proxy stops being a pure relay:
//!
//! * **Transaction pooling** cannot relay authentication, because the backend connection
//!   that serves a query is not the one the client authenticated on. The proxy must hold
//!   connections that are *already authenticated*, which means it must authenticate to the
//!   backend itself.
//! * **Terminating client authentication** (what the policy engine will need, so it can
//!   reject a client before spending a backend) requires the same machinery.
//!
//! ## The trade-off this makes explicit
//!
//! Authenticating to a backend needs a credential. That is exactly PgBouncer's documented
//! bind: against managed providers that block `pg_authid`, a proxy must be given the
//! password in plaintext, and a SCRAM verifier cannot be reused because it is bound to the
//! server's salt and iteration count.
//!
//! **Session mode avoids this entirely** by relaying, which is why passthrough is the
//! default there and is validated in `tests/conformance`. Transaction mode cannot avoid
//! it, and this module is honest about the requirement: a `password` on the database entry,
//! or a backend that trusts the proxy.

use std::io;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, Instant};

use tracing::debug;

use crate::auth::messages::{self as auth, AuthenticationRequest};
use crate::auth::scram::ScramClient;
use crate::auth::{AuthError, md5};
use crate::protocol::codec::{Frame, FrameReader, FrameWriter};
use crate::protocol::messages::{Severity, sqlstate};
use crate::protocol::{PROTOCOL_3_0, backend, backend_name, frontend};

use crate::session::BackendTarget;

/// How the proxy identifies itself to a backend.
#[derive(Clone)]
pub struct BackendCredentials {
    /// Role to connect as.
    pub user: String,
    /// Password, required only if the backend challenges.
    pub password: Option<String>,
    /// Database to request; `None` uses the target's database.
    pub database: Option<String>,
    /// Value for `application_name`, so sessions are attributable in `pg_stat_activity`.
    pub application_name: Option<String>,
}

impl std::fmt::Debug for BackendCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackendCredentials")
            .field("user", &self.user)
            .field("password", &self.password.as_ref().map(|_| "[REDACTED]"))
            .field("database", &self.database)
            .field("application_name", &self.application_name)
            .finish()
    }
}

/// A connection to a backend that has completed its startup handshake.
pub struct BackendConnection {
    _tls_bridge: Option<crate::tls::TlsBridge>,
    tls_options: Option<crate::backend_tls::BackendTls>,
    address: SocketAddr,
    reader: FrameReader<TcpStream>,
    writer: FrameWriter<TcpStream>,
    parameters: Vec<(String, String)>,
    process_id: i32,
    cancel_key: Vec<u8>,
    user: String,
    database: String,
    failover_generation: Option<(Arc<AtomicU64>, u64)>,
    failover_invalidation: Option<Arc<dyn Fn(u64) -> bool + Send + Sync>>,
    credential_expiry: Option<Instant>,
    healthy: bool,
    require_primary: bool,
    transaction_status: u8,
    capacity_permit: Option<pgproxy_pool::ConnectionPermit>,
}

impl BackendConnection {
    /// Open a connection and complete the startup and authentication handshake.
    pub fn connect(
        target: &BackendTarget,
        credentials: &BackendCredentials,
        timeout: Duration,
        max_message_len: usize,
    ) -> io::Result<Self> {
        Self::connect_with_tls(target, credentials, timeout, max_message_len, None)
    }
    pub fn connect_with_tls(
        target: &BackendTarget,
        credentials: &BackendCredentials,
        timeout: Duration,
        max_message_len: usize,
        tls_options: Option<&crate::backend_tls::BackendTls>,
    ) -> io::Result<Self> {
        let deadline = Instant::now() + timeout;
        let stream = open_stream(target, timeout)?;
        let address = stream.peer_addr()?;
        let tls_bridge = tls_options
            .map(|tls| {
                tls.connect(
                    stream.try_clone()?,
                    deadline
                        .checked_duration_since(Instant::now())
                        .ok_or_else(|| {
                            io::Error::new(io::ErrorKind::TimedOut, "backend startup deadline")
                        })?,
                )
            })
            .transpose()?;
        let stream = if let Some(bridge) = &tls_bridge {
            bridge.stream.try_clone()?
        } else {
            stream
        };
        let binding = tls_bridge
            .as_ref()
            .and_then(|bridge| bridge.channel_binding.clone());
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        let mut reader = FrameReader::with_max_message_len(stream.try_clone()?, max_message_len);
        let mut writer = FrameWriter::new(stream);

        let database = credentials
            .database
            .clone()
            .or_else(|| target.database.clone())
            .unwrap_or_else(|| credentials.user.clone());

        let packet = startup_packet(credentials, &database);
        writer.write_raw(&packet)?;
        writer.flush()?;

        let mut parameters = Vec::new();
        let mut process_id = 0i32;
        let mut cancel_key = Vec::new();
        let mut scram: Option<ScramClient> = None;
        let mut bound_auth_verified = false;
        let mut scram_verified = false;

        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::TimedOut, "backend startup deadline")
                })?;
            reader.get_ref().set_read_timeout(Some(remaining))?;
            writer.get_ref().set_write_timeout(Some(remaining))?;
            let frame = reader
                .read_message_checked(|stream| {
                    stream.set_read_timeout(Some(
                        deadline
                            .checked_duration_since(Instant::now())
                            .ok_or_else(|| {
                                io::Error::new(io::ErrorKind::TimedOut, "backend startup deadline")
                            })?,
                    ))
                })?
                .ok_or_else(|| io::Error::other("backend closed during startup"))?;

            match frame.tag {
                backend::AUTHENTICATION => {
                    let request = AuthenticationRequest::parse(frame.payload)
                        .map_err(|e| io::Error::other(e.to_string()))?;
                    match request {
                        AuthenticationRequest::Ok => {
                            if scram.is_some() && !scram_verified {
                                return Err(io::Error::other(
                                    "backend completed SCRAM without a verified server signature",
                                ));
                            }
                            if tls_options.is_some_and(|t| t.require_channel_binding)
                                && !bound_auth_verified
                            {
                                return Err(io::Error::other(
                                    "backend authentication did not verify required channel binding",
                                ));
                            }
                        }
                        AuthenticationRequest::CleartextPassword => {
                            if tls_options.is_some_and(|t| t.require_channel_binding) {
                                return Err(io::Error::other(
                                    "backend requested unbound password authentication",
                                ));
                            }
                            let password = require_password(credentials)?;
                            let payload = auth::password_message(password);
                            writer.write_message(frontend::PASSWORD, &payload)?;
                            writer.flush()?;
                        }
                        AuthenticationRequest::Md5Password { salt } => {
                            if tls_options.is_some_and(|t| t.require_channel_binding) {
                                return Err(io::Error::other(
                                    "backend requested unbound MD5 authentication",
                                ));
                            }
                            let password = require_password(credentials)?;
                            let stored = md5::hash_password(password.as_bytes(), &credentials.user);
                            let response = md5::response(&stored, &salt)
                                .map_err(|e| io::Error::other(e.to_string()))?;
                            let payload = auth::password_message(&response);
                            writer.write_message(frontend::PASSWORD, &payload)?;
                            writer.flush()?;
                        }
                        AuthenticationRequest::Sasl { mechanisms } => {
                            let password = require_password(credentials)?;
                            let plus = binding.is_some()
                                && mechanisms.iter().any(|m| m == "SCRAM-SHA-256-PLUS");
                            if tls_options.is_some_and(|t| t.require_channel_binding) && !plus {
                                return Err(io::Error::other(
                                    "backend did not offer required SCRAM channel binding",
                                ));
                            }
                            if !plus
                                && !mechanisms
                                    .iter()
                                    .any(|m| m == crate::auth::scram::MECHANISM)
                            {
                                return Err(io::Error::other(
                                    "backend offers no supported SCRAM mechanism",
                                ));
                            }
                            let mut client = ScramClient::new(password.as_bytes());
                            if plus {
                                client = client.with_channel_binding(
                                    binding.clone().expect("binding checked"),
                                );
                            }
                            let first = client.client_first();
                            let payload =
                                auth::sasl_initial_response(client.mechanism(), first.as_bytes());
                            writer.write_message(frontend::PASSWORD, &payload)?;
                            writer.flush()?;
                            scram = Some(client);
                        }
                        AuthenticationRequest::SaslContinue(data) => {
                            let client = scram.as_mut().ok_or_else(|| {
                                io::Error::other("backend sent SASLContinue before SASL")
                            })?;
                            let message = String::from_utf8_lossy(&data).into_owned();
                            let final_message =
                                client.handle_server_first(&message).map_err(scram_error)?;
                            // A SASL *continuation* is a bare PasswordMessage: the payload is
                            // the SASL bytes with no length prefix and no null terminator.
                            // Only the *initial* response carries a mechanism name and length.
                            writer.write_message(frontend::PASSWORD, final_message.as_bytes())?;
                            writer.flush()?;
                        }
                        AuthenticationRequest::SaslFinal(data) => {
                            let client = scram.as_mut().ok_or_else(|| {
                                io::Error::other("backend sent SASLFinal before SASL")
                            })?;
                            let message = String::from_utf8_lossy(&data).into_owned();
                            client.handle_server_final(&message).map_err(scram_error)?;
                            scram_verified = true;
                            bound_auth_verified =
                                binding.is_some() && client.mechanism() == "SCRAM-SHA-256-PLUS";
                        }
                        other => {
                            return Err(io::Error::other(format!(
                                "backend requested unsupported authentication: {other:?}"
                            )));
                        }
                    }
                }
                backend::PARAMETER_STATUS => {
                    if let Some((name, value)) = parse_parameter_status(frame.payload) {
                        parameters.push((name, value));
                    }
                }
                backend::BACKEND_KEY_DATA => {
                    if frame.payload.len() >= 4 {
                        process_id = i32::from_be_bytes([
                            frame.payload[0],
                            frame.payload[1],
                            frame.payload[2],
                            frame.payload[3],
                        ]);
                        // Variable length as of protocol 3.2; keep whatever arrives.
                        cancel_key = frame.payload[4..].to_vec();
                    }
                }
                backend::ERROR_RESPONSE => {
                    let message = parse_error_message(frame.payload)
                        .unwrap_or_else(|| "backend rejected the connection".to_string());
                    return Err(io::Error::other(message));
                }
                backend::NOTICE_RESPONSE => {
                    debug!("backend notice during startup");
                }
                backend::READY_FOR_QUERY => break,
                other => {
                    debug!(
                        message = backend_name(other),
                        "ignoring unexpected message during startup"
                    );
                }
            }
        }

        Ok(Self {
            _tls_bridge: tls_bridge,
            tls_options: tls_options.cloned(),
            address,
            reader,
            writer,
            parameters,
            process_id,
            cancel_key,
            user: credentials.user.clone(),
            database,
            failover_generation: None,
            failover_invalidation: None,
            credential_expiry: None,
            healthy: true,
            require_primary: false,
            transaction_status: b'I',
            capacity_permit: None,
        })
    }

    pub fn with_failover_generation(mut self, epoch: Arc<AtomicU64>, generation: u64) -> Self {
        self.failover_generation = Some((epoch, generation));
        self
    }
    pub fn with_failover_invalidation(
        mut self,
        invalidate: Arc<dyn Fn(u64) -> bool + Send + Sync>,
    ) -> Self {
        self.failover_invalidation = Some(invalidate);
        self
    }
    /// Retire other sockets from this route generation after a failed role check.
    /// The selection lock makes invalidation and route changes one atomic operation.
    pub fn invalidate_generation_if_current(&self) -> bool {
        match (&self.failover_generation, &self.failover_invalidation) {
            (Some((_, generation)), Some(invalidate)) => invalidate(*generation),
            _ => false,
        }
    }
    pub fn with_credential_expiry(mut self, expiry: Option<Instant>) -> Self {
        self.credential_expiry = expiry;
        self
    }
    pub fn generation_is_current(&self) -> bool {
        self.failover_generation
            .as_ref()
            .is_none_or(|(epoch, generation)| epoch.load(Ordering::Acquire) == *generation)
    }
    pub fn credentials_are_current(&self) -> bool {
        self.credential_expiry
            .is_none_or(|expiry| Instant::now() < expiry)
    }
    fn ensure_ownership_current(&mut self) -> io::Result<()> {
        if self.generation_is_current() && self.credentials_are_current() {
            Ok(())
        } else {
            self.healthy = false;
            Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "backend routing generation or credential lease expired",
            ))
        }
    }
    pub fn with_capacity_permit(mut self, permit: pgproxy_pool::ConnectionPermit) -> Self {
        self.capacity_permit = Some(permit);
        self
    }

    pub fn backend_address(&self) -> SocketAddr {
        self.address
    }
    pub fn tls_options(&self) -> Option<&crate::backend_tls::BackendTls> {
        self.tls_options.as_ref()
    }

    /// Bound blocking backend reads, including reset queries and startup exchanges.
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.reader.get_ref().set_read_timeout(timeout)
    }
    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.writer.get_ref().set_write_timeout(timeout)
    }

    /// Borrow the reader and writer together.
    ///
    /// Returns disjoint borrows so a frame read from the reader can be written straight to
    /// the writer without copying — the relay path.
    pub fn split(&mut self) -> (&mut FrameReader<TcpStream>, &mut FrameWriter<TcpStream>) {
        (&mut self.reader, &mut self.writer)
    }

    /// Read one message from the backend.
    pub fn read_message(&mut self) -> io::Result<Option<Frame<'_>>> {
        self.reader.read_message()
    }

    /// Bound every partial transport read and reject retired/expired ownership.
    pub fn read_message_with_deadline(
        &mut self,
        deadline: Instant,
    ) -> io::Result<Option<Frame<'_>>> {
        self.ensure_ownership_current()?;
        let generation = self.failover_generation.clone();
        let expiry = self.credential_expiry;
        let result = self.reader.read_message_checked(move |stream| {
            let now = Instant::now();
            if generation
                .as_ref()
                .is_some_and(|(epoch, observed)| epoch.load(Ordering::Acquire) != *observed)
                || expiry.is_some_and(|expires| now >= expires)
            {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "backend ownership retired",
                ));
            }
            let remaining = deadline
                .checked_duration_since(now)
                .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "backend read deadline"))?;
            let remaining = expiry
                .and_then(|expires| expires.checked_duration_since(now))
                .map_or(remaining, |lease| remaining.min(lease));
            stream.set_read_timeout(Some(remaining))
        });
        if result.is_err() {
            self.healthy = false;
        }
        result
    }

    /// Send an already-framed message.
    pub fn write_raw(&mut self, raw: &[u8]) -> io::Result<()> {
        self.writer.write_raw(raw)
    }

    /// Run a simple query and discard the results, returning the final transaction status.
    ///
    /// Used to reset a connection before it goes back into the pool. `DISCARD ALL` is the
    /// blunt instrument that makes transaction pooling *safe*; it is also why prepared
    /// statements break under it, which is precisely what Phase 1 exists to fix.
    pub fn simple_query(&mut self, sql: &str) -> io::Result<u8> {
        let mut payload = Vec::with_capacity(sql.len() + 1);
        payload.extend_from_slice(sql.as_bytes());
        payload.push(0);
        self.writer.write_message(frontend::QUERY, &payload)?;
        self.writer.flush()?;

        loop {
            let frame = self
                .reader
                .read_message()?
                .ok_or_else(|| io::Error::other("backend closed during reset"))?;
            match frame.tag {
                backend::READY_FOR_QUERY => {
                    let status = frame.payload.first().copied().unwrap_or(b'I');
                    self.transaction_status = status;
                    return Ok(status);
                }
                backend::ERROR_RESPONSE => {
                    let message = parse_error_message(frame.payload)
                        .unwrap_or_else(|| "reset query failed".to_string());
                    self.healthy = false;
                    return Err(io::Error::other(message));
                }
                _ => {}
            }
        }
    }

    /// Primary-only routes recheck role before every backend handoff.
    pub fn require_primary(&mut self, required: bool) {
        self.require_primary = required;
    }
    pub fn verify_primary(&mut self) -> io::Result<()> {
        let timeout = self
            .reader
            .get_ref()
            .read_timeout()?
            .unwrap_or(Duration::from_secs(10));
        self.verify_primary_with_deadline(Instant::now() + timeout)
    }
    pub fn verify_primary_with_deadline(&mut self, deadline: Instant) -> io::Result<()> {
        self.ensure_ownership_current()?;
        let previous_read_timeout = self.reader.get_ref().read_timeout()?;
        let previous_write_timeout = self.writer.get_ref().write_timeout()?;
        let result = (|| {
            self.apply_deadline(deadline)?;
            self.writer.write_message(frontend::QUERY,
                b"SELECT NOT pg_catalog.pg_is_in_recovery() AND pg_catalog.current_setting('transaction_read_only') = 'off'\0")?;
            self.writer.flush()?;
            let mut primary = None;
            loop {
                self.apply_deadline(deadline)?;
                let frame = self
                    .reader
                    .read_message_checked(|stream| {
                        stream.set_read_timeout(Some(
                            deadline
                                .checked_duration_since(Instant::now())
                                .ok_or_else(|| {
                                    io::Error::new(io::ErrorKind::TimedOut, "backend role deadline")
                                })?,
                        ))
                    })?
                    .ok_or_else(|| io::Error::other("backend closed during role check"))?;
                match frame.tag {
                    backend::DATA_ROW => {
                        if primary.is_some() {
                            return Err(io::Error::other("duplicate role check row"));
                        }
                        primary = Some(parse_boolean_row(frame.payload)?);
                    }
                    backend::ERROR_RESPONSE => {
                        return Err(io::Error::other("backend role check failed"));
                    }
                    backend::READY_FOR_QUERY => {
                        if frame.payload == b"I" && primary == Some(true) {
                            return Ok(());
                        }
                        return Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            "backend is not a writable primary",
                        ));
                    }
                    _ => {}
                }
            }
        })();
        let result = result.and_then(|()| {
            self.reader
                .get_ref()
                .set_read_timeout(previous_read_timeout)?;
            self.writer
                .get_ref()
                .set_write_timeout(previous_write_timeout)
        });
        if result.is_err() {
            self.invalidate_generation_if_current();
            self.healthy = false;
        }
        result
    }

    /// Check primary role before injecting trusted read-only/RLS/role settings.
    pub fn restore_session_in_context(
        &mut self,
        commands: &[pgproxy_session::RestoreCommand],
        context: &[String],
    ) -> io::Result<()> {
        use pgproxy_session::RestoreCommand;
        self.ensure_ownership_current()?;
        if self.require_primary {
            self.verify_primary()?;
        }
        let mut restored: Vec<RestoreCommand> =
            context.iter().cloned().map(RestoreCommand::Query).collect();
        for command in commands {
            match command {
                RestoreCommand::Query(sql) => {
                    restored.push(RestoreCommand::Query(sql.clone()));
                    if sql.eq_ignore_ascii_case("RESET ALL") {
                        restored.extend(context.iter().cloned().map(RestoreCommand::Query));
                    }
                }
                RestoreCommand::Parse(payload) => {
                    restored.push(RestoreCommand::Parse(payload.clone()))
                }
            }
        }
        self.restore_commands(&restored)
    }

    /// Pipeline the ledger restore in one network round trip and suppress its replies.
    pub fn restore_session(
        &mut self,
        commands: &[pgproxy_session::RestoreCommand],
    ) -> io::Result<()> {
        self.ensure_ownership_current()?;
        if self.require_primary {
            self.verify_primary()?;
        }
        self.restore_commands(commands)
    }
    fn restore_commands(&mut self, commands: &[pgproxy_session::RestoreCommand]) -> io::Result<()> {
        if commands.is_empty() {
            return Ok(());
        }
        let outcome = (|| {
            let mut completions = 1usize;
            for command in commands {
                match command {
                    pgproxy_session::RestoreCommand::Query(sql) => {
                        let mut payload = sql.as_bytes().to_vec();
                        payload.push(0);
                        self.writer.write_message(frontend::QUERY, &payload)?;
                        completions += 1;
                    }
                    pgproxy_session::RestoreCommand::Parse(payload) => {
                        self.writer.write_message(frontend::PARSE, payload)?
                    }
                }
            }
            self.writer.write_message(frontend::SYNC, &[])?;
            self.writer.flush()?;
            while completions != 0 {
                let frame = self
                    .reader
                    .read_message()?
                    .ok_or_else(|| io::Error::other("backend closed during session restore"))?;
                match frame.tag {
                    backend::ERROR_RESPONSE => {
                        return Err(io::Error::other(
                            parse_error_message(frame.payload)
                                .unwrap_or_else(|| "session restore failed".into()),
                        ));
                    }
                    backend::PARAMETER_STATUS => {
                        if let Some((name, value)) = parse_parameter_status(frame.payload) {
                            if let Some(parameter) =
                                self.parameters.iter_mut().find(|(key, _)| key == &name)
                            {
                                parameter.1 = value;
                            } else {
                                self.parameters.push((name, value));
                            }
                        }
                    }
                    backend::READY_FOR_QUERY => {
                        if frame.payload != b"I" {
                            return Err(io::Error::other("session restore did not end idle"));
                        }
                        completions -= 1;
                    }
                    _ => {}
                }
            }
            Ok(())
        })();
        if outcome.is_err() {
            self.healthy = false;
        }
        outcome
    }

    fn apply_deadline(&self, deadline: Instant) -> io::Result<()> {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "backend handshake deadline"))?;
        self.reader.get_ref().set_read_timeout(Some(remaining))?;
        self.writer.get_ref().set_write_timeout(Some(remaining))
    }
    /// Parameter set reported by the backend, for forwarding to clients.
    pub fn parameters(&self) -> &[(String, String)] {
        &self.parameters
    }

    /// Look up one backend parameter.
    pub fn parameter(&self, name: &str) -> Option<&str> {
        self.parameters
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// Backend process id.
    pub fn process_id(&self) -> i32 {
        self.process_id
    }

    /// Cancel key the backend issued.
    ///
    /// Bytes rather than an integer: protocol 3.2 allows up to 256 bits.
    pub fn cancel_key(&self) -> &[u8] {
        &self.cancel_key
    }

    /// Role this connection is authenticated as.
    pub fn user(&self) -> &str {
        &self.user
    }

    /// Database this connection is attached to.
    pub fn database(&self) -> &str {
        &self.database
    }

    /// Last transaction status the backend reported: `I`, `T` or `E`.
    pub fn transaction_status(&self) -> u8 {
        self.transaction_status
    }

    /// Record the transaction status observed by the relay.
    pub fn set_transaction_status(&mut self, status: u8) {
        self.transaction_status = status;
    }

    /// Whether a transaction is currently open.
    pub fn in_transaction(&self) -> bool {
        self.transaction_status != b'I'
    }

    /// Prepare the connection to be handed to a different client.
    ///
    /// This is what makes transaction pooling *safe*. Without it, session state — a
    /// changed `search_path`, a temp table, an open transaction — leaks into whoever gets
    /// the connection next, which is a correctness and tenant-isolation bug rather than a
    /// performance one. PgBouncer's equivalent is `server_reset_query = DISCARD ALL`;
    /// pgagroal's transaction pipeline does not do it at all and leaks.
    ///
    /// `DISCARD ALL` is also exactly why prepared statements break under transaction
    /// pooling, which is the trade-off Phase 1 exists to remove.
    pub fn reset_for_reuse(&mut self) -> io::Result<()> {
        // A connection abandoned mid-transaction cannot run DISCARD ALL, so roll back
        // first. Ignoring a rollback failure here is deliberate: the DISCARD ALL that
        // follows will fail too, and that is the error the caller acts on.
        if self.in_transaction() {
            let _ = self.simple_query("ROLLBACK");
        }
        self.simple_query("DISCARD ALL")?;
        Ok(())
    }

    /// Mark the connection as unsafe to reuse.
    pub fn mark_unhealthy(&mut self) {
        self.healthy = false;
    }

    /// Whether the connection is still believed usable.
    ///
    /// Idle pooled connections must have neither EOF nor unsolicited data. Pending data
    /// may be a fatal shutdown response; discard rather than delivering it to a new
    /// borrower. The probe never consumes bytes. Notification sessions retain ownership.
    pub fn is_healthy(&self) -> bool {
        if !self.healthy || !self.generation_is_current() || !self.credentials_are_current() {
            return false;
        }
        let stream = self.reader.get_ref();
        if stream.set_nonblocking(true).is_err() {
            return false;
        }
        let mut byte = [0];
        let probe = stream.peek(&mut byte);
        if stream.set_nonblocking(false).is_err() {
            return false;
        }
        match probe {
            Ok(_) => false,
            Err(error) => matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ),
        }
    }

    /// Send `Terminate` and close.
    pub fn terminate(mut self) {
        let _ = self.writer.write_message(frontend::TERMINATE, &[]);
        let _ = self.writer.flush();
    }
}

fn parse_boolean_row(payload: &[u8]) -> io::Result<bool> {
    // Exactly one text-format boolean column, no nulls or trailing data.
    if payload.len() == 7 && payload[..6] == [0, 1, 0, 0, 0, 1] {
        match payload[6] {
            b't' => return Ok(true),
            b'f' => return Ok(false),
            _ => {}
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid backend role result",
    ))
}

impl std::fmt::Debug for BackendConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackendConnection")
            .field("user", &self.user)
            .field("database", &self.database)
            .field("process_id", &self.process_id)
            .field("healthy", &self.healthy)
            .field("parameters", &self.parameters.len())
            .finish_non_exhaustive()
    }
}

fn require_password(credentials: &BackendCredentials) -> io::Result<&str> {
    credentials.password.as_deref().ok_or_else(|| {
        io::Error::other(format!(
            "the backend requires a password for role {:?} but none is configured; \
             transaction pooling needs a backend credential, unlike session-mode passthrough",
            credentials.user
        ))
    })
}

fn scram_error(e: AuthError) -> io::Error {
    io::Error::other(format!("SCRAM with the backend failed: {e}"))
}

/// Resolve and connect, trying each address in turn.
fn open_stream(target: &BackendTarget, timeout: Duration) -> io::Result<TcpStream> {
    let deadline = Instant::now() + timeout;
    let addrs: Vec<SocketAddr> = (target.host.as_str(), target.port)
        .to_socket_addrs()
        .map_err(|e| io::Error::new(io::ErrorKind::NotFound, e))?
        .collect();

    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "backend host resolved to no addresses",
        ));
    }

    let mut last_error = None;
    for addr in addrs {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "backend connect deadline"))?;
        match TcpStream::connect_timeout(&addr, remaining) {
            Ok(stream) => {
                let _ = stream.set_nodelay(true);
                return Ok(stream);
            }
            Err(e) => last_error = Some(e),
        }
    }
    Err(last_error.unwrap_or_else(|| io::Error::other("no backend address could be reached")))
}

/// Build a startup packet for the proxy's own connection to a backend.
fn startup_packet(credentials: &BackendCredentials, database: &str) -> Vec<u8> {
    let mut entries: Vec<(&str, &[u8])> = vec![
        ("user", credentials.user.as_bytes()),
        ("database", database.as_bytes()),
        ("client_encoding", b"UTF8"),
    ];
    if let Some(app) = &credentials.application_name {
        entries.push(("application_name", app.as_bytes()));
    }

    let mut body_len = 4 + 1;
    for (key, value) in &entries {
        body_len += key.len() + 1 + value.len() + 1;
    }

    let mut packet = Vec::with_capacity(4 + body_len);
    packet.extend_from_slice(&((body_len + 4) as i32).to_be_bytes());
    packet.extend_from_slice(&PROTOCOL_3_0.to_be_bytes());
    for (key, value) in &entries {
        packet.extend_from_slice(key.as_bytes());
        packet.push(0);
        packet.extend_from_slice(value);
        packet.push(0);
    }
    packet.push(0);
    packet
}

/// Extract `(name, value)` from a `ParameterStatus` payload.
pub fn parse_parameter_status(payload: &[u8]) -> Option<(String, String)> {
    let name_end = payload.iter().position(|&b| b == 0)?;
    let rest = &payload[name_end + 1..];
    let value_end = rest.iter().position(|&b| b == 0)?;
    Some((
        String::from_utf8_lossy(&payload[..name_end]).into_owned(),
        String::from_utf8_lossy(&rest[..value_end]).into_owned(),
    ))
}

/// Extract the human-readable message from an `ErrorResponse` payload.
///
/// Field layout is repeated `u8 code` + null-terminated value, ended by a zero byte; `M` is
/// the primary message and `C` the SQLSTATE.
pub fn parse_error_message(payload: &[u8]) -> Option<String> {
    let mut message = None;
    let mut severity = None;
    let mut code = None;

    let mut rest = payload;
    while !rest.is_empty() && rest[0] != 0 {
        let field = rest[0];
        let tail = &rest[1..];
        let end = tail.iter().position(|&b| b == 0)?;
        let value = String::from_utf8_lossy(&tail[..end]).into_owned();
        match field {
            b'M' => message = Some(value),
            b'S' => severity = Some(value),
            b'C' => code = Some(value),
            _ => {}
        }
        rest = &tail[end + 1..];
    }

    match (severity, code, message) {
        (Some(s), Some(c), Some(m)) => Some(format!("{s}: {m} (SQLSTATE {c})")),
        (_, _, Some(m)) => Some(m),
        _ => None,
    }
}

/// Build an `ErrorResponse` the proxy sends to a client when the backend refuses it.
pub fn backend_error_to_client(error: &io::Error) -> (Severity, &'static str, String) {
    (
        Severity::Fatal,
        sqlstate::CANNOT_CONNECT_NOW,
        error.to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::StartupRequest;
    use crate::protocol::messages as backend_messages;

    fn error_payload(severity: &str, code: &str, message: &str) -> Vec<u8> {
        backend_messages::error_fields(
            match severity {
                "FATAL" => Severity::Fatal,
                _ => Severity::Error,
            },
            code,
            message,
        )
    }

    #[test]
    fn parses_an_error_response() {
        let payload = error_payload("FATAL", "28P01", "password authentication failed");
        let parsed = parse_error_message(&payload).expect("a message");
        assert!(parsed.contains("FATAL"), "{parsed}");
        assert!(
            parsed.contains("password authentication failed"),
            "{parsed}"
        );
        assert!(parsed.contains("28P01"), "{parsed}");
    }

    #[test]
    fn parses_an_error_response_with_only_a_message() {
        let payload = [b'M', b'b', b'o', b'o', b'm', 0, 0];
        assert_eq!(parse_error_message(&payload).as_deref(), Some("boom"));
    }

    #[test]
    fn a_malformed_error_response_yields_none_rather_than_panicking() {
        assert!(parse_error_message(b"Mx").is_none());
        assert!(parse_error_message(&[]).is_none());
    }

    #[test]
    fn parses_a_parameter_status() {
        // Built explicitly rather than as one literal: `\018` would be parsed as an octal
        // escape, silently producing a different payload than it appears to.
        let mut payload = b"server_version\0".to_vec();
        payload.extend_from_slice(b"18.0\0");
        let (name, value) = parse_parameter_status(&payload).expect("parameter");
        assert_eq!(name, "server_version");
        assert_eq!(value, "18.0");
    }

    #[test]
    fn rejects_a_malformed_parameter_status() {
        assert!(parse_parameter_status(b"no-nulls").is_none());
        assert!(parse_parameter_status(b"name\0").is_none());
    }

    #[test]
    fn startup_packet_has_the_right_length_field() {
        let credentials = BackendCredentials {
            user: "pool".to_string(),
            password: None,
            database: None,
            application_name: Some("pgproxy".to_string()),
        };
        let packet = startup_packet(&credentials, "app");
        let declared = i32::from_be_bytes(packet[0..4].try_into().unwrap());
        assert_eq!(declared as usize, packet.len());

        // And it must round-trip through the real startup parser.
        let mut reader = FrameReader::new(io::Cursor::new(packet));
        match reader.read_startup().expect("parses") {
            StartupRequest::Startup(params) => {
                assert_eq!(params.get("user"), Some("pool"));
                assert_eq!(params.get("database"), Some("app"));
                assert_eq!(params.get("application_name"), Some("pgproxy"));
            }
            other => panic!("expected a startup, got {other:?}"),
        }
    }

    #[test]
    fn a_missing_password_is_reported_as_such() {
        let credentials = BackendCredentials {
            user: "pool".to_string(),
            password: None,
            database: None,
            application_name: None,
        };
        let err = require_password(&credentials).unwrap_err();
        assert!(
            err.to_string().contains("requires a password"),
            "the error should say why the connection cannot proceed: {err}"
        );
        // The message must explain the asymmetry, because it is the key design trade-off.
        assert!(
            err.to_string().contains("passthrough"),
            "the error should point at the alternative: {err}"
        );
    }
    #[test]
    fn role_check_results_reject_nulls_malformed_and_extra_columns() {
        assert!(parse_boolean_row(b"\0\x01\0\0\0\x01t").unwrap());
        assert!(!parse_boolean_row(b"\0\x01\0\0\0\x01f").unwrap());
        for payload in [
            b"".as_slice(),
            b"\0\x01\xff\xff\xff\xff",
            b"\0\x01\0\0\0\x01x",
            b"\0\x01\0\0\0\x01tX",
        ] {
            assert!(parse_boolean_row(payload).is_err());
        }
    }
    #[test]
    fn deadline_read_bounds_partial_frame_trickle() {
        use std::io::Write;
        let (mut connection, mut peer) = socket_backend();
        let sending = std::thread::spawn(move || {
            for byte in b"Z\0\0\0\x05I" {
                if peer.write_all(&[*byte]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        });
        let started = Instant::now();
        let result = connection.read_message_with_deadline(started + Duration::from_millis(50));
        assert!(
            matches!(result, Err(ref error) if matches!(error.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock))
        );
        assert!(started.elapsed() < Duration::from_millis(300));
        assert!(!connection.healthy);
        drop(connection);
        sending.join().unwrap();
    }

    #[test]
    fn expired_credentials_and_stale_generations_reject_before_sql() {
        let (connection, mut peer) = socket_backend();
        let epoch = Arc::new(AtomicU64::new(1));
        let mut connection = connection.with_failover_generation(Arc::clone(&epoch), 1);
        assert!(connection.is_healthy());
        epoch.store(2, Ordering::Release);
        assert!(!connection.is_healthy());
        assert_eq!(
            connection.verify_primary().unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
        peer.set_nonblocking(true).unwrap();
        use std::io::Read;
        assert_eq!(
            peer.read(&mut [0u8; 1]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        let (connection, _) = socket_backend();
        let mut expired = connection.with_credential_expiry(Some(Instant::now()));
        assert!(!expired.is_healthy());
        assert_eq!(
            expired.verify_primary().unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
    }

    fn socket_backend() -> (BackendConnection, TcpStream) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (peer, _) = listener.accept().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        (
            BackendConnection {
                _tls_bridge: None,
                tls_options: None,
                address: client.peer_addr().unwrap(),
                reader: FrameReader::new(client.try_clone().unwrap()),
                writer: FrameWriter::new(client),
                parameters: Vec::new(),
                process_id: 1,
                cancel_key: vec![1; 4],
                user: "test".into(),
                database: "test".into(),
                failover_generation: None,
                failover_invalidation: None,
                credential_expiry: None,
                healthy: true,
                require_primary: false,
                transaction_status: b'I',
                capacity_permit: None,
            },
            peer,
        )
    }
    #[test]
    fn idle_probe_detects_eof_without_consuming_pending_messages() {
        use std::io::Write;
        let (connection, mut peer) = socket_backend();
        assert!(connection.is_healthy());
        peer.write_all(b"N").unwrap();
        let mut pending = [0];
        assert_eq!(connection.reader.get_ref().peek(&mut pending).unwrap(), 1);
        assert_eq!(&pending, b"N");
        assert!(!connection.is_healthy());
        let (dead, peer) = socket_backend();
        peer.shutdown(std::net::Shutdown::Both).unwrap();
        // Synchronise on the FIN rather than assuming immediate network delivery.
        assert_eq!(dead.reader.get_ref().peek(&mut [0]).unwrap(), 0);
        assert!(!dead.is_healthy());
    }
    #[test]
    fn role_checks_reject_a_backend_that_becomes_read_only() {
        let (mut connection, peer) = socket_backend();
        let server = std::thread::spawn(move || {
            let mut reader = FrameReader::new(peer.try_clone().unwrap());
            let mut writer = FrameWriter::new(peer);
            for primary in [b't', b'f'] {
                let request = reader.read_message().unwrap().unwrap();
                assert_eq!(request.tag, frontend::QUERY);
                let mut row = vec![0, 1, 0, 0, 0, 1];
                row.push(primary);
                writer.write_message(backend::DATA_ROW, &row).unwrap();
                writer
                    .write_message(backend::COMMAND_COMPLETE, b"SELECT 1\0")
                    .unwrap();
                writer
                    .write_message(backend::READY_FOR_QUERY, b"I")
                    .unwrap();
                writer.flush().unwrap();
            }
        });
        connection.verify_primary().unwrap();
        assert!(connection.verify_primary().is_err());
        assert!(!connection.healthy);
        server.join().unwrap();
    }
    #[test]
    fn backend_cannot_skip_scram_server_signature() {
        use std::io::Read;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut length = [0; 4];
            stream.read_exact(&mut length).unwrap();
            let mut startup = vec![0; u32::from_be_bytes(length) as usize - 4];
            stream.read_exact(&mut startup).unwrap();
            let mut writer = FrameWriter::new(stream.try_clone().unwrap());
            let mut sasl = 10_i32.to_be_bytes().to_vec();
            sasl.extend_from_slice(b"SCRAM-SHA-256\0\0");
            writer
                .write_message(backend::AUTHENTICATION, &sasl)
                .unwrap();
            writer.flush().unwrap();
            let mut reader = FrameReader::new(stream);
            assert_eq!(
                reader.read_message().unwrap().unwrap().tag,
                frontend::PASSWORD
            );
            writer
                .write_message(backend::AUTHENTICATION, &0_i32.to_be_bytes())
                .unwrap();
            writer.flush().unwrap();
        });
        let target = BackendTarget {
            host: "127.0.0.1".into(),
            port: address.port(),
            database: Some("postgres".into()),
            user: None,
        };
        let credentials = BackendCredentials {
            user: "postgres".into(),
            password: Some("public-fixture".into()),
            database: None,
            application_name: None,
        };
        let error = BackendConnection::connect(&target, &credentials, Duration::from_secs(2), 1024)
            .err()
            .unwrap();
        assert!(error.to_string().contains("server signature"));
        server.join().unwrap();
    }
}
