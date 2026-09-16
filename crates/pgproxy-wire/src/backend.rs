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
use std::time::Duration;

use tracing::debug;

use crate::auth::messages::{self as auth, AuthenticationRequest};
use crate::auth::scram::ScramClient;
use crate::auth::{AuthError, md5};
use crate::protocol::codec::{Frame, FrameReader, FrameWriter};
use crate::protocol::messages::{Severity, sqlstate};
use crate::protocol::{PROTOCOL_3_0, backend, backend_name, frontend};

use crate::session::BackendTarget;

/// How the proxy identifies itself to a backend.
#[derive(Debug, Clone)]
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

/// A connection to a backend that has completed its startup handshake.
pub struct BackendConnection {
    reader: FrameReader<TcpStream>,
    writer: FrameWriter<TcpStream>,
    parameters: Vec<(String, String)>,
    process_id: i32,
    cancel_key: Vec<u8>,
    user: String,
    database: String,
    healthy: bool,
}

impl BackendConnection {
    /// Open a connection and complete the startup and authentication handshake.
    pub fn connect(
        target: &BackendTarget,
        credentials: &BackendCredentials,
        timeout: Duration,
        max_message_len: usize,
    ) -> io::Result<Self> {
        let stream = open_stream(target, timeout)?;
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

        loop {
            let frame = reader
                .read_message()?
                .ok_or_else(|| io::Error::other("backend closed during startup"))?;

            match frame.tag {
                backend::AUTHENTICATION => {
                    let request = AuthenticationRequest::parse(frame.payload)
                        .map_err(|e| io::Error::other(e.to_string()))?;
                    match request {
                        AuthenticationRequest::Ok => {}
                        AuthenticationRequest::CleartextPassword => {
                            let password = require_password(credentials)?;
                            let payload = auth::password_message(password);
                            writer.write_message(frontend::PASSWORD, &payload)?;
                            writer.flush()?;
                        }
                        AuthenticationRequest::Md5Password { salt } => {
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
                            if !mechanisms
                                .iter()
                                .any(|m| m == crate::auth::scram::MECHANISM)
                            {
                                return Err(io::Error::other(format!(
                                    "backend offers no SCRAM-SHA-256 ({}) and channel binding is \
                                     not implemented",
                                    mechanisms.join(", ")
                                )));
                            }
                            let mut client = ScramClient::new(password.as_bytes());
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
            reader,
            writer,
            parameters,
            process_id,
            cancel_key,
            user: credentials.user.clone(),
            database,
            healthy: true,
        })
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
                    return Ok(frame.payload.first().copied().unwrap_or(b'I'));
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

    /// Mark the connection as unsafe to reuse.
    pub fn mark_unhealthy(&mut self) {
        self.healthy = false;
    }

    /// Whether the connection is still believed usable.
    ///
    /// Deliberately a *belief*: it is cleared on any observed I/O or protocol failure, but a
    /// backend that dies while the connection sits idle is not detected here. PgBouncer has
    /// the same gap and covers it with a periodic health check; that belongs in a later W4
    /// increment rather than being faked with a probe that could swallow a pending
    /// `NotificationResponse`.
    pub fn is_healthy(&self) -> bool {
        self.healthy
    }

    /// Send `Terminate` and close.
    pub fn terminate(mut self) {
        let _ = self.writer.write_message(frontend::TERMINATE, &[]);
        let _ = self.writer.flush();
    }
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
        match TcpStream::connect_timeout(&addr, timeout) {
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
}
