//! The connection state machine: one client session, from startup to close.
//!
//! ## What this does
//!
//! ```text
//! client connects
//!   read startup        (declining TLS for now, with an honest 'N')
//!   route               client's `database` -> a configured backend
//!   connect             to the backend
//!   forward startup     rebuilt, so the backend sees its own database name
//!   relay               every message in both directions until either side closes
//! ```
//!
//! ## Why authentication needs no special case
//!
//! The relay is message-agnostic, so the authentication exchange *is* the relay: the
//! backend's `AuthenticationSASL` reaches the client, the client's proof reaches the
//! backend, and the proxy never learns the password or the verifier. That is passthrough,
//! and it is the answer to PgBouncer's documented weakness — against providers that block
//! `pg_authid`, terminating authentication requires a plaintext secret, and a SCRAM
//! verifier cannot be reused unless the salt and iteration count match exactly.
//!
//! Terminating authentication (the code in [`crate::auth`]) is still needed: the policy
//! engine will want to reject a client before a backend is touched, and passthrough
//! always spends a backend connection on an unauthenticated client. Which one runs is a
//! later, per-database decision; this module implements passthrough, which is the one
//! that needs no secrets at all.
//!
//! ## Scope
//!
//! Session mode only — one backend connection per client, held for the session's life.
//! Transaction pooling is workstream W4, and the Session-State Ledger is Phase 1. The
//! relay is deliberately message-level rather than a raw byte copy so that both of those
//! have the frame boundaries and transaction state they need.

pub mod rewrite;

use std::io::{self, Write};
use std::net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

use tracing::{debug, info, warn};

use crate::protocol::codec::{Frame, FrameReader, FrameWriter};
use crate::protocol::messages::{self as backend_messages, Severity, sqlstate};
use crate::protocol::startup::{StartupParams, StartupRequest};
use crate::protocol::{DEFAULT_MAX_MESSAGE_LEN, backend};
use crate::service::{Connection, Service, ShutdownToken};

use rewrite::build_startup;

/// Where a session's backend lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendTarget {
    /// Backend host.
    pub host: String,
    /// Backend port.
    pub port: u16,
    /// Database name to request from the backend, overriding whatever the client asked
    /// for. `None` forwards the client's choice unchanged.
    pub database: Option<String>,
    /// User to connect to the backend as. `None` forwards the client's choice, which is
    /// what makes per-user pools and per-user authentication possible.
    pub user: Option<String>,
}

/// Rewrites applied to the forwarded startup packet.
#[derive(Debug, Clone, Copy, Default)]
pub struct StartupOverrides<'a> {
    /// Replacement database name.
    pub database: Option<&'a str>,
    /// Replacement user.
    pub user: Option<&'a str>,
}

/// Why a connection could not be routed.
#[derive(Debug, Clone, thiserror::Error)]
pub enum RouteError {
    /// The client asked for a database this proxy does not serve.
    #[error("database {0:?} does not exist on this proxy")]
    UnknownDatabase(String),
    /// The client named no database and the proxy has no default for it.
    #[error("no database was requested and no default is configured")]
    NoDatabase,
    /// The router itself failed.
    #[error("{0}")]
    Internal(String),
}

/// Decides which backend serves a given startup request.
///
/// Kept as a trait so `pgproxy-wire` does not need to know about configuration, and so a
/// future router (sharding, read/write split, policy-driven isolation) can replace the
/// simple name lookup without touching the session machinery.
pub trait DatabaseRouter: Send + Sync + 'static {
    /// Resolve a startup request to a backend.
    fn route(&self, params: &StartupParams) -> Result<BackendTarget, RouteError>;
}

/// Tunables for one session.
#[derive(Debug, Clone)]
pub struct SessionOptions {
    /// How long to wait for the backend to accept a TCP connection.
    pub connect_timeout: Duration,
    /// Largest message accepted in either direction.
    pub max_message_len: usize,
}

impl Default for SessionOptions {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            max_message_len: DEFAULT_MAX_MESSAGE_LEN,
        }
    }
}

/// Observable state for one session.
///
/// This is the seed of the per-client observability the research identified as missing
/// from every existing pooler: transaction state read from `ReadyForQuery`, and per
/// direction message and byte counts. Phase 1 grows this into the Session-State Ledger.
#[derive(Debug, Default)]
pub struct SessionStats {
    handshake_complete: AtomicBool,
    transaction_status: AtomicU8,
    messages_from_client: AtomicU64,
    messages_from_backend: AtomicU64,
    bytes_from_client: AtomicU64,
    bytes_from_backend: AtomicU64,
}

impl SessionStats {
    /// Whether the backend has reached its first `ReadyForQuery`.
    pub fn handshake_complete(&self) -> bool {
        self.handshake_complete.load(Ordering::Relaxed)
    }

    /// The last transaction status byte the backend reported.
    pub fn transaction_status(&self) -> u8 {
        self.transaction_status.load(Ordering::Relaxed)
    }

    /// Whether a transaction is currently open.
    pub fn in_transaction(&self) -> bool {
        self.transaction_status() == b'T'
    }

    /// Whether the transaction block has failed and only `ROLLBACK` is accepted.
    pub fn failed_transaction(&self) -> bool {
        self.transaction_status() == b'E'
    }

    /// Messages relayed from client to backend.
    pub fn messages_from_client(&self) -> u64 {
        self.messages_from_client.load(Ordering::Relaxed)
    }

    /// Messages relayed from backend to client.
    pub fn messages_from_backend(&self) -> u64 {
        self.messages_from_backend.load(Ordering::Relaxed)
    }

    /// Bytes relayed from client to backend.
    pub fn bytes_from_client(&self) -> u64 {
        self.bytes_from_client.load(Ordering::Relaxed)
    }

    /// Bytes relayed from backend to client.
    pub fn bytes_from_backend(&self) -> u64 {
        self.bytes_from_backend.load(Ordering::Relaxed)
    }

    fn observe(&self, direction: Direction, frame: &Frame<'_>) {
        match direction {
            Direction::ClientToBackend => {
                self.messages_from_client.fetch_add(1, Ordering::Relaxed);
                self.bytes_from_client
                    .fetch_add(frame.len() as u64, Ordering::Relaxed);
            }
            Direction::BackendToClient => {
                self.messages_from_backend.fetch_add(1, Ordering::Relaxed);
                self.bytes_from_backend
                    .fetch_add(frame.len() as u64, Ordering::Relaxed);

                // `ReadyForQuery` is the only place the protocol reports transaction
                // state, and its payload is exactly one byte. Reading it here is what
                // makes transaction pooling possible later without re-parsing anything.
                if frame.tag == backend::READY_FOR_QUERY && frame.payload.len() == 1 {
                    self.transaction_status
                        .store(frame.payload[0], Ordering::Relaxed);
                    self.handshake_complete.store(true, Ordering::Relaxed);
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    ClientToBackend,
    BackendToClient,
}

/// A [`Service`] that proxies sessions to configured backends.
pub struct SessionService {
    router: Arc<dyn DatabaseRouter>,
    options: SessionOptions,
}

impl SessionService {
    /// Create a service routing through `router` with default options.
    pub fn new(router: Arc<dyn DatabaseRouter>) -> Self {
        Self {
            router,
            options: SessionOptions::default(),
        }
    }

    /// Create a service with explicit options.
    pub fn with_options(router: Arc<dyn DatabaseRouter>, options: SessionOptions) -> Self {
        Self { router, options }
    }
}

impl Service for SessionService {
    fn handle(&self, conn: Connection) -> io::Result<()> {
        serve(conn, self.router.as_ref(), &self.options)
    }
}

/// Run one client session to completion.
fn serve(
    conn: Connection,
    router: &dyn DatabaseRouter,
    options: &SessionOptions,
) -> io::Result<()> {
    let Connection {
        id,
        worker,
        peer,
        stream,
        shutdown,
    } = conn;

    let mut client_reader =
        FrameReader::with_max_message_len(stream.try_clone()?, options.max_message_len);
    let mut client_writer = FrameWriter::new(stream);

    // ---------------------------------------------------------------- startup

    let startup = match client_reader.read_startup() {
        Ok(s) => s,
        Err(e) => {
            // A peer that cannot form a startup packet is not our failure to report; it
            // may not even be speaking this protocol.
            debug!(id, worker, %peer, error = %e, "malformed startup packet");
            return Ok(());
        }
    };

    let startup = if matches!(startup, StartupRequest::SslRequest) {
        // TLS is a later W2 item. Decline honestly: a client with sslmode=prefer (the
        // common default) continues in plaintext, and one with sslmode=require fails
        // rather than being silently downgraded.
        debug!(id, "client requested TLS; declining");
        client_writer.get_ref().write_all(b"N")?;
        client_writer.get_ref().flush()?;
        match client_reader.read_startup() {
            Ok(s) => s,
            Err(e) => {
                debug!(id, error = %e, "malformed startup packet after TLS refusal");
                return Ok(());
            }
        }
    } else {
        startup
    };

    let params = match startup {
        StartupRequest::Startup(params) => params,
        StartupRequest::CancelRequest(cancel) => {
            // Routing a cancellation requires the proxy to have issued the cancel key in
            // the first place, which is ADR-0007. Refusing is correct until then: a
            // cancellation that silently does nothing is worse than one that is reported.
            warn!(
                id,
                process_id = cancel.process_id,
                key_len = cancel.key.len(),
                "CancelRequest received but cancellation routing is not implemented (see ADR-0007)"
            );
            return Ok(());
        }
        other => {
            let _ = backend_messages::send_error(
                &mut client_writer,
                Severity::Fatal,
                sqlstate::PROTOCOL_VIOLATION,
                "expected a startup message",
            );
            debug!(id, ?other, "unexpected startup-phase message");
            return Ok(());
        }
    };

    // ---------------------------------------------------------------- route

    let target = match router.route(&params) {
        Ok(target) => target,
        Err(e) => {
            warn!(id, %peer, error = %e, "refusing connection");
            let _ = backend_messages::send_error(
                &mut client_writer,
                Severity::Fatal,
                sqlstate::INVALID_CATALOG,
                &e.to_string(),
            );
            return Ok(());
        }
    };

    // ---------------------------------------------------------------- connect

    let backend = match connect(&target, options.connect_timeout) {
        Ok(stream) => stream,
        Err(e) => {
            warn!(id, host = %target.host, port = target.port, error = %e, "cannot reach backend");
            // Deliberately does not echo the address to the client: a proxy that reports
            // backend topology to an unauthenticated peer is an information leak.
            let _ = backend_messages::send_error(
                &mut client_writer,
                Severity::Fatal,
                sqlstate::CANNOT_CONNECT_NOW,
                "the proxy cannot reach this database right now",
            );
            return Ok(());
        }
    };

    let backend_reader =
        FrameReader::with_max_message_len(backend.try_clone()?, options.max_message_len);
    let mut backend_writer = FrameWriter::new(backend);

    // ---------------------------------------------------------------- forward startup

    let database = target
        .database
        .clone()
        .or_else(|| params.get("database").map(str::to_string));
    let overrides = StartupOverrides {
        database: target.database.as_deref(),
        user: target.user.as_deref(),
    };
    let packet = build_startup(&params, &overrides);
    if let Err(e) = backend_writer.write_raw(&packet) {
        warn!(id, error = %e, "cannot send startup to backend");
        let _ = backend_messages::send_error(
            &mut client_writer,
            Severity::Fatal,
            sqlstate::CANNOT_CONNECT_NOW,
            "the proxy could not start this session",
        );
        return Ok(());
    }
    let _ = backend_writer.flush();

    info!(
        id,
        worker,
        %peer,
        user = params.get("user").unwrap_or(""),
        database = database.as_deref().unwrap_or(""),
        "session established"
    );

    // ---------------------------------------------------------------- relay

    let stats = Arc::new(SessionStats::default());
    let result = relay(
        client_reader,
        client_writer,
        backend_reader,
        backend_writer,
        Arc::clone(&stats),
        shutdown,
    );

    info!(
        id,
        messages_in = stats.messages_from_client(),
        messages_out = stats.messages_from_backend(),
        bytes_in = stats.bytes_from_client(),
        bytes_out = stats.bytes_from_backend(),
        "session closed"
    );

    result
}

/// Connect to the backend, trying each resolved address in turn.
fn connect(target: &BackendTarget, timeout: Duration) -> io::Result<TcpStream> {
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

/// Relay messages in both directions until either side stops.
///
/// One thread per direction with blocking I/O, which is the model spike S1 measured as
/// equal to or faster than both a work-stealing runtime and a zero-copy `splice(2)` path.
fn relay(
    client_reader: FrameReader<TcpStream>,
    client_writer: FrameWriter<TcpStream>,
    backend_reader: FrameReader<TcpStream>,
    backend_writer: FrameWriter<TcpStream>,
    stats: Arc<SessionStats>,
    shutdown: ShutdownToken,
) -> io::Result<()> {
    let upstream_stats = Arc::clone(&stats);
    let upstream_shutdown = shutdown.clone();
    let upstream = thread::Builder::new()
        .name("pgproxy-up".to_string())
        .spawn(move || {
            pump(
                client_reader,
                backend_writer,
                Direction::ClientToBackend,
                upstream_stats,
                upstream_shutdown,
            )
        })?;

    let downstream = pump(
        backend_reader,
        client_writer,
        Direction::BackendToClient,
        stats,
        shutdown,
    );

    // Whichever direction ends first shuts down its destination's write side, so the
    // peer observes EOF and the other thread stops rather than blocking forever.
    let _ = upstream.join();
    downstream
}

/// Anything whose write side can be closed, to propagate EOF.
trait ShutdownWrite {
    fn shutdown_write(&self);
}

impl ShutdownWrite for TcpStream {
    fn shutdown_write(&self) {
        let _ = self.shutdown(Shutdown::Write);
    }
}

/// Copy frames from a reader to a writer until end of stream.
fn pump<R, W>(
    mut reader: FrameReader<R>,
    mut writer: FrameWriter<W>,
    direction: Direction,
    stats: Arc<SessionStats>,
    shutdown: ShutdownToken,
) -> io::Result<()>
where
    R: io::Read,
    W: io::Write + ShutdownWrite,
{
    let outcome = loop {
        if shutdown.is_shutdown() {
            break Ok(());
        }

        match reader.read_message() {
            // Clean end of stream at a message boundary.
            Ok(None) => break Ok(()),
            Ok(Some(frame)) => {
                stats.observe(direction, &frame);
                if let Err(e) = writer.write_raw(frame.raw) {
                    break Err(e);
                }
            }
            Err(e) => break Err(e),
        }
    };

    let _ = writer.flush();
    // Always propagate EOF, including on the error path: the other direction is very
    // likely blocked on a read that only this can release.
    writer.get_ref().shutdown_write();
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_options_defaults_are_sane() {
        let options = SessionOptions::default();
        assert_eq!(options.connect_timeout, Duration::from_secs(10));
        assert_eq!(options.max_message_len, DEFAULT_MAX_MESSAGE_LEN);
    }

    #[test]
    fn fresh_stats_report_no_transaction_and_no_traffic() {
        let stats = SessionStats::default();
        assert!(!stats.handshake_complete());
        assert!(!stats.in_transaction());
        assert!(!stats.failed_transaction());
        assert_eq!(stats.messages_from_client(), 0);
        assert_eq!(stats.messages_from_backend(), 0);
        assert_eq!(stats.bytes_from_client(), 0);
        assert_eq!(stats.bytes_from_backend(), 0);
    }

    #[test]
    fn ready_for_query_drives_transaction_state() {
        let stats = SessionStats::default();

        let idle = [b'Z', 0, 0, 0, 5, b'I'];
        let frame = Frame {
            tag: b'Z',
            payload: &idle[5..],
            raw: &idle,
        };
        stats.observe(Direction::BackendToClient, &frame);
        assert!(stats.handshake_complete());
        assert!(!stats.in_transaction());

        let in_tx = [b'Z', 0, 0, 0, 5, b'T'];
        stats.observe(
            Direction::BackendToClient,
            &Frame {
                tag: b'Z',
                payload: &in_tx[5..],
                raw: &in_tx,
            },
        );
        assert!(stats.in_transaction());

        let failed = [b'Z', 0, 0, 0, 5, b'E'];
        stats.observe(
            Direction::BackendToClient,
            &Frame {
                tag: b'Z',
                payload: &failed[5..],
                raw: &failed,
            },
        );
        assert!(stats.failed_transaction());
        assert!(!stats.in_transaction());
    }

    #[test]
    fn a_ready_for_query_with_a_wrong_length_is_ignored() {
        // Defensive: a malformed ReadyForQuery must not be read as a status byte.
        let stats = SessionStats::default();
        let odd = [b'Z', 0, 0, 0, 6, b'I', 0];
        stats.observe(
            Direction::BackendToClient,
            &Frame {
                tag: b'Z',
                payload: &odd[5..],
                raw: &odd,
            },
        );
        assert!(!stats.handshake_complete());
        assert_eq!(stats.transaction_status(), 0);
    }

    #[test]
    fn counters_are_per_direction() {
        let stats = SessionStats::default();
        let up = [b'Q', 0, 0, 0, 5, b'x'];
        stats.observe(
            Direction::ClientToBackend,
            &Frame {
                tag: b'Q',
                payload: &up[5..],
                raw: &up,
            },
        );
        assert_eq!(stats.messages_from_client(), 1);
        assert_eq!(stats.messages_from_backend(), 0);
        assert_eq!(stats.bytes_from_client(), 6);
        assert_eq!(stats.bytes_from_backend(), 0);
    }

    #[test]
    fn route_errors_explain_themselves_without_leaking_topology() {
        let unknown = RouteError::UnknownDatabase("nope".to_string());
        assert!(unknown.to_string().contains("nope"));
        assert!(RouteError::NoDatabase.to_string().contains("no database"));
    }

    #[test]
    fn connect_fails_cleanly_when_the_host_does_not_resolve() {
        let target = BackendTarget {
            host: "no-such-host.invalid".to_string(),
            port: 5432,
            database: None,
            user: None,
        };
        let err = connect(&target, Duration::from_millis(200)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn connect_fails_on_a_closed_port() {
        // Bind then drop to get a port that is very likely closed.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let target = BackendTarget {
            host: "127.0.0.1".to_string(),
            port,
            database: None,
            user: None,
        };
        assert!(connect(&target, Duration::from_millis(500)).is_err());
    }
}
