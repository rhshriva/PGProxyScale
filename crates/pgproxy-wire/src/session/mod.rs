//! The connection state machine: one client session, from startup to close.
//!
//! ## Two modes
//!
//! * **Session** (default) — a backend is bound to the client for the whole session and
//!   every message is relayed. Authentication needs no special case: the relay *is* the
//!   exchange, so the client authenticates to the backend through the proxy and the proxy
//!   never learns the password or the verifier.
//! * **Transaction** — a backend is bound only for the duration of a transaction, then
//!   reset and returned to the pool. The proxy must be the server to the client and a
//!   client to the backend, which is why it needs a backend credential at all. See
//!   [`transaction`].
//!
//! ```text
//! client connects
//!   read startup        (declining TLS for now, with an honest 'N')
//!   route               client's `database` -> a configured backend
//!   session mode:       connect, forward startup, relay until either side closes
//!   transaction mode:   check out a pooled backend, handshake with the client as the
//!                       server, then bind a backend per transaction
//! ```
//!
//! ## Scope
//!
//! The Session-State Ledger is Phase 1. The relay is deliberately message-level rather
//! than a raw byte copy so that it has the frame boundaries and transaction state the
//! ledger will need.

pub mod rewrite;
pub mod transaction;

use std::collections::HashMap;
use std::io;
use std::net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use rand::RngCore;
use rand::rngs::OsRng;
use tracing::{debug, info, warn};

use pgproxy_pool::{Pool, PoolConfig, Poolable};

use crate::backend::{BackendConnection, BackendCredentials};
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

/// How a database is pooled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PoolMode {
    /// One backend per client, held for the session. Relaying makes authentication
    /// passthrough, so no backend credential is needed.
    #[default]
    Session,
    /// One backend per transaction, returned to the pool at each transaction boundary.
    /// Requires a backend credential, because authentication cannot be relayed.
    Transaction,
}

/// Pool sizing for a database.
#[derive(Debug, Clone, Copy)]
pub struct PoolSettings {
    /// Maximum backend connections, idle plus checked out.
    pub max_size: usize,
    /// How long a session waits for a backend before being told there are too many
    /// clients.
    pub checkout_timeout: Duration,
}

impl Default for PoolSettings {
    fn default() -> Self {
        Self {
            max_size: 20,
            checkout_timeout: Duration::from_secs(5),
        }
    }
}

/// Everything needed to serve a connection, resolved from configuration.
#[derive(Debug, Clone)]
pub struct ResolvedBackend {
    /// Where the backend is.
    pub target: BackendTarget,
    /// How to pool it.
    pub mode: PoolMode,
    /// How to authenticate to it. `None` means the proxy relies on the backend trusting
    /// it, which only session mode can get away with.
    pub credentials: Option<BackendCredentials>,
    /// Pool sizing.
    pub pool: PoolSettings,
    /// How long to wait for a TCP connection to this backend.
    pub connect_timeout: Duration,
}

impl ResolvedBackend {
    /// Identity of the pool this connection belongs to.
    ///
    /// Includes the role, so pools are per `(database, user)` as PgBouncer's are: two
    /// clients of different roles must never share a backend connection.
    pub fn pool_key(&self) -> String {
        format!(
            "{}:{}/{}@{}",
            self.target.host,
            self.target.port,
            self.target.database.as_deref().unwrap_or(""),
            self.credentials
                .as_ref()
                .map(|c| c.user.as_str())
                .unwrap_or(""),
        )
    }
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
    /// Resolve a startup request to a backend and a pooling mode.
    fn route(&self, params: &StartupParams) -> Result<ResolvedBackend, RouteError>;
}

/// Tunables for one session.
#[derive(Debug, Clone)]
pub struct SessionOptions {
    /// How long to wait for the backend to accept a TCP connection.
    pub connect_timeout: Duration,
    /// Largest message accepted in either direction.
    pub max_message_len: usize,
    /// How long a client may hold a pooled backend while saying nothing.
    ///
    /// Without a bound like this, one stalled client pins a pooled connection forever and
    /// the pool starves: every later client is told "too many clients already" and nothing
    /// in the logs says why. Session mode does not need it, because the connection is
    /// already the client's own.
    pub idle_in_transaction: Duration,
    /// How long a single backend exchange may take before the connection is abandoned.
    ///
    /// This is a safety net, not a query timeout: it exists so that a proxy bug cannot
    /// silently consume every pooled connection.
    pub query_timeout: Duration,
    /// How long a write to a client may block before the client is treated as gone.
    ///
    /// A client that stops reading while the proxy writes a large result set would
    /// otherwise block its session thread indefinitely, again holding a backend.
    pub client_write_timeout: Duration,
}

impl Default for SessionOptions {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            max_message_len: DEFAULT_MAX_MESSAGE_LEN,
            // Matches the spirit of PostgreSQL's idle_in_transaction_session_timeout,
            // which also exists to stop a client holding resources it is not using.
            idle_in_transaction: Duration::from_secs(30),
            query_timeout: Duration::from_secs(30),
            client_write_timeout: Duration::from_secs(30),
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
                // makes transaction pooling possible without re-parsing anything.
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

/// A pooled backend connection is usable while it is believed healthy.
impl Poolable for BackendConnection {
    fn is_usable(&self) -> bool {
        self.is_healthy()
    }
}

/// A [`Service`] that proxies sessions to configured backends.
pub struct SessionService {
    router: Arc<dyn DatabaseRouter>,
    options: SessionOptions,
    /// Pools, created on first use and keyed by [`ResolvedBackend::pool_key`].
    pools: Mutex<HashMap<String, Arc<Pool<BackendConnection>>>>,
    /// Source of the process ids the proxy reports as `BackendKeyData`.
    next_process_id: AtomicI32,
    /// The proxy's own cancel key, issued to clients instead of a backend's.
    cancel_key: Vec<u8>,
}

impl SessionService {
    /// Create a service routing through `router` with default options.
    pub fn new(router: Arc<dyn DatabaseRouter>) -> Self {
        Self::with_options(router, SessionOptions::default())
    }

    /// Create a service with explicit options.
    pub fn with_options(router: Arc<dyn DatabaseRouter>, options: SessionOptions) -> Self {
        // A per-process key rather than the backend's: the proxy issues its own so that
        // cancellation can eventually be routed to whichever backend is bound (ADR-0007).
        let mut cancel_key = vec![0u8; 4];
        OsRng.fill_bytes(&mut cancel_key);

        Self {
            router,
            options,
            pools: Mutex::new(HashMap::new()),
            next_process_id: AtomicI32::new(1),
            cancel_key,
        }
    }

    /// The pool for a resolved backend, creating it on first use.
    fn pool_for(&self, resolved: &ResolvedBackend) -> Arc<Pool<BackendConnection>> {
        let key = resolved.pool_key();
        let mut pools = self.pools.lock().expect("pool map poisoned");
        if let Some(pool) = pools.get(&key) {
            return Arc::clone(pool);
        }

        let target = resolved.target.clone();
        let credentials = resolved.credentials.clone().unwrap_or(BackendCredentials {
            user: String::new(),
            password: None,
            database: None,
            application_name: None,
        });
        let options = self.options.clone();
        let connect_timeout = resolved.connect_timeout;

        let pool = Pool::new(
            PoolConfig {
                max_size: resolved.pool.max_size,
                checkout_timeout: resolved.pool.checkout_timeout,
            },
            move || {
                BackendConnection::connect(
                    &target,
                    &credentials,
                    connect_timeout,
                    options.max_message_len,
                )
            },
        );
        pools.insert(key, Arc::clone(&pool));
        pool
    }

    /// Aggregate pool statistics, for diagnostics.
    pub fn pool_stats(&self) -> Vec<(String, pgproxy_pool::PoolStats)> {
        let pools = self.pools.lock().expect("pool map poisoned");
        let mut out: Vec<(String, pgproxy_pool::PoolStats)> = pools
            .iter()
            .map(|(key, pool)| (key.clone(), pool.stats()))
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// Close every pool.
    pub fn close_pools(&self) {
        let pools = self.pools.lock().expect("pool map poisoned");
        for pool in pools.values() {
            pool.close();
        }
    }
}

impl Service for SessionService {
    fn handle(&self, conn: Connection) -> io::Result<()> {
        self.serve(conn)
    }
}

impl SessionService {
    /// Run one client session to completion.
    fn serve(&self, conn: Connection) -> io::Result<()> {
        let Connection {
            id,
            worker,
            peer,
            stream,
            shutdown,
        } = conn;

        let mut client_reader =
            FrameReader::with_max_message_len(stream.try_clone()?, self.options.max_message_len);
        let mut client_writer = FrameWriter::new(stream);

        // ------------------------------------------------------------ startup

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
            use std::io::Write as _;
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
                // Routing a cancellation requires the proxy to have issued the cancel key
                // in the first place, which is ADR-0007. Refusing is correct until then: a
                // cancellation that silently does nothing is worse than one that is
                // reported.
                warn!(
                    id,
                    process_id = cancel.process_id,
                    key_len = cancel.key.len(),
                    "CancelRequest received but cancellation routing is not implemented \
                     (see ADR-0007)"
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

        // ------------------------------------------------------------ route

        let resolved = match self.router.route(&params) {
            Ok(resolved) => resolved,
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

        // ------------------------------------------------------------ dispatch

        match resolved.mode {
            PoolMode::Session => serve_session(
                id,
                worker,
                peer,
                &params,
                &resolved,
                client_reader,
                client_writer,
                &self.options,
                shutdown,
            ),
            PoolMode::Transaction => {
                let pool = self.pool_for(&resolved);
                let process_id = self.next_process_id.fetch_add(1, Ordering::Relaxed);
                transaction::serve(
                    id,
                    peer,
                    &params,
                    client_reader,
                    client_writer,
                    pool,
                    &self.options,
                    shutdown,
                    process_id,
                    &self.cancel_key,
                )
            }
        }
    }
}

/// Session mode: one backend bound for the whole session, every message relayed.
#[allow(clippy::too_many_arguments)]
fn serve_session(
    id: u64,
    worker: usize,
    peer: SocketAddr,
    params: &StartupParams,
    resolved: &ResolvedBackend,
    client_reader: FrameReader<TcpStream>,
    mut client_writer: FrameWriter<TcpStream>,
    options: &SessionOptions,
    shutdown: ShutdownToken,
) -> io::Result<()> {
    let target = &resolved.target;

    let backend = match connect(target, resolved.connect_timeout) {
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

    let database = target
        .database
        .clone()
        .or_else(|| params.get("database").map(str::to_string));
    let overrides = StartupOverrides {
        database: target.database.as_deref(),
        user: target.user.as_deref(),
    };
    let packet = build_startup(params, &overrides);
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

    // Whichever direction ends first shuts down its destination's write side, so the peer
    // observes EOF and the other thread stops rather than blocking forever.
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
