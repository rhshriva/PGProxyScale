//! Transaction pooling: a backend is bound to a client only for the duration of a
//! transaction.
//!
//! ## Why this mode cannot relay authentication
//!
//! Session mode relays the login exchange, so the client authenticates *to the backend*
//! and the proxy never needs a credential. Transaction pooling cannot do that, because the
//! connection that serves a query is not the one the client logged in on. The proxy must
//! therefore be the server to the client, and a client to the backend — which is why
//! [`crate::backend`] exists.
//!
//! ## The loop
//!
//! ```text
//! check out a backend  (it also supplies the parameter set for the login handshake)
//! send AuthenticationOk, ParameterStatus, BackendKeyData, ReadyForQuery
//! repeat:
//!   read one client message
//!   if Terminate -> stop WITHOUT forwarding it
//!   check out a backend if none is bound
//!   forward, then relay backend messages until ReadyForQuery
//!   if the status is 'I', reset and return the backend to the pool
//! ```
//!
//! ## What this deliberately breaks
//!
//! Anything that lives longer than a transaction: prepared statements, `WITH HOLD`
//! cursors, advisory locks, `LISTEN`, `SET` outside a transaction, temp tables. The
//! conformance harness names each one, because those failures are the evidence Phase 1
//! exists to act on rather than a reason to pretend the mode is finished.
//!
//! Resetting with `DISCARD ALL` is what makes reuse *safe* — without it, one client's
//! `search_path` or temp table leaks into the next, which is the pgagroal failure mode.
//! It is also precisely why prepared statements break here.

use std::io;
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;

use tracing::{debug, info, warn};

use pgproxy_pool::{CheckedOut, Pool, PoolError};

use crate::backend::BackendConnection;
use crate::protocol::codec::{FrameReader, FrameWriter};
use crate::protocol::messages::{self as backend_messages, Severity, TransactionStatus, sqlstate};
use crate::protocol::startup::StartupParams;
use crate::protocol::{backend, frontend};
use crate::service::ShutdownToken;

use super::{Direction, SessionOptions, SessionStats};

/// Serve one client session with transaction pooling.
#[allow(clippy::too_many_arguments)]
pub(super) fn serve(
    id: u64,
    peer: SocketAddr,
    params: &StartupParams,
    mut client_reader: FrameReader<TcpStream>,
    mut client_writer: FrameWriter<TcpStream>,
    pool: Arc<Pool<BackendConnection>>,
    options: &SessionOptions,
    shutdown: ShutdownToken,
    proxy_process_id: i32,
    proxy_cancel_key: &[u8],
) -> io::Result<()> {
    // A backend is needed before the client handshake can complete, because the proxy has
    // to tell the client what `server_version` and the rest actually are. That connection
    // then serves the client's first transaction rather than being wasted.
    let first = match pool.checkout() {
        Ok(connection) => connection,
        Err(e) => {
            let (severity, code, message) = pool_error_response(&e);
            let stats = pool.stats();
            warn!(
                id,
                %peer,
                error = %e,
                idle = stats.idle,
                total = stats.total,
                waiters = stats.waiters,
                created = stats.created,
                reused = stats.reused,
                discarded = stats.discarded,
                timeouts = stats.timeouts,
                "cannot start a transaction-pooled session"
            );
            let _ = backend_messages::send_error(&mut client_writer, severity, code, &message);
            return Ok(());
        }
    };

    backend_messages::send_authentication_ok(&mut client_writer)?;
    for (name, value) in first.get().parameters() {
        backend_messages::send_parameter_status(&mut client_writer, name, value)?;
    }
    // The proxy's own key, not the backend's: cancellation has to be routed back through
    // whichever backend is bound at the time (ADR-0007, not yet implemented).
    backend_messages::send_backend_key_data(
        &mut client_writer,
        proxy_process_id,
        proxy_cancel_key,
    )?;
    backend_messages::send_ready(&mut client_writer, TransactionStatus::Idle)?;
    client_writer.flush()?;

    info!(
        id,
        %peer,
        user = params.get("user").unwrap_or(""),
        database = params.get("database").unwrap_or(""),
        "transaction-pooled session established"
    );

    // Bound the time a stalled client can hold a pooled connection. Both timeouts exist
    // because without them one silent or non-reading client starves the whole pool, and
    // the only symptom is "too many clients already" with no explanation.
    let client_socket = client_reader.get_ref().try_clone()?;
    let _ = client_socket.set_write_timeout(Some(options.client_write_timeout));

    let stats = Arc::new(SessionStats::default());
    let mut bound: Option<CheckedOut<BackendConnection>> = Some(first);

    let outcome = run_loop(
        id,
        &mut client_reader,
        &mut client_writer,
        &pool,
        &mut bound,
        &stats,
        &shutdown,
        options,
        &client_socket,
    );

    // Whatever happened, the connection must be accounted for: reset and returned, or
    // destroyed. A leaked connection starves the pool silently.
    if let Some(connection) = bound.take() {
        check_in(id, connection);
    }

    let pool_stats = pool.stats();
    info!(
        id,
        messages_in = stats.messages_from_client(),
        messages_out = stats.messages_from_backend(),
        bytes_in = stats.bytes_from_client(),
        bytes_out = stats.bytes_from_backend(),
        idle = pool_stats.idle,
        total = pool_stats.total,
        "transaction-pooled session closed"
    );

    outcome
}

#[allow(clippy::too_many_arguments)]
fn run_loop(
    id: u64,
    client_reader: &mut FrameReader<TcpStream>,
    client_writer: &mut FrameWriter<TcpStream>,
    pool: &Arc<Pool<BackendConnection>>,
    bound: &mut Option<CheckedOut<BackendConnection>>,
    stats: &Arc<SessionStats>,
    shutdown: &ShutdownToken,
    options: &SessionOptions,
    client_socket: &TcpStream,
) -> io::Result<()> {
    loop {
        if shutdown.is_shutdown() {
            return Ok(());
        }

        // Only enforce the idle bound while a backend is actually held. Between
        // transactions the client may be idle for as long as it likes.
        let _ = client_socket.set_read_timeout(if bound.is_some() {
            Some(options.idle_in_transaction)
        } else {
            None
        });

        let frame = match client_reader.read_message() {
            Ok(None) => return Ok(()), // clean disconnect
            Ok(Some(frame)) => frame,
            Err(e) if is_timeout(&e) => {
                if bound.is_some() {
                    // Held a backend and said nothing. PostgreSQL's own
                    // idle_in_transaction_timeout kills such a session; releasing the
                    // backend is the minimum, and the client is told why.
                    warn!(
                        id,
                        timeout_secs = options.idle_in_transaction.as_secs(),
                        "client idle while holding a backend; releasing it"
                    );
                    let connection = bound.take().expect("checked above");
                    check_in(id, connection);
                    let _ = backend_messages::send_error(
                        client_writer,
                        Severity::Fatal,
                        sqlstate::IDLE_IN_TRANSACTION,
                        "the proxy released this session's backend after it was idle;                          reconnect to continue",
                    );
                    return Ok(());
                }
                continue;
            }
            Err(e) => return Err(e),
        };
        stats.observe(Direction::ClientToBackend, &frame);

        if frame.tag == frontend::TERMINATE {
            // Never forwarded: the backend must outlive the client so it can be pooled.
            // Forwarding Terminate would close it and waste the connection.
            debug!(id, "client terminated");
            return Ok(());
        }

        if bound.is_none() {
            match pool.checkout() {
                Ok(connection) => *bound = Some(connection),
                Err(e) => {
                    let (severity, code, message) = pool_error_response(&e);
                    let stats = pool.stats();
                    warn!(
                        id,
                        error = %e,
                        idle = stats.idle,
                        total = stats.total,
                        waiters = stats.waiters,
                        reused = stats.reused,
                        discarded = stats.discarded,
                        "no backend available mid-session"
                    );
                    let _ = backend_messages::send_error(client_writer, severity, code, &message);
                    return Ok(());
                }
            }
        }

        let connection = bound
            .as_mut()
            .expect("a backend was just checked out")
            .get_mut();

        if let Err(e) = connection.write_raw(frame.raw) {
            connection.mark_unhealthy();
            return Err(e);
        }

        // Relay until the transaction boundary. Holding the connection for the whole
        // stretch is what keeps an extended-protocol exchange (Parse/Bind/Execute/Sync) on
        // one backend.
        let status = loop {
            let connection = bound.as_mut().expect("a backend is bound").get_mut();

            let Some(frame) = connection.read_message()? else {
                connection.mark_unhealthy();
                return Err(io::Error::other("backend closed mid-transaction"));
            };

            let tag = frame.tag;
            let payload_status = frame.payload.first().copied();
            stats.observe(Direction::BackendToClient, &frame);
            client_writer.write_raw(frame.raw)?;

            if tag == backend::READY_FOR_QUERY {
                let status = payload_status.unwrap_or(b'I');
                connection.set_transaction_status(status);
                break status;
            }
        };
        client_writer.flush()?;

        if status == b'I' {
            // Outside a transaction: the connection is no longer this client's.
            let connection = bound.take().expect("a backend is bound");
            check_in(id, connection);
        }
    }
}

/// Whether an I/O error is a timeout rather than a real failure.
fn is_timeout(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

/// Reset a connection and return it to the pool, or destroy it.
fn check_in(id: u64, mut connection: CheckedOut<BackendConnection>) {
    match connection.get_mut().reset_for_reuse() {
        Ok(()) => connection.release(),
        Err(e) => {
            // It could not be made safe for another client, so it must not be reused.
            warn!(id, error = %e, "discarding a backend connection that could not be reset");
            connection.discard();
        }
    }
}

/// Map a pool failure onto what the client should be told.
fn pool_error_response(error: &PoolError) -> (Severity, &'static str, String) {
    match error {
        // The canonical PostgreSQL wording, so drivers and operators recognise it.
        PoolError::Timeout { .. } => (
            Severity::Fatal,
            sqlstate::TOO_MANY_CONNECTIONS,
            "sorry, too many clients already".to_string(),
        ),
        PoolError::Connect(inner) => (
            Severity::Fatal,
            sqlstate::CANNOT_CONNECT_NOW,
            format!("the proxy cannot reach this database right now: {inner}"),
        ),
        PoolError::Closed => (
            Severity::Fatal,
            sqlstate::CANNOT_CONNECT_NOW,
            "the proxy is shutting down".to_string(),
        ),
    }
}
