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
//!   relay both directions concurrently using socket readiness
//!   retain the backend until every forwarded Query/Sync has completed
//!   if the status is 'I', reset and return the backend to the pool
//! ```
//!
//! ## Session state
//!
//! A per-client ledger replays confirmed settings and prepared statements before
//! handoff. LISTEN, held cursors, temporary tables, session locks, and opaque effects
//! retain the backend until their state can be safely cleared. The relay returns a
//! backend only when protocol completion, transaction status, and ledger state agree.
//! DISCARD ALL isolates subsequent borrowers, while replay restores the next client's
//! tracked state. Full state virtualization remains a separate development goal.

use mio::{Events, Interest, Poll, Token};
use std::io;
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::{debug, info, warn};

use pgproxy_pool::{CheckedOut, Pool, PoolError};

use crate::backend::BackendConnection;
use crate::protocol::codec::{FrameReader, FrameWriter};
use crate::protocol::messages::{self as backend_messages, Severity, TransactionStatus, sqlstate};
use crate::protocol::startup::StartupParams;
use crate::protocol::{backend, frontend};
use crate::service::ShutdownToken;

use super::{Direction, SessionOptions, SessionStats};
use pgproxy_session::SessionLedger;

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
    cancellation: &super::cancel::CancelSession,
    retain_backend: bool,
    governance: Option<Arc<crate::governance::RouteGovernance>>,
) -> io::Result<()> {
    // A backend is needed before the client handshake can complete, because the proxy has
    // to tell the client what `server_version` and the rest actually are. That connection
    // then serves the client's first transaction rather than being wasted.
    let mut ledger = SessionLedger::new(
        options.session_memory_bytes,
        options.max_sql_bytes,
        Default::default(),
    );
    let mut guard = match governance
        .map(|route| route.session(params.get("user").unwrap_or("")))
        .transpose()
    {
        Ok(guard) => guard,
        Err(error) => {
            backend_messages::send_error(
                &mut client_writer,
                Severity::Fatal,
                "42501",
                &error.to_string(),
            )?;
            return Ok(());
        }
    };
    if let Some(guard) = guard.as_ref() {
        let principal = guard.principal();
        options.operations.usage_identity(
            id,
            pgproxy_admin::UsageIdentity {
                user: principal.user.clone(),
                tenant: principal.tenant.clone(),
                agent: principal.agent.clone(),
            },
        );
    }
    if guard.is_some()
        && params.iter().any(|(name, _)| {
            !name.starts_with("_pq_.")
                && !matches!(
                    name,
                    "user" | "database" | "application_name" | "client_encoding"
                )
        })
    {
        backend_messages::send_error(
            &mut client_writer,
            Severity::Fatal,
            "42501",
            "policy routes require default startup settings",
        )?;
        return Ok(());
    }
    if retain_backend {
        ledger.retain_backend_for_session();
    }
    for (name, value) in params.iter() {
        match name {
            "user" | "database" | "options" => {}
            name if name.starts_with("_pq_.") => {}
            "client_encoding" if startup_encoding_is_utf8(value) => {}
            "client_encoding" | "replication" => {
                backend_messages::send_error(
                    &mut client_writer,
                    Severity::Fatal,
                    sqlstate::FEATURE_NOT_SUPPORTED,
                    "transaction mode requires UTF8 and does not support replication",
                )?;
                return Ok(());
            }
            _ => ledger
                .startup_setting(
                    name,
                    std::str::from_utf8(value)
                        .map_err(|_| io::Error::other("startup settings require UTF8"))?,
                )
                .map_err(io::Error::other)?,
        }
    }
    let startup_options = match params.checked_options() {
        Ok(settings) => settings,
        Err(_) => {
            backend_messages::send_error(
                &mut client_writer,
                Severity::Fatal,
                sqlstate::FEATURE_NOT_SUPPORTED,
                "unrecognized startup options",
            )?;
            return Ok(());
        }
    };
    for (name, value) in startup_options {
        ledger
            .startup_setting(&name, &value)
            .map_err(io::Error::other)?;
    }
    let mut first = match pool.checkout() {
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

    if let Some(version) = first.get().parameter("server_version") {
        let major = version
            .split('.')
            .next()
            .and_then(|v| v.parse::<u16>().ok())
            .ok_or_else(|| io::Error::other("unsupported backend version"))?;
        ledger.set_backend_major(major).map_err(io::Error::other)?;
    }
    let context = guard
        .as_ref()
        .map(|guard| guard.context_commands())
        .transpose()
        .map_err(io::Error::other)?
        .unwrap_or_default();
    first = match checkout_and_restore(&pool, &ledger.restore(), &context, Some(first)) {
        Ok(connection) => connection,
        Err(error) => {
            let (severity, code, message) = error.response();
            backend_messages::send_error(&mut client_writer, severity, code, &message)?;
            client_writer.flush()?;
            return Err(io::Error::other(message));
        }
    };
    // A primary handoff may have selected another server before AuthenticationOk.
    if let Some(version) = first.get().parameter("server_version") {
        let major = version
            .split('.')
            .next()
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| io::Error::other("unsupported backend version"))?;
        ledger.set_backend_major(major).map_err(io::Error::other)?;
    }
    backend_messages::send_authentication_ok(&mut client_writer)?;
    for (name, value) in first.get().parameters() {
        backend_messages::send_parameter_status(&mut client_writer, name, value)?;
    }
    // The proxy's own key, not the backend's: cancellation has to be routed back through
    // whichever backend is bound at the time.
    backend_messages::send_backend_key_data(
        &mut client_writer,
        cancellation.process_id,
        &cancellation.key,
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

    let stats = Arc::new(SessionStats::with_operations(
        Arc::clone(&options.operations),
        id,
        options.cost_attribution,
    ));
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
        cancellation,
        &mut ledger,
        &mut guard,
    );

    // Whatever happened, the connection must be accounted for: reset and returned, or
    // destroyed. A leaked connection starves the pool silently.
    if let Some(connection) = bound.take() {
        if outcome.is_ok() {
            check_in(id, connection);
        } else {
            connection.discard();
        }
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

    if outcome.is_err() {
        let _ = client_socket.shutdown(std::net::Shutdown::Both);
    }
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
    cancellation: &super::cancel::CancelSession,
    ledger: &mut SessionLedger,
    guard: &mut Option<crate::governance::SessionGuard>,
) -> io::Result<()> {
    let mut poll = Poll::new()?;
    let mut client_source = mio::net::TcpStream::from_std(client_socket.try_clone()?);
    client_socket.set_nonblocking(true)?;
    poll.registry()
        .register(&mut client_source, Token(0), Interest::READABLE)?;
    let mut backend_source = None;
    let mut cancel_binding = None;
    let mut events = Events::with_capacity(2);
    let mut pending = 0usize;
    let mut extended = false;
    let mut last_activity = Instant::now();

    if ledger.is_pinned() {
        let connection = bound.as_mut().expect("startup backend");
        let address = connection.get().backend_address();
        cancel_binding = Some(cancellation.bind_with_tls(
            address,
            connection.get().process_id(),
            connection.get().cancel_key(),
            connection.get().tls_options().cloned(),
        )?);
        let (reader, _) = connection.get_mut().split();
        let mut source = mio::net::TcpStream::from_std(reader.get_ref().try_clone()?);
        reader.get_ref().set_nonblocking(true)?;
        poll.registry()
            .register(&mut source, Token(1), Interest::READABLE)?;
        backend_source = Some(source);
    } else if let Some(connection) = bound.take() {
        check_in(id, connection);
    }

    loop {
        if shutdown.is_shutdown() && bound.is_none() {
            return Ok(());
        }
        let mut progressed = false;
        match if ledger.frontend_barrier() {
            Err(io::Error::from(io::ErrorKind::WouldBlock))
        } else {
            client_reader.read_message()
        } {
            Ok(None) => {
                if (pending != 0 || extended)
                    && let Some(connection) = bound.take()
                {
                    connection.discard();
                }
                return Ok(());
            }
            Ok(Some(frame)) => {
                progressed = true;
                if ledger.awaiting_discard_sync()
                    && !matches!(
                        frame.tag,
                        frontend::FLUSH | frontend::SYNC | frontend::TERMINATE
                    )
                {
                    client_socket.set_nonblocking(false)?;
                    backend_messages::send_error(
                        client_writer,
                        Severity::Fatal,
                        sqlstate::FEATURE_NOT_SUPPORTED,
                        "DISCARD ALL with startup defaults requires a Sync boundary before another command",
                    )?;
                    return Err(io::Error::other("DISCARD ALL requires Sync boundary"));
                }
                stats.accounting_options(ledger.parse_options());
                stats.observe(Direction::ClientToBackend, &frame);
                if frame.tag == frontend::TERMINATE {
                    if (pending != 0 || extended)
                        && let Some(connection) = bound.take()
                    {
                        connection.discard();
                    }
                    debug!(id, "client terminated");
                    return Ok(());
                }
                if let Some(guard) = guard.as_mut()
                    && let Err(error) = guard.frontend(frame.tag, frame.payload)
                {
                    let code = if matches!(
                        error,
                        crate::governance::GovernanceError::Admission(_)
                            | crate::governance::GovernanceError::Scheduler(_)
                    ) {
                        sqlstate::TOO_MANY_CONNECTIONS
                    } else {
                        "42501"
                    };
                    client_socket.set_nonblocking(false)?;
                    backend_messages::send_error(
                        client_writer,
                        Severity::Fatal,
                        code,
                        &error.to_string(),
                    )?;
                    return Err(io::Error::other(error));
                }
                if bound.as_ref().is_some_and(|c| {
                    !c.get().generation_is_current() || !c.get().credentials_are_current()
                }) {
                    client_socket.set_nonblocking(false)?;
                    backend_messages::send_error(
                        client_writer,
                        Severity::Fatal,
                        "08006",
                        "backend ownership expired; active work cannot be migrated",
                    )?;
                    return Err(io::Error::other("stale backend ownership"));
                }
                let idle = pending == 0
                    && !extended
                    && bound
                        .as_ref()
                        .is_none_or(|c| c.get().transaction_status() == b'I');
                let cursor_protocol =
                    match ledger.cursor_extended_frontend(frame.tag, frame.payload, idle) {
                        Ok(messages) => messages,
                        Err(error) => {
                            client_socket.set_nonblocking(false)?;
                            backend_messages::send_error(
                                client_writer,
                                Severity::Fatal,
                                sqlstate::FEATURE_NOT_SUPPORTED,
                                &error.to_string(),
                            )?;
                            return Err(io::Error::other(error));
                        }
                    };
                if let Some(messages) = cursor_protocol {
                    for (tag, payload) in messages {
                        let mut raw = vec![tag];
                        raw.extend_from_slice(&((payload.len() + 4) as u32).to_be_bytes());
                        raw.extend_from_slice(&payload);
                        stats.observe(
                            Direction::BackendToClient,
                            &crate::protocol::codec::Frame {
                                tag,
                                payload: &payload,
                                raw: &raw,
                            },
                        );
                        blocking_write(client_writer, &raw, options.client_write_timeout)?;
                        if tag == backend::ERROR_RESPONSE
                            && let Some(guard) = guard.as_mut()
                        {
                            guard.backend_error();
                        }
                        if tag == backend::READY_FOR_QUERY
                            && let Some(guard) = guard.as_mut()
                        {
                            guard.ready(b'I');
                        }
                    }
                    continue;
                }
                let local_status = bound
                    .as_ref()
                    .map_or(b'I', |c| c.get().transaction_status());
                let local = match ledger.virtual_cursor_request(
                    frame.tag,
                    frame.payload,
                    pending == 0 && !extended && matches!(local_status, b'I' | b'T'),
                ) {
                    Ok(local) => local,
                    Err(error) => {
                        client_socket.set_nonblocking(false)?;
                        backend_messages::send_error(
                            client_writer,
                            Severity::Fatal,
                            sqlstate::FEATURE_NOT_SUPPORTED,
                            &error.to_string(),
                        )?;
                        return Err(io::Error::other(error));
                    }
                };
                if let Err(error) = ledger.frontend(frame.tag, frame.payload) {
                    client_socket.set_nonblocking(false)?;
                    backend_messages::send_error(
                        client_writer,
                        Severity::Fatal,
                        sqlstate::FEATURE_NOT_SUPPORTED,
                        &error.to_string(),
                    )?;
                    return Err(io::Error::other(error));
                }
                if let Some(mut messages) = local {
                    messages.push((backend::READY_FOR_QUERY, vec![local_status]));
                    for (tag, payload) in messages {
                        ledger.backend(tag, &payload).map_err(io::Error::other)?;
                        let mut raw = vec![tag];
                        raw.extend_from_slice(&((payload.len() + 4) as u32).to_be_bytes());
                        raw.extend_from_slice(&payload);
                        stats.observe(
                            Direction::BackendToClient,
                            &crate::protocol::codec::Frame {
                                tag,
                                payload: &payload,
                                raw: &raw,
                            },
                        );
                        blocking_write(client_writer, &raw, options.client_write_timeout)?;
                    }
                    if let Some(guard) = guard.as_mut() {
                        guard.ready(local_status);
                    }
                    continue;
                }
                let rewritten = ledger
                    .rewrite_frontend(frame.tag, frame.payload)
                    .map_err(io::Error::other)?;
                if bound.is_none() {
                    let context = guard
                        .as_ref()
                        .map(|guard| guard.context_commands())
                        .transpose()
                        .map_err(io::Error::other)?
                        .unwrap_or_default();
                    let connection =
                        match checkout_and_restore(pool, &ledger.restore(), &context, None) {
                            Ok(connection) => connection,
                            Err(error) => {
                                let (severity, code, message) = error.response();
                                client_socket.set_nonblocking(false)?;
                                backend_messages::send_error(
                                    client_writer,
                                    severity,
                                    code,
                                    &message,
                                )?;
                                return Err(io::Error::other(message));
                            }
                        };
                    let address = connection.get().backend_address();
                    cancel_binding = Some(cancellation.bind_with_tls(
                        address,
                        connection.get().process_id(),
                        connection.get().cancel_key(),
                        connection.get().tls_options().cloned(),
                    )?);
                    *bound = Some(connection);
                    let connection = bound
                        .as_mut()
                        .ok_or_else(|| io::Error::other("missing checked-out backend"))?;
                    let (reader, _) = connection.get_mut().split();
                    let reader = reader.get_ref();
                    let mut source = mio::net::TcpStream::from_std(reader.try_clone()?);
                    reader.set_nonblocking(true)?;
                    poll.registry()
                        .register(&mut source, Token(1), Interest::READABLE)?;
                    backend_source = Some(source);
                }
                match frame.tag {
                    frontend::QUERY | frontend::SYNC => {
                        pending += 1;
                        extended = false;
                    }
                    frontend::PARSE
                    | frontend::BIND
                    | frontend::DESCRIBE
                    | frontend::EXECUTE
                    | frontend::CLOSE => extended = true,
                    _ => {}
                }
                if let Some(connection) = bound.as_mut() {
                    let (_, writer) = connection.get_mut().split();
                    if let Some(payload) = rewritten {
                        let mut raw = Vec::with_capacity(payload.len() + 5);
                        raw.push(frame.tag);
                        raw.extend_from_slice(&((payload.len() + 4) as u32).to_be_bytes());
                        raw.extend_from_slice(&payload);
                        blocking_write(writer, &raw, options.client_write_timeout)?;
                    } else {
                        blocking_write(writer, frame.raw, options.client_write_timeout)?;
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
        }

        if let Some(connection) = bound.as_mut() {
            match connection.get_mut().read_message() {
                Ok(Some(frame)) => {
                    progressed = true;
                    stats.observe(Direction::BackendToClient, &frame);
                    if frame.tag == backend::ERROR_RESPONSE
                        && let Some(guard) = guard.as_mut()
                    {
                        guard.backend_error();
                    }
                    let rewritten_backend = ledger.rewrite_backend(frame.tag, frame.payload);
                    ledger
                        .backend(frame.tag, frame.payload)
                        .map_err(io::Error::other)?;
                    options.operations.pins(id, &ledger.pin_reasons());
                    let ready = if frame.tag == backend::READY_FOR_QUERY {
                        match frame.payload {
                            [status @ (b'I' | b'T' | b'E')] if pending > 0 => Some(*status),
                            _ => {
                                return Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "unexpected ReadyForQuery",
                                ));
                            }
                        }
                    } else {
                        None
                    };
                    let ready_raw = ready.map(|_| frame.raw.to_vec());
                    if ready.is_none() {
                        if let Some(payload) = rewritten_backend {
                            let mut raw = vec![frame.tag];
                            raw.extend_from_slice(&((payload.len() + 4) as u32).to_be_bytes());
                            raw.extend_from_slice(&payload);
                            blocking_write(client_writer, &raw, options.client_write_timeout)?;
                        } else {
                            blocking_write(client_writer, frame.raw, options.client_write_timeout)?;
                        }
                    }
                    if let Some(status) = ready {
                        debug!(id, status, pending, extended, pin_reasons=?ledger.pin_reasons(), "backend affinity at protocol completion");
                        if let Some(guard) = guard.as_mut() {
                            guard.ready(status);
                        }
                        pending -= 1;
                        connection.get_mut().set_transaction_status(status);
                        let startup_restore = if status == b'I' {
                            ledger.take_startup_restore()
                        } else {
                            Vec::new()
                        };
                        if !startup_restore.is_empty() {
                            let (reader, _) = connection.get_mut().split();
                            reader.get_ref().set_nonblocking(false)?;
                            connection.get_mut().restore_session(&startup_restore)?;
                            let (reader, _) = connection.get_mut().split();
                            reader.get_ref().set_nonblocking(true)?;
                            for (name, value) in connection.get().parameters() {
                                let mut payload = name.as_bytes().to_vec();
                                payload.push(0);
                                payload.extend_from_slice(value.as_bytes());
                                payload.push(0);
                                let mut raw = vec![backend::PARAMETER_STATUS];
                                raw.extend_from_slice(&((payload.len() + 4) as u32).to_be_bytes());
                                raw.extend_from_slice(&payload);
                                blocking_write(client_writer, &raw, options.client_write_timeout)?;
                            }
                        }
                        if status == b'I'
                            && pending == 0
                            && !extended
                            && options.virtualize_hold_cursors
                        {
                            materialize_cursors(
                                connection.get_mut(),
                                ledger,
                                options.query_timeout,
                            )?;
                        }
                        if let Some(raw) = ready_raw {
                            blocking_write(client_writer, &raw, options.client_write_timeout)?;
                        }
                        if status == b'I' && pending == 0 && !extended && !ledger.is_pinned() {
                            if let Some(mut source) = backend_source.take() {
                                poll.registry().deregister(&mut source)?;
                            }
                            let reusable = cancel_binding
                                .take()
                                .map(|binding| binding.finish())
                                .transpose()?
                                .unwrap_or(true);
                            if let Some(mut connection) = bound.take() {
                                let (reader, _) = connection.get_mut().split();
                                reader.get_ref().set_nonblocking(false)?;
                                if reusable {
                                    check_in(id, connection);
                                } else {
                                    connection.discard();
                                }
                            }
                        }
                    }
                }
                Ok(None) => return Err(io::Error::other("backend closed mid-transaction")),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
        }
        if progressed {
            last_activity = Instant::now();
            continue;
        }
        let limit = if pending != 0 {
            options.query_timeout
        } else {
            options.idle_in_transaction
        };
        let idle_pinned = pending == 0
            && !extended
            && ledger.is_pinned()
            && bound
                .as_ref()
                .is_some_and(|connection| !connection.get().in_transaction());
        if bound.is_some() && !idle_pinned && last_activity.elapsed() >= limit {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "transaction relay timed out",
            ));
        }
        // Re-arm after draining: sockets are edge-triggered on supported platforms.
        poll.registry()
            .reregister(&mut client_source, Token(0), Interest::READABLE)?;
        if let Some(source) = backend_source.as_mut() {
            poll.registry()
                .reregister(source, Token(1), Interest::READABLE)?;
        }
        poll.poll(&mut events, Some(Duration::from_millis(100)))?;
    }
}

/// Reads stay nonblocking; writes retain the existing bounded backpressure policy.
fn blocking_write(
    writer: &mut FrameWriter<TcpStream>,
    raw: &[u8],
    timeout: Duration,
) -> io::Result<()> {
    writer.get_ref().set_nonblocking(false)?;
    writer.get_ref().set_write_timeout(Some(timeout))?;
    let outcome = writer.write_raw(raw);
    writer.get_ref().set_nonblocking(true)?;
    outcome
}

/// Reset a connection and return it to the pool, or destroy it.
fn check_in(id: u64, mut connection: CheckedOut<BackendConnection>) {
    let reset = (|| {
        let (reader, _) = connection.get_mut().split();
        reader.get_ref().set_nonblocking(false)?;
        connection.get_mut().reset_for_reuse()
    })();
    match reset {
        Ok(()) => connection.release(),
        Err(e) => {
            // It could not be made safe for another client, so it must not be reused.
            warn!(id, error = %e, "discarding a backend connection that could not be reset");
            connection.discard();
        }
    }
}

/// Map a pool failure onto what the client should be told.
#[derive(Debug)]
enum RestoreCheckoutError {
    Pool(PoolError),
    Restore(io::Error),
}
impl RestoreCheckoutError {
    fn response(&self) -> (Severity, &'static str, String) {
        match self {
            Self::Pool(error) => pool_error_response(error),
            Self::Restore(error) => (
                Severity::Fatal,
                "08006",
                format!("cannot restore session before request: {error}"),
            ),
        }
    }
}
/// Retry only before user bytes are forwarded. Primary verification invalidates
/// the shared ownership generation, so subsequent checkout evicts every stale idle
/// socket rather than spending the bounded attempts on additional old owners.
fn checkout_and_restore(
    pool: &Arc<Pool<BackendConnection>>,
    commands: &[pgproxy_session::RestoreCommand],
    context: &[String],
    initial: Option<CheckedOut<BackendConnection>>,
) -> Result<CheckedOut<BackendConnection>, RestoreCheckoutError> {
    let mut connection = match initial {
        Some(connection) => connection,
        None => pool.checkout().map_err(RestoreCheckoutError::Pool)?,
    };
    for attempt in 0..2 {
        match connection
            .get_mut()
            .restore_session_in_context(commands, context)
        {
            Ok(()) => return Ok(connection),
            Err(error) => {
                connection.discard();
                if attempt == 1 {
                    return Err(RestoreCheckoutError::Restore(error));
                }
                connection = pool.checkout().map_err(RestoreCheckoutError::Pool)?;
            }
        }
    }
    unreachable!("bounded restore attempts")
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::BackendCredentials;
    use crate::session::BackendTarget;
    use pgproxy_pool::PoolConfig;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn startup_restore_failure_retires_all_idle_owners_before_bounded_recheckout() {
        use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let epoch = Arc::new(AtomicU64::new(1));
        let created = Arc::new(AtomicUsize::new(0));
        let server = thread::spawn(move || {
            let mut workers = Vec::new();
            for index in 0..3 {
                let (stream, _) = listener.accept().unwrap();
                workers.push(thread::spawn(move || {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(3)))
                        .unwrap();
                    let mut reader = FrameReader::new(stream.try_clone().unwrap());
                    let mut writer = FrameWriter::new(stream);
                    reader.read_startup().unwrap();
                    backend_messages::send_authentication_ok(&mut writer).unwrap();
                    backend_messages::send_ready(&mut writer, TransactionStatus::Idle).unwrap();
                    if index == 1 || index == 2 {
                        let frame = reader.read_message().unwrap().unwrap();
                        assert_eq!(frame.tag, b'Q');
                        assert!(
                            frame
                                .payload
                                .starts_with(b"SELECT NOT pg_catalog.pg_is_in_recovery()")
                        );
                        let mut row = vec![0, 1, 0, 0, 0, 1];
                        row.push(if index == 2 { b't' } else { b'f' });
                        writer.write_message(b'D', &row).unwrap();
                        writer.write_message(b'Z', b"I").unwrap();
                        writer.flush().unwrap();
                    }
                    assert!(
                        reader.read_message().unwrap().is_none(),
                        "no user SQL is authorized in retry test"
                    );
                }));
            }
            for worker in workers {
                worker.join().unwrap();
            }
        });
        let factory_epoch = Arc::clone(&epoch);
        let factory_created = Arc::clone(&created);
        let pool = Pool::new(
            PoolConfig {
                max_size: 3,
                checkout_timeout: Duration::from_secs(1),
            },
            move || {
                factory_created.fetch_add(1, Ordering::SeqCst);
                let generation = factory_epoch.load(Ordering::Acquire);
                let invalidate_epoch = Arc::clone(&factory_epoch);
                let mut connection = BackendConnection::connect(
                    &BackendTarget {
                        host: address.ip().to_string(),
                        port: address.port(),
                        database: Some("test".into()),
                        user: None,
                    },
                    &BackendCredentials {
                        user: "test".into(),
                        password: None,
                        database: None,
                        application_name: None,
                    },
                    Duration::from_secs(1),
                    1024,
                )?
                .with_failover_generation(Arc::clone(&factory_epoch), generation)
                .with_failover_invalidation(Arc::new(move |observed| {
                    invalidate_epoch
                        .compare_exchange(
                            observed,
                            observed + 1,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                }));
                connection.require_primary(true);
                Ok(connection)
            },
        );
        let one = pool.checkout().unwrap();
        let two = pool.checkout().unwrap();
        drop(one);
        drop(two);
        let initial = pool.checkout().unwrap();
        let acquired = checkout_and_restore(&pool, &[], &[], Some(initial)).unwrap();
        assert_eq!(created.load(Ordering::SeqCst), 3);
        assert_eq!(pool.stats().discarded, 2);
        assert_eq!(epoch.load(Ordering::Acquire), 2);
        assert!(acquired.get().generation_is_current());
        acquired.discard();
        pool.close();
        server.join().unwrap();
    }
    #[test]
    fn restore_checkout_preserves_pool_connection_error_sqlstate() {
        let pool = Pool::new(
            PoolConfig {
                max_size: 1,
                checkout_timeout: Duration::from_millis(10),
            },
            || {
                Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "test endpoint unavailable",
                ))
            },
        );
        let error = match checkout_and_restore(&pool, &[], &[], None) {
            Err(error) => error,
            Ok(connection) => {
                connection.discard();
                panic!("unavailable factory must fail")
            }
        };
        assert_eq!(error.response().1, sqlstate::CANNOT_CONNECT_NOW);
        assert!(error.response().2.contains("test endpoint unavailable"));
    }

    type Step = (u8, Vec<(u8, Vec<u8>)>);

    fn exercise(
        steps: Vec<Step>,
        client: impl FnOnce(FrameReader<TcpStream>, FrameWriter<TcpStream>),
    ) {
        let backend_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = backend_listener.local_addr().unwrap();
        let (finish_server, keep_backend_open) = std::sync::mpsc::channel();
        let server = thread::spawn(move || {
            let (stream, _) = backend_listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut reader = FrameReader::new(stream.try_clone().unwrap());
            let mut writer = FrameWriter::new(stream);
            reader.read_startup().unwrap();
            backend_messages::send_authentication_ok(&mut writer).unwrap();
            backend_messages::send_ready(&mut writer, TransactionStatus::Idle).unwrap();
            for (expected, responses) in steps {
                let frame = reader.read_message().unwrap().unwrap();
                assert_eq!(frame.tag, expected);
                for (tag, payload) in responses {
                    writer.write_message(tag, &payload).unwrap();
                }
            }
            keep_backend_open
                .recv_timeout(Duration::from_secs(3))
                .unwrap();
        });
        let pool = Pool::new(
            PoolConfig {
                max_size: 1,
                checkout_timeout: Duration::from_secs(1),
            },
            move || {
                BackendConnection::connect(
                    &BackendTarget {
                        host: address.ip().to_string(),
                        port: address.port(),
                        database: Some("test".into()),
                        user: None,
                    },
                    &BackendCredentials {
                        user: "test".into(),
                        password: None,
                        database: None,
                        application_name: None,
                    },
                    Duration::from_secs(1),
                    1024,
                )
            },
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let (proxy_stream, _) = listener.accept().unwrap();
        let proxy_pool = Arc::clone(&pool);
        let proxy = thread::spawn(move || {
            let socket = proxy_stream.try_clone().unwrap();
            let mut reader = FrameReader::new(proxy_stream.try_clone().unwrap());
            let mut writer = FrameWriter::new(proxy_stream);
            let mut bound = None;
            let result = run_loop(
                1,
                &mut reader,
                &mut writer,
                &proxy_pool,
                &mut bound,
                &Arc::new(SessionStats::default()),
                &ShutdownToken::new(),
                &SessionOptions {
                    query_timeout: Duration::from_secs(1),
                    idle_in_transaction: Duration::from_secs(1),
                    ..SessionOptions::default()
                },
                &socket,
                &Arc::new(super::super::cancel::CancelRegistry::default())
                    .session()
                    .unwrap(),
                &mut SessionLedger::new(4 * 1024 * 1024, 65536, Default::default()),
                &mut None,
            );
            if let Some(connection) = bound {
                connection.discard();
            }
            result
        });
        client(
            FrameReader::new(stream.try_clone().unwrap()),
            FrameWriter::new(stream),
        );
        proxy.join().unwrap().unwrap();
        assert_eq!(pool.stats().idle, 1, "completed backend should be reusable");
        assert_eq!(pool.stats().total, 1);
        finish_server.send(()).unwrap();
        server.join().unwrap();
    }

    fn reset() -> Step {
        (
            frontend::QUERY,
            vec![
                (backend::COMMAND_COMPLETE, b"DISCARD ALL\0".to_vec()),
                (backend::READY_FOR_QUERY, vec![b'I']),
            ],
        )
    }

    #[test]
    fn extended_flush_responds_before_sync() {
        exercise(
            vec![
                (frontend::PARSE, vec![(backend::PARSE_COMPLETE, vec![])]),
                (frontend::FLUSH, vec![]),
                (frontend::BIND, vec![(backend::BIND_COMPLETE, vec![])]),
                (
                    frontend::EXECUTE,
                    vec![(backend::COMMAND_COMPLETE, b"SELECT 1\0".to_vec())],
                ),
                (frontend::SYNC, vec![(backend::READY_FOR_QUERY, vec![b'I'])]),
                reset(),
            ],
            |mut reader, mut writer| {
                writer
                    .write_message(frontend::PARSE, b"\0select 1\0\0\0")
                    .unwrap();
                writer.write_message(frontend::FLUSH, &[]).unwrap();
                assert_eq!(
                    reader.read_message().unwrap().unwrap().tag,
                    backend::PARSE_COMPLETE
                );
                writer
                    .write_message(frontend::BIND, b"\0\0\0\0\0\0\0\0")
                    .unwrap();
                writer
                    .write_message(frontend::EXECUTE, b"\0\0\0\0\0")
                    .unwrap();
                writer.write_message(frontend::SYNC, &[]).unwrap();
                for tag in [
                    backend::BIND_COMPLETE,
                    backend::COMMAND_COMPLETE,
                    backend::READY_FOR_QUERY,
                ] {
                    assert_eq!(reader.read_message().unwrap().unwrap().tag, tag);
                }
                writer.write_message(frontend::TERMINATE, &[]).unwrap();
            },
        );
    }

    #[test]
    fn pipelined_syncs_do_not_release_at_first_ready() {
        exercise(
            vec![
                (frontend::SYNC, vec![]),
                (
                    frontend::SYNC,
                    vec![
                        (backend::READY_FOR_QUERY, vec![b'I']),
                        (backend::READY_FOR_QUERY, vec![b'I']),
                    ],
                ),
                reset(),
            ],
            |mut reader, mut writer| {
                writer.write_message(frontend::SYNC, &[]).unwrap();
                writer.write_message(frontend::SYNC, &[]).unwrap();
                for _ in 0..2 {
                    assert_eq!(
                        reader.read_message().unwrap().unwrap().tag,
                        backend::READY_FOR_QUERY
                    );
                }
                writer.write_message(frontend::TERMINATE, &[]).unwrap();
            },
        );
    }

    #[test]
    fn failed_transaction_stays_bound_until_rollback() {
        exercise(
            vec![
                (
                    frontend::QUERY,
                    vec![(backend::READY_FOR_QUERY, vec![b'T'])],
                ),
                (
                    frontend::QUERY,
                    vec![
                        (backend::ERROR_RESPONSE, b"Mfailed\0\0".to_vec()),
                        (backend::READY_FOR_QUERY, vec![b'E']),
                    ],
                ),
                (
                    frontend::QUERY,
                    vec![(backend::READY_FOR_QUERY, vec![b'I'])],
                ),
                reset(),
            ],
            |mut reader, mut writer| {
                writer.write_message(frontend::QUERY, b"BEGIN\0").unwrap();
                assert_eq!(reader.read_message().unwrap().unwrap().payload, b"T");
                writer
                    .write_message(frontend::QUERY, b"select 1/0\0")
                    .unwrap();
                assert_eq!(
                    reader.read_message().unwrap().unwrap().tag,
                    backend::ERROR_RESPONSE
                );
                assert_eq!(reader.read_message().unwrap().unwrap().payload, b"E");
                writer
                    .write_message(frontend::QUERY, b"ROLLBACK\0")
                    .unwrap();
                assert_eq!(reader.read_message().unwrap().unwrap().payload, b"I");
                writer.write_message(frontend::TERMINATE, &[]).unwrap();
            },
        );
    }

    #[test]
    fn extended_error_recovers_at_sync() {
        exercise(
            vec![
                (
                    frontend::PARSE,
                    vec![(backend::ERROR_RESPONSE, b"Msyntax error\0\0".to_vec())],
                ),
                (frontend::FLUSH, vec![]),
                (frontend::BIND, vec![]),
                (frontend::SYNC, vec![(backend::READY_FOR_QUERY, vec![b'I'])]),
                reset(),
            ],
            |mut reader, mut writer| {
                writer
                    .write_message(frontend::PARSE, b"\0bad sql\0\0\0")
                    .unwrap();
                writer.write_message(frontend::FLUSH, &[]).unwrap();
                assert_eq!(
                    reader.read_message().unwrap().unwrap().tag,
                    backend::ERROR_RESPONSE
                );
                writer
                    .write_message(frontend::BIND, b"\0\0\0\0\0\0\0\0")
                    .unwrap();
                writer.write_message(frontend::SYNC, &[]).unwrap();
                assert_eq!(
                    reader.read_message().unwrap().unwrap().tag,
                    backend::READY_FOR_QUERY
                );
                writer.write_message(frontend::TERMINATE, &[]).unwrap();
            },
        );
    }

    #[test]
    fn copy_in_services_both_directions() {
        exercise(
            vec![
                (
                    frontend::QUERY,
                    vec![(backend::COPY_IN_RESPONSE, vec![0, 0, 0])],
                ),
                (frontend::COPY_DATA, vec![]),
                (
                    frontend::COPY_DONE,
                    vec![
                        (backend::COMMAND_COMPLETE, b"COPY 1\0".to_vec()),
                        (backend::READY_FOR_QUERY, vec![b'I']),
                    ],
                ),
                reset(),
            ],
            |mut reader, mut writer| {
                writer
                    .write_message(frontend::QUERY, b"COPY test FROM STDIN\0")
                    .unwrap();
                assert_eq!(
                    reader.read_message().unwrap().unwrap().tag,
                    backend::COPY_IN_RESPONSE
                );
                writer.write_message(frontend::COPY_DATA, b"1\n").unwrap();
                writer.write_message(frontend::COPY_DONE, &[]).unwrap();
                assert_eq!(
                    reader.read_message().unwrap().unwrap().tag,
                    backend::COMMAND_COMPLETE
                );
                assert_eq!(
                    reader.read_message().unwrap().unwrap().tag,
                    backend::READY_FOR_QUERY
                );
                writer.write_message(frontend::TERMINATE, &[]).unwrap();
            },
        );
    }
}

/// PostgreSQL accepts quoted encoding names (asyncpg sends '\'utf-8\'') and
/// punctuation-insensitive UTF8 aliases. Accept only ASCII and a balanced quote pair.
fn startup_encoding_is_utf8(value: &[u8]) -> bool {
    let value = if value.len() >= 2 && value.first() == Some(&b'\'') && value.last() == Some(&b'\'')
    {
        &value[1..value.len() - 1]
    } else {
        value
    };
    if !value.is_ascii() || value.contains(&b'\'') {
        return false;
    }
    let normalized: Vec<u8> = value
        .iter()
        .copied()
        .filter(|byte| byte.is_ascii_alphanumeric())
        .map(|byte| byte.to_ascii_uppercase())
        .collect();
    normalized == b"UTF8" || normalized == b"UNICODE"
}
#[cfg(test)]
mod encoding_tests {
    use super::startup_encoding_is_utf8;
    #[test]
    fn postgres_utf8_aliases_include_asyncpg_quoted_names() {
        for value in [
            b"UTF8".as_slice(),
            b"UTF-8",
            b"utf_8",
            b"UNICODE",
            b"'utf-8'",
        ] {
            assert!(startup_encoding_is_utf8(value));
        }
        for value in [
            b"SQL_ASCII".as_slice(),
            b"LATIN1",
            b"'utf8",
            b"utf8'",
            b"utf8\xff",
        ] {
            assert!(!startup_encoding_is_utf8(value));
        }
    }
}

/// Internal reads are bounded and never re-execute the cursor SELECT. Overflow keeps
/// the native cursor and rewinds the pristine SCROLL cursor to its original position.
fn materialize_cursors(
    connection: &mut BackendConnection,
    ledger: &mut SessionLedger,
    timeout: Duration,
) -> io::Result<()> {
    for name in ledger.cursor_candidates() {
        let quoted = format!("\"{}\"", name.replace('"', "\"\""));
        let limit = ledger.cursor_snapshot_limit();
        let deadline = Instant::now() + timeout;
        let (reader, _) = connection.split();
        reader.get_ref().set_nonblocking(false)?;
        connection.set_read_timeout(Some(timeout))?;
        let result = (|| {
            let mut payload = format!("FETCH ALL FROM {quoted}").into_bytes();
            payload.push(0);
            let (_, writer) = connection.split();
            writer.write_message(frontend::QUERY, &payload)?;
            writer.flush()?;
            let mut description = None;
            let mut rows = Vec::new();
            let mut bytes = 0usize;
            let mut overflow = false;
            let mut failed = false;
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "cursor snapshot deadline exceeded",
                    ));
                }
                connection.set_read_timeout(Some(remaining))?;
                let frame = connection
                    .read_message()?
                    .ok_or_else(|| io::Error::other("backend closed during cursor snapshot"))?;
                match frame.tag {
                    b'T' => {
                        bytes += frame.payload.len();
                        description = Some(frame.payload.to_vec());
                    }
                    b'D' => {
                        bytes = bytes.saturating_add(frame.payload.len() + 32);
                        if bytes <= limit && !overflow {
                            rows.push(frame.payload.to_vec());
                        } else {
                            overflow = true;
                            rows.clear();
                        }
                    }
                    b'E' => failed = true,
                    b'Z' => {
                        if frame.payload != b"I" {
                            return Err(io::Error::other(
                                "cursor snapshot left backend in transaction",
                            ));
                        }
                        break;
                    }
                    _ => {}
                }
            }
            let snapshot = if overflow || failed {
                None
            } else {
                description.and_then(|d| pgproxy_session::CursorSnapshot::new(d, rows, limit))
            };
            if let Some(snapshot) = snapshot {
                if ledger
                    .install_cursor_snapshot(name.clone(), snapshot)
                    .is_ok()
                {
                    connection.simple_query(&format!("CLOSE {quoted}"))?;
                } else {
                    connection.simple_query(&format!("MOVE ABSOLUTE 0 FROM {quoted}"))?;
                    ledger.retain_native_cursor(&name);
                }
            } else {
                connection.simple_query(&format!("MOVE ABSOLUTE 0 FROM {quoted}"))?;
                ledger.retain_native_cursor(&name);
            }
            Ok(())
        })();
        let (reader, _) = connection.split();
        reader.get_ref().set_nonblocking(true)?;
        connection.set_read_timeout(Some(timeout))?;
        result?;
    }
    Ok(())
}
