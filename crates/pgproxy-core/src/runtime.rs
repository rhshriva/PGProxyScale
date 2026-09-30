//! The thread-per-core runtime.
//!
//! One OS thread per core. Each worker owns its own `SO_REUSEPORT` listener, its own
//! readiness poller, and eventually its own pool and parse caches. There is no shared
//! accept mutex and no cross-core synchronisation on the accept path.
//!
//! Model chosen on measurement: spike S1 found blocking thread-per-core equal to or
//! faster than Tokio (which plateaued at ~92k TPS from 16 to 64 clients while this model
//! kept scaling) and statistically identical to a zero-copy `splice(2)` path. See
//! `docs/plans/spike-findings.md`.
//!
//! Per-connection work runs on its own thread. That is the data-path model S1 measured;
//! an event loop per core is a later optimisation gated on evidence, not preference.

use crate::admission::Admission;
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Sender};
use std::thread;
use std::time::{Duration, Instant};

use mio::net::TcpListener as MioListener;
use mio::{Events, Interest, Poll, Token, Waker};
use pgproxy_wire::{Connection, Service, ShutdownToken};

use crate::config::Config;
use crate::error::{Error, Result};
use crate::listener::{reuseport_listener, set_nodelay};

/// Token for the listening socket.
const LISTENER_TOKEN: Token = Token(0);
/// Token for the cross-thread shutdown waker.
const WAKER_TOKEN: Token = Token(1);

/// Readiness wait budget. The waker makes shutdown immediate; this only bounds how long
/// a worker sleeps if the waker is somehow lost.
const ACCEPT_POLL_BACKSTOP: Duration = Duration::from_millis(250);

/// How often the main thread checks for a shutdown request.
const SHUTDOWN_POLL: Duration = Duration::from_millis(25);

/// Ready signal: the concrete address actually bound, sent once listeners are up.
///
/// Needed because a configured port of `0` means "any free port", which the caller cannot
/// otherwise discover — and needed by tests.
pub type ReadySignal = Sender<SocketAddr>;

/// Runs the proxy: binds listeners, spawns workers, waits for shutdown.
pub struct Runtime {
    cfg: Config,
    service: Arc<dyn Service>,
    ready: Option<ReadySignal>,
    shutdown: Option<ShutdownToken>,
    operations: Arc<pgproxy_admin::Operations>,
    diagnostics: pgproxy_admin::http::PoolDiagnostics,
    control: Option<pgproxy_admin::http::Control>,
}

impl Runtime {
    /// Create a runtime for the given configuration and service.
    pub fn new(cfg: Config, service: Arc<dyn Service>) -> Self {
        Self {
            cfg,
            service,
            ready: None,
            shutdown: None,
            operations: Arc::default(),
            diagnostics: Arc::new(|| "[]".into()),
            control: None,
        }
    }

    /// Report the bound address on this channel once listeners are up.
    ///
    /// Useful when `listen_port = 0` (any free port) and for tests.
    pub fn with_ready_signal(mut self, ready: ReadySignal) -> Self {
        self.ready = Some(ready);
        self
    }

    /// Supply an external shutdown token instead of installing signal handlers.
    ///
    /// For embedders and tests: the caller decides when to stop, and no process-wide
    /// signal handler is installed.
    pub fn with_shutdown_token(mut self, token: ShutdownToken) -> Self {
        self.shutdown = Some(token);
        self
    }

    pub fn with_operations(
        mut self,
        operations: Arc<pgproxy_admin::Operations>,
        diagnostics: pgproxy_admin::http::PoolDiagnostics,
    ) -> Self {
        self.operations = operations;
        self.diagnostics = diagnostics;
        self
    }

    pub fn with_control(mut self, control: pgproxy_admin::http::Control) -> Self {
        self.control = Some(control);
        self
    }
    /// Run until a shutdown signal arrives, then drain within the configured budget.
    pub fn run(self) -> Result<()> {
        let workers = self.cfg.effective_workers();
        if workers == 0 {
            return Err(Error::Config("worker count resolved to 0".to_string()));
        }

        // Signal handlers only when we own the process's signals; an embedder that
        // supplied its own token keeps control (ADR-0005).
        let shutdown = match &self.shutdown {
            Some(token) => token.clone(),
            None => {
                let token = ShutdownToken::new();
                install_signal_handlers(&token)?;
                token
            }
        };

        // Bind the first listener, then bind the rest to the *concrete* address. This
        // makes `listen_port = 0` work for any number of workers instead of giving each
        // worker its own ephemeral port.
        let requested = self.cfg.socket_addr()?;
        let first = reuseport_listener(requested)?;
        let bound = first.local_addr().map_err(|source| Error::Bind {
            addr: requested,
            source,
        })?;

        let mut listeners: Vec<TcpListener> = Vec::with_capacity(workers);
        listeners.push(first);
        for _ in 1..workers {
            listeners.push(reuseport_listener(bound)?);
        }

        let _operations_server = self
            .cfg
            .operations
            .as_ref()
            .map(|cfg| {
                pgproxy_admin::http::Server::start_with_control(
                    cfg.listen,
                    cfg.token.clone(),
                    Arc::clone(&self.operations),
                    Arc::clone(&self.diagnostics),
                    self.control.clone(),
                )
            })
            .transpose()
            .map_err(Error::Poll)?;
        let admission = Admission::new(
            self.cfg.general.max_client_connections,
            self.cfg.general.connection_rate_per_second,
        );
        let next_id = Arc::new(AtomicU64::new(1));
        let mut wakers = Vec::with_capacity(workers);
        let mut handles = Vec::with_capacity(workers);

        for (worker, std_listener) in listeners.into_iter().enumerate() {
            let poll = Poll::new().map_err(Error::Poll)?;
            // The waker lets the main thread interrupt `poll` from outside, which is what
            // makes shutdown prompt rather than dependent on the timeout.
            let waker = Waker::new(poll.registry(), WAKER_TOKEN).map_err(Error::Poll)?;

            // Managed sockets must be non-blocking. Set it on the std listener we own
            // rather than trusting the wrapper: a blocking `accept` here parks the
            // worker where no waker can reach it, and the process then only exits when
            // the drain budget expires.
            std_listener.set_nonblocking(true).map_err(Error::Poll)?;
            let mut listener = MioListener::from_std(std_listener);
            poll.registry()
                .register(&mut listener, LISTENER_TOKEN, Interest::READABLE)
                .map_err(Error::Poll)?;

            wakers.push(waker);

            let service = Arc::clone(&self.service);
            let token = shutdown.clone();
            let ids = Arc::clone(&next_id);
            let admission = Arc::clone(&admission);
            let operations = Arc::clone(&self.operations);

            let handle = thread::Builder::new()
                .name(format!("pgproxy-w{worker}"))
                .spawn(move || {
                    worker_loop(
                        worker, listener, poll, service, token, ids, admission, operations,
                    )
                })
                .map_err(|source| Error::Spawn { worker, source })?;
            handles.push((worker, handle));
        }

        tracing::info!(
            address = %bound,
            workers,
            databases = self.cfg.databases.len(),
            "pgproxy listening"
        );

        self.operations.set_ready(true);
        if let Some(tx) = &self.ready {
            // A closed receiver is not an error: the caller may not care.
            let _ = tx.send(bound);
        }

        while !shutdown.is_shutdown() {
            thread::sleep(SHUTDOWN_POLL);
        }

        self.operations.set_ready(false);
        tracing::info!("shutdown requested; draining in-flight work");
        for waker in &wakers {
            if let Err(e) = waker.wake() {
                tracing::warn!(error = %e, "could not wake a worker; it will exit on its poll backstop");
            }
        }

        self.drain(handles, &admission)
    }

    /// Join workers, bounded by the configured shutdown timeout.
    fn drain(
        &self,
        handles: Vec<(usize, thread::JoinHandle<Result<()>>)>,
        admission: &Admission,
    ) -> Result<()> {
        let began = Instant::now();
        let budget = Duration::from_secs(self.cfg.general.shutdown_timeout_secs);
        let (tx, rx) = mpsc::channel::<Option<usize>>();

        thread::Builder::new()
            .name("pgproxy-drain".to_string())
            .spawn(move || {
                for (worker, handle) in handles {
                    // A worker returning `Err` is a failure, not a success: `join()`
                    // only reports panics. Treating `Ok(Err(_))` as clean exit would
                    // hide a dead accept loop behind the drain timeout.
                    match handle.join() {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => {
                            tracing::error!(worker, error = %e, "worker exited with an error");
                            let _ = tx.send(Some(worker));
                        }
                        Err(_) => {
                            let _ = tx.send(Some(worker));
                        }
                    }
                }
                let _ = tx.send(None);
            })
            .map_err(|source| Error::Spawn { worker: 0, source })?;

        match rx.recv_timeout(budget) {
            Ok(Some(worker)) => Err(Error::WorkerPanic { worker }),
            Ok(None) => {
                if !admission.wait_empty(budget.saturating_sub(began.elapsed())) {
                    tracing::warn!("shutdown budget elapsed waiting for client sessions");
                }
                tracing::info!("all workers stopped");
                Ok(())
            }
            Err(_) => {
                tracing::warn!(
                    timeout_secs = self.cfg.general.shutdown_timeout_secs,
                    "shutdown budget elapsed; abandoning remaining connections"
                );
                Ok(())
            }
        }
    }
}

/// Accept loop for one worker. Runs until shutdown is requested.
#[allow(clippy::too_many_arguments)]
fn worker_loop(
    worker: usize,
    listener: MioListener,
    mut poll: Poll,
    service: Arc<dyn Service>,
    shutdown: ShutdownToken,
    next_id: Arc<AtomicU64>,
    admission: Arc<Admission>,
    operations: Arc<pgproxy_admin::Operations>,
) -> Result<()> {
    tracing::debug!(worker, "worker started");

    // Reused across iterations so the accept path does not allocate.
    let mut events = Events::with_capacity(128);

    while !shutdown.is_shutdown() {
        match poll.poll(&mut events, Some(ACCEPT_POLL_BACKSTOP)) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(Error::Poll(e)),
        }

        // Draining unconditionally is correct: if only the waker fired, `accept` returns
        // WouldBlock immediately and the loop exits.
        loop {
            match listener.accept() {
                Ok((stream, peer)) => {
                    let Some(permit) = admission.acquire() else {
                        operations.rejected.fetch_add(1, Ordering::Relaxed);
                        tracing::debug!(worker, "connection admission limit reached");
                        continue;
                    };
                    let stream: std::net::TcpStream = stream.into();
                    // The listener is non-blocking (mio requires it) and an accepted
                    // socket INHERITS that flag. The session layer uses blocking I/O with
                    // one thread per direction, so without this the first `read_exact`
                    // returns `WouldBlock` and every connection dies on arrival — with no
                    // error visible at the default log level.
                    if let Err(e) = stream.set_nonblocking(false) {
                        tracing::warn!(error = %e, "cannot switch an accepted socket to blocking");
                        continue;
                    }
                    set_nodelay(&stream);
                    let id = next_id.fetch_add(1, Ordering::Relaxed);
                    let service = Arc::clone(&service);
                    let conn = Connection {
                        id,
                        worker,
                        peer,
                        stream,
                        shutdown: shutdown.clone(),
                    };

                    if let Err(e) = thread::Builder::new().name(format!("pgproxy-c{id}")).spawn(
                        move || {
                            let _permit = permit;
                            if let Err(err) = service.handle(conn) {
                                tracing::debug!(id, error = %err, "connection ended with error");
                            }
                        },
                    ) {
                        // Thread exhaustion must not take the worker down.
                        tracing::warn!(id, error = %e, "cannot spawn connection thread");
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    tracing::warn!(worker, error = %e, "accept failed");
                    break;
                }
            }
        }
    }

    tracing::debug!(worker, "worker stopping");
    Ok(())
}

/// Route `SIGTERM` and `SIGINT` into the shutdown token.
///
/// Safe API only: `signal-hook`'s flag registration stores into the same atomic the
/// workers read, so no locks or allocation happen in the handler.
fn install_signal_handlers(shutdown: &ShutdownToken) -> Result<()> {
    use signal_hook::consts::{SIGINT, SIGTERM};
    let flag = shutdown.flag();
    for sig in [SIGTERM, SIGINT] {
        signal_hook::flag::register(sig, Arc::clone(&flag)).map_err(Error::Signal)?;
    }
    Ok(())
}
