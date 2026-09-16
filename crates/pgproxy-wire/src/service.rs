//! What it means to serve one client connection.
//!
//! This trait lives in `pgproxy-wire` rather than `pgproxy-core` on purpose: the crate
//! dependency graph places `pgproxy-wire` *below* `pgproxy-core`, so a trait defined here
//! can be implemented by the protocol layer and consumed by the runtime without creating
//! a dependency cycle.
//!
//! The split also keeps `pgproxy-core` free of protocol knowledge, which is what makes a
//! future sidecar or embedded host a new consumer of the same runtime rather than a
//! rewrite (ADR-0005).

use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// A broadcast flag telling workers and connections to stop.
///
/// Cloneable and cheap; every clone observes the same flag. The inner `Arc<AtomicBool>`
/// is exposed via [`ShutdownToken::flag`] so `signal-hook` can set it directly from a
/// signal handler without allocating or locking.
#[derive(Clone, Debug)]
pub struct ShutdownToken(Arc<AtomicBool>);

impl ShutdownToken {
    /// Create a token in the "running" state.
    pub fn new() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }

    /// The underlying flag, for `signal_hook::flag::register`.
    pub fn flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.0)
    }

    /// Request shutdown. Idempotent.
    pub fn trigger(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    /// Whether shutdown has been requested.
    pub fn is_shutdown(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

impl Default for ShutdownToken {
    fn default() -> Self {
        Self::new()
    }
}

/// One accepted client connection, handed to a [`Service`] on its own thread.
pub struct Connection {
    /// Process-unique connection id, monotonically assigned at accept time.
    pub id: u64,
    /// Index of the worker that accepted this connection.
    pub worker: usize,
    /// Client address, as reported by `accept`.
    pub peer: SocketAddr,
    /// The client socket. Owned by the handler for the connection's lifetime.
    pub stream: TcpStream,
    /// Shutdown signal, so long-lived handlers can stop early.
    pub shutdown: ShutdownToken,
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("id", &self.id)
            .field("worker", &self.worker)
            .field("peer", &self.peer)
            .finish_non_exhaustive()
    }
}

/// Handles one client connection to completion, on a dedicated thread.
///
/// Implementations are shared across every worker and every connection, so they must be
/// `Send + Sync`. This is why per-connection state lives in [`Connection`] and per-core
/// state is passed explicitly rather than held in globals (ADR-0001).
pub trait Service: Send + Sync + 'static {
    /// Serve a connection until the client disconnects or an error occurs.
    ///
    /// Returning `Err` is not fatal to the process; it is logged and the connection is
    /// closed. Implementations should prefer returning `Err` with a useful message over
    /// panicking, since a panic in a connection thread is a dropped client rather than a
    /// diagnosable error.
    fn handle(&self, conn: Connection) -> std::io::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shutdown_token_starts_running_and_is_shared() {
        let a = ShutdownToken::new();
        let b = a.clone();
        assert!(!a.is_shutdown());
        assert!(!b.is_shutdown());
        a.trigger();
        assert!(b.is_shutdown(), "clones must observe the same flag");
    }

    #[test]
    fn trigger_is_idempotent() {
        let t = ShutdownToken::new();
        t.trigger();
        t.trigger();
        assert!(t.is_shutdown());
    }

    #[test]
    fn exposed_flag_reflects_trigger() {
        let t = ShutdownToken::new();
        let flag = t.flag();
        assert!(!flag.load(Ordering::SeqCst));
        t.trigger();
        assert!(flag.load(Ordering::SeqCst));
    }
}
