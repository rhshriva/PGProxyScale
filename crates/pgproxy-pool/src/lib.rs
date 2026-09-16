//! Backend connection pools.
//!
//! A pool hands out server connections to sessions and takes them back. The two
//! properties that matter most are:
//!
//! * **A checked-out connection always comes back.** The handle is RAII: dropping it
//!   returns the connection, so a panicking or early-returning session cannot leak one.
//!   Leaked connections are the failure mode that makes a pooler look healthy while
//!   slowly starving — the service degrades to "waiting for a connection" with no error
//!   anywhere.
//! * **A connection that is no longer usable is discarded, not handed out.** The next
//!   caller must never receive a socket whose peer has already gone.
//!
//! Deliberately not here yet (tracked against workstream W4): per-core pools with
//! globally coordinated admission control, fairness and priority classes, and health
//! checks beyond the cheap usability probe.
#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

pub use std::io;

/// How a pool behaves.
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Maximum connections the pool will ever hold, idle plus checked out.
    pub max_size: usize,
    /// How long a caller waits for an idle connection before giving up.
    ///
    /// Waiting forever is never right: it converts an overloaded pool into a silent hang,
    /// which is the failure the research describes as "queries queue instead of failing
    /// fast". A bounded wait with a typed error is diagnosable.
    pub checkout_timeout: Duration,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_size: 20,
            checkout_timeout: Duration::from_secs(5),
        }
    }
}

/// A connection a pool can manage.
pub trait Poolable: Send + 'static {
    /// Whether the connection can still be used.
    ///
    /// Called before handing an idle connection to a caller, and when deciding whether to
    /// keep one. A cheap check is correct here — a full round trip belongs in a health
    /// check, not on the checkout path.
    fn is_usable(&self) -> bool;
}

/// Why a checkout failed.
#[derive(Debug, thiserror::Error)]
pub enum PoolError {
    /// No connection became available within the timeout.
    #[error("timed out after {waited:?} waiting for a pooled connection")]
    Timeout {
        /// How long the caller waited.
        waited: Duration,
    },
    /// The connector could not open a new connection.
    #[error("cannot open a backend connection: {0}")]
    Connect(#[source] io::Error),
    /// The pool has been closed.
    #[error("the pool is closed")]
    Closed,
}

/// A snapshot of pool state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PoolStats {
    /// Connections currently idle and available.
    pub idle: usize,
    /// Connections that exist: idle plus checked out.
    pub total: usize,
    /// Callers waiting for a connection.
    pub waiters: usize,
    /// Connections opened since the pool was created.
    pub created: u64,
    /// Checkouts served from the idle list.
    pub reused: u64,
    /// Connections closed instead of being returned.
    pub discarded: u64,
    /// Checkouts that timed out.
    pub timeouts: u64,
    /// Connector failures.
    pub connect_errors: u64,
}

#[derive(Debug)]
struct State<T> {
    /// Idle connections, most recently returned last. Checkout pops the back, which keeps
    /// a small working set hot rather than round-robining across every connection.
    idle: Vec<T>,
    total: usize,
    waiters: usize,
    created: u64,
    reused: u64,
    discarded: u64,
    timeouts: u64,
    connect_errors: u64,
}

impl<T> Default for State<T> {
    fn default() -> Self {
        Self {
            idle: Vec::new(),
            total: 0,
            waiters: 0,
            created: 0,
            reused: 0,
            discarded: 0,
            timeouts: 0,
            connect_errors: 0,
        }
    }
}

/// A pool of connections produced by `connector`.
pub struct Pool<T> {
    config: PoolConfig,
    connector: Box<dyn Fn() -> io::Result<T> + Send + Sync>,
    state: Mutex<State<T>>,
    available: Condvar,
    closed: AtomicBool,
}

impl<T: Poolable> Pool<T> {
    /// Create a pool. `connector` is called whenever the pool needs a new connection.
    pub fn new<F>(config: PoolConfig, connector: F) -> Arc<Self>
    where
        F: Fn() -> io::Result<T> + Send + Sync + 'static,
    {
        Arc::new(Self {
            config,
            connector: Box::new(connector),
            state: Mutex::new(State::default()),
            available: Condvar::new(),
            closed: AtomicBool::new(false),
        })
    }

    /// The pool's configuration.
    pub fn config(&self) -> &PoolConfig {
        &self.config
    }

    /// Take a connection, waiting up to the configured timeout.
    pub fn checkout(self: &Arc<Self>) -> Result<CheckedOut<T>, PoolError> {
        let deadline = Instant::now() + self.config.checkout_timeout;
        let mut state = self.state.lock().expect("pool mutex poisoned");

        loop {
            if self.closed.load(Ordering::SeqCst) {
                return Err(PoolError::Closed);
            }

            // Prefer an idle connection, discarding any that have gone bad.
            while let Some(connection) = state.idle.pop() {
                if connection.is_usable() {
                    state.reused += 1;
                    return Ok(CheckedOut::new(Arc::clone(self), connection));
                }
                state.total -= 1;
                state.discarded += 1;
            }

            // Otherwise grow, if allowed.
            if state.total < self.config.max_size {
                state.total += 1;
                state.created += 1;
                drop(state);

                match (self.connector)() {
                    Ok(connection) => return Ok(CheckedOut::new(Arc::clone(self), connection)),
                    Err(e) => {
                        let mut state = self.state.lock().expect("pool mutex poisoned");
                        state.total -= 1;
                        state.connect_errors += 1;
                        self.available.notify_one();
                        return Err(PoolError::Connect(e));
                    }
                }
            }

            // At capacity: wait for someone to return one.
            let now = Instant::now();
            if now >= deadline {
                state.timeouts += 1;
                return Err(PoolError::Timeout {
                    waited: self.config.checkout_timeout,
                });
            }

            state.waiters += 1;
            let (guard, timeout) = self
                .available
                .wait_timeout(state, deadline - now)
                .expect("pool mutex poisoned");
            state = guard;
            state.waiters -= 1;

            // A notification may have arrived with the timeout; the loop re-checks for an
            // idle connection before giving up, so a connection is never missed.
            let _ = timeout;
        }
    }

    /// Current state, for diagnostics and metrics.
    pub fn stats(&self) -> PoolStats {
        let state = self.state.lock().expect("pool mutex poisoned");
        PoolStats {
            idle: state.idle.len(),
            total: state.total,
            waiters: state.waiters,
            created: state.created,
            reused: state.reused,
            discarded: state.discarded,
            timeouts: state.timeouts,
            connect_errors: state.connect_errors,
        }
    }

    /// Close the pool and drop every idle connection.
    ///
    /// Callers already waiting are released and fail with [`PoolError::Closed`].
    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        let mut state = self.state.lock().expect("pool mutex poisoned");
        let dropped = state.idle.len();
        state.idle.clear();
        state.total -= dropped;
        drop(state);
        self.available.notify_all();
    }

    /// Whether the pool has been closed.
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// Return a connection to the idle list, or discard it.
    fn give_back(&self, connection: T, reusable: bool) {
        let mut state = self.state.lock().expect("pool mutex poisoned");
        if reusable && connection.is_usable() && !self.closed.load(Ordering::SeqCst) {
            state.idle.push(connection);
        } else {
            state.total -= 1;
            state.discarded += 1;
        }
        drop(state);
        self.available.notify_one();
    }
}

/// A borrowed connection that returns itself to the pool when dropped.
pub struct CheckedOut<T: Poolable> {
    pool: Arc<Pool<T>>,
    connection: Option<T>,
}

impl<T: Poolable> CheckedOut<T> {
    fn new(pool: Arc<Pool<T>>, connection: T) -> Self {
        Self {
            pool,
            connection: Some(connection),
        }
    }

    /// The connection.
    pub fn get(&self) -> &T {
        self.connection
            .as_ref()
            .expect("a checked-out connection is present until it is returned")
    }

    /// The connection, mutably.
    pub fn get_mut(&mut self) -> &mut T {
        self.connection
            .as_mut()
            .expect("a checked-out connection is present until it is returned")
    }

    /// Return the connection to the pool now, before the handle is dropped.
    pub fn release(mut self) {
        self.return_to_pool(true);
    }

    /// Destroy the connection instead of returning it.
    ///
    /// For connections that are still open but must not be reused: a failed transaction, a
    /// protocol desynchronisation, or a session that left state we cannot clean.
    pub fn discard(mut self) {
        self.return_to_pool(false);
    }

    fn return_to_pool(&mut self, reusable: bool) {
        if let Some(connection) = self.connection.take() {
            self.pool.give_back(connection, reusable);
        }
    }
}

impl<T: Poolable> Drop for CheckedOut<T> {
    fn drop(&mut self) {
        // The safety net: a session that errors, panics or returns early still gives its
        // connection back.
        self.return_to_pool(true);
    }
}

impl<T: Poolable> std::fmt::Debug for CheckedOut<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CheckedOut")
            .field("held", &self.connection.is_some())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;

    /// A fake connection with an identity and a liveness flag.
    #[derive(Debug)]
    struct Fake {
        id: u64,
        alive: bool,
    }

    impl Poolable for Fake {
        fn is_usable(&self) -> bool {
            self.alive
        }
    }

    fn fake_pool(max: usize, timeout: Duration) -> (Arc<Pool<Fake>>, Arc<AtomicU64>) {
        let next = Arc::new(AtomicU64::new(1));
        let counter = Arc::clone(&next);
        let pool = Pool::new(
            PoolConfig {
                max_size: max,
                checkout_timeout: timeout,
            },
            move || {
                Ok(Fake {
                    id: counter.fetch_add(1, Ordering::SeqCst),
                    alive: true,
                })
            },
        );
        (pool, next)
    }

    #[test]
    fn a_checkout_creates_a_connection() {
        let (pool, _) = fake_pool(4, Duration::from_millis(50));
        let conn = pool.checkout().expect("checkout");
        assert_eq!(conn.get().id, 1);
        assert_eq!(pool.stats().total, 1);
        assert_eq!(pool.stats().created, 1);
    }

    #[test]
    fn dropping_the_handle_returns_the_connection() {
        // The property that stops a panicking session from leaking a connection.
        let (pool, _) = fake_pool(4, Duration::from_millis(50));
        {
            let _conn = pool.checkout().expect("checkout");
        }
        assert_eq!(pool.stats().idle, 1);
        assert_eq!(pool.stats().total, 1);

        let again = pool.checkout().expect("checkout");
        assert_eq!(again.get().id, 1, "the same connection should come back");
        assert_eq!(pool.stats().reused, 1);
        assert_eq!(
            pool.stats().created,
            1,
            "no new connection should be opened"
        );
    }

    #[test]
    fn the_pool_never_exceeds_its_maximum() {
        let (pool, _) = fake_pool(2, Duration::from_millis(80));
        let a = pool.checkout().expect("first");
        let b = pool.checkout().expect("second");
        let err = pool.checkout().unwrap_err();
        assert!(matches!(err, PoolError::Timeout { .. }), "{err}");
        assert_eq!(pool.stats().total, 2);
        assert_eq!(pool.stats().timeouts, 1);
        drop((a, b));
    }

    #[test]
    fn a_waiter_is_served_when_a_connection_returns() {
        let (pool, _) = fake_pool(1, Duration::from_secs(5));
        let held = pool.checkout().expect("first");

        let waiter_pool = Arc::clone(&pool);
        let waiter = std::thread::spawn(move || waiter_pool.checkout().map(|c| c.get().id));

        // Give the waiter time to block, then release.
        std::thread::sleep(Duration::from_millis(100));
        held.release();

        let id = waiter
            .join()
            .expect("waiter thread")
            .expect("waiter checkout");
        assert_eq!(id, 1);
    }

    #[test]
    fn an_unusable_connection_is_discarded_and_replaced() {
        let (pool, _) = fake_pool(4, Duration::from_millis(50));
        {
            let mut conn = pool.checkout().expect("checkout");
            conn.get_mut().alive = false;
        } // returned, but unusable

        let conn = pool.checkout().expect("checkout");
        assert_eq!(
            conn.get().id,
            2,
            "a fresh connection should have been opened"
        );
        assert_eq!(pool.stats().discarded, 1);
        assert_eq!(pool.stats().created, 2);
    }

    #[test]
    fn discard_destroys_instead_of_reusing() {
        let (pool, _) = fake_pool(4, Duration::from_millis(50));
        let conn = pool.checkout().expect("checkout");
        conn.discard();

        assert_eq!(pool.stats().total, 0);
        assert_eq!(pool.stats().discarded, 1);
        assert_eq!(pool.stats().idle, 0);
    }

    #[test]
    fn discarding_frees_a_slot_for_the_next_caller() {
        let (pool, _) = fake_pool(1, Duration::from_millis(80));
        let conn = pool.checkout().expect("checkout");
        conn.discard();
        let _next = pool.checkout().expect("checkout after discard");
        assert_eq!(pool.stats().total, 1);
    }

    #[test]
    fn idle_connections_are_reused_last_in_first_out() {
        let (pool, _) = fake_pool(4, Duration::from_millis(50));

        // Both must be held at once: if the first handle is dropped before the second is
        // requested, the second simply reuses it and the test proves nothing.
        let a = pool.checkout().expect("a");
        let b = pool.checkout().expect("b");
        let (first, second) = (a.get().id, b.get().id);
        assert_ne!(
            first, second,
            "two simultaneous checkouts need two connections"
        );

        drop(a); // returned first
        drop(b); // returned last, so it sits on top of the idle stack

        let next = pool.checkout().expect("c").get().id;
        assert_eq!(next, second, "LIFO keeps a small working set hot");
    }

    #[test]
    fn connector_failures_are_reported_and_do_not_leak_slots() {
        let pool: Arc<Pool<Fake>> = Pool::new(
            PoolConfig {
                max_size: 1,
                checkout_timeout: Duration::from_millis(50),
            },
            || Err(io::Error::other("backend is down")),
        );

        let err = pool.checkout().unwrap_err();
        assert!(matches!(err, PoolError::Connect(_)), "{err}");
        assert_eq!(
            pool.stats().total,
            0,
            "a failed connect must not consume a slot"
        );
        assert_eq!(pool.stats().connect_errors, 1);

        // And a slot is still available for a later attempt.
        assert!(pool.checkout().is_err());
        assert_eq!(pool.stats().connect_errors, 2);
    }

    #[test]
    fn closing_the_pool_fails_further_checkouts() {
        let (pool, _) = fake_pool(2, Duration::from_millis(50));
        let held = pool.checkout().expect("checkout");
        pool.close();

        assert!(pool.is_closed());
        let err = pool.checkout().unwrap_err();
        assert!(matches!(err, PoolError::Closed), "{err}");

        // Returning a connection to a closed pool discards it rather than resurrecting it.
        held.release();
        assert_eq!(pool.stats().idle, 0);
        assert_eq!(pool.stats().total, 0);
    }

    #[test]
    fn close_releases_waiters() {
        let (pool, _) = fake_pool(1, Duration::from_secs(10));
        let _held = pool.checkout().expect("checkout");

        let waiter_pool = Arc::clone(&pool);
        let waiter = std::thread::spawn(move || waiter_pool.checkout().is_err());

        std::thread::sleep(Duration::from_millis(100));
        pool.close();

        assert!(
            waiter.join().expect("waiter thread"),
            "a waiter must not stay blocked after close"
        );
    }

    #[test]
    fn stats_track_the_lifecycle() {
        let (pool, _) = fake_pool(4, Duration::from_millis(50));
        let a = pool.checkout().expect("a");
        let b = pool.checkout().expect("b");
        b.discard();
        a.release();

        let stats = pool.stats();
        assert_eq!(stats.created, 2);
        assert_eq!(stats.discarded, 1);
        assert_eq!(stats.idle, 1);
        assert_eq!(stats.total, 1);
        assert_eq!(stats.waiters, 0);
    }

    #[test]
    fn concurrent_checkouts_never_exceed_the_maximum() {
        // The invariant that matters under load, exercised rather than asserted.
        let max = 4;
        let (pool, _) = fake_pool(max, Duration::from_millis(200));
        let peak = Arc::new(AtomicU64::new(0));

        let workers: Vec<_> = (0..32)
            .map(|_| {
                let pool = Arc::clone(&pool);
                let peak = Arc::clone(&peak);
                std::thread::spawn(move || {
                    for _ in 0..10 {
                        if let Ok(conn) = pool.checkout() {
                            let total = pool.stats().total as u64;
                            peak.fetch_max(total, Ordering::SeqCst);
                            drop(conn);
                        }
                    }
                })
            })
            .collect();

        for worker in workers {
            worker.join().expect("worker thread");
        }

        let final_stats = pool.stats();
        assert!(
            peak.load(Ordering::SeqCst) <= max as u64,
            "pool exceeded its maximum of {max}: peak was {}",
            peak.load(Ordering::SeqCst)
        );
        assert!(
            final_stats.total <= max,
            "pool holds {} connections, above its maximum of {max}",
            final_stats.total
        );
        assert_eq!(
            final_stats.idle, final_stats.total,
            "every connection should be idle once all workers finish: {final_stats:?}"
        );
        assert_eq!(
            final_stats.created, final_stats.total as u64,
            "nothing should have been discarded: {final_stats:?}"
        );
    }
}
