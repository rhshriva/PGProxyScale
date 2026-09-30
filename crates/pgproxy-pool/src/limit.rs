//! Process-wide physical backend admission across users, pools and reload generations.
use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LimitError {
    #[error("backend connection capacity is zero")]
    InvalidCapacity,
    #[error("backend connection admission is closed")]
    Closed,
    #[error("backend connection admission timed out")]
    TimedOut,
    #[error("too many backend connection waiters")]
    TooManyWaiters,
    #[error("invalid backend connection admission timeout")]
    InvalidTimeout,
    #[error("backend admission ticket space exhausted")]
    Exhausted,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LimitSnapshot {
    pub capacity: usize,
    pub used: usize,
    pub waiters: usize,
    pub closed: bool,
}
#[derive(Default)]
struct State {
    used: usize,
    closed: bool,
    next_ticket: u64,
    queue: VecDeque<u64>,
}
/// A permit must remain owned for the complete physical backend socket lifetime,
/// including idle pooling. Checked-out query lifetimes alone do not enforce this cap.
pub struct ConnectionLimit {
    capacity: usize,
    max_waiters: usize,
    state: Mutex<State>,
    available: Condvar,
}
impl std::fmt::Debug for ConnectionLimit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.snapshot().fmt(f)
    }
}
#[derive(Debug)]
pub struct ConnectionPermit {
    limit: Arc<ConnectionLimit>,
}
impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        let mut state = self.limit.state.lock().unwrap();
        state.used -= 1;
        self.limit.available.notify_all();
    }
}
impl ConnectionLimit {
    pub fn new(capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            capacity,
            max_waiters: capacity.saturating_mul(1024).clamp(1024, 1_000_000),
            state: Mutex::default(),
            available: Condvar::new(),
        })
    }
    pub fn capacity(&self) -> usize {
        self.capacity
    }
    pub fn used(&self) -> usize {
        self.state.lock().unwrap().used
    }
    pub fn snapshot(&self) -> LimitSnapshot {
        let state = self.state.lock().unwrap();
        LimitSnapshot {
            capacity: self.capacity,
            used: state.used,
            waiters: state.queue.len(),
            closed: state.closed,
        }
    }
    /// FIFO admission with a bounded wait and bounded waiter memory. Closure wakes
    /// waiters; already admitted connections retain their permit until dropped.
    pub fn acquire(self: &Arc<Self>, timeout: Duration) -> Result<ConnectionPermit, LimitError> {
        if self.capacity == 0 {
            return Err(LimitError::InvalidCapacity);
        }
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(LimitError::InvalidTimeout)?;
        let mut state = self.state.lock().unwrap();
        if state.closed {
            return Err(LimitError::Closed);
        }
        if state.used < self.capacity && state.queue.is_empty() {
            state.used += 1;
            return Ok(ConnectionPermit {
                limit: Arc::clone(self),
            });
        }
        if timeout.is_zero() {
            return Err(LimitError::TimedOut);
        }
        if state.queue.len() >= self.max_waiters {
            return Err(LimitError::TooManyWaiters);
        }
        let ticket = state.next_ticket;
        state.next_ticket = ticket.checked_add(1).ok_or(LimitError::Exhausted)?;
        state.queue.push_back(ticket);
        loop {
            let error = if state.closed {
                Some(LimitError::Closed)
            } else if Instant::now() >= deadline {
                Some(LimitError::TimedOut)
            } else {
                None
            };
            if let Some(error) = error {
                state.queue.retain(|queued| *queued != ticket);
                self.available.notify_all();
                return Err(error);
            }
            if state.queue.front() == Some(&ticket) && state.used < self.capacity {
                state.queue.pop_front();
                state.used += 1;
                self.available.notify_all();
                return Ok(ConnectionPermit {
                    limit: Arc::clone(self),
                });
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            (state, _) = self.available.wait_timeout(state, remaining).unwrap();
        }
    }
    pub fn close(&self) {
        self.state.lock().unwrap().closed = true;
        self.available.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn wait_for_waiters(limit: &ConnectionLimit, n: usize) {
        let deadline = Instant::now() + Duration::from_secs(1);
        while limit.snapshot().waiters != n {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    #[test]
    fn permits_bound_idle_and_checked_out_connection_lifetimes() {
        let limit = ConnectionLimit::new(2);
        let first = limit.acquire(Duration::ZERO).unwrap();
        let second = limit.acquire(Duration::ZERO).unwrap();
        assert_eq!(limit.used(), 2);
        assert_eq!(
            limit.acquire(Duration::ZERO).unwrap_err(),
            LimitError::TimedOut
        );
        drop(first);
        assert_eq!(limit.used(), 1);
        let replacement = limit.acquire(Duration::ZERO).unwrap();
        drop(second);
        drop(replacement);
        assert_eq!(limit.used(), 0);
    }
    #[test]
    fn fifo_waiters_do_not_overtake_existing_waiters() {
        let limit = ConnectionLimit::new(1);
        let initial = limit.acquire(Duration::ZERO).unwrap();
        let (send, receive) = std::sync::mpsc::channel();
        let first_limit = Arc::clone(&limit);
        let first_send = send.clone();
        let first = std::thread::spawn(move || {
            let _permit = first_limit.acquire(Duration::from_secs(1)).unwrap();
            first_send.send(1).unwrap();
        });
        wait_for_waiters(&limit, 1);
        let second_limit = Arc::clone(&limit);
        let second = std::thread::spawn(move || {
            let _permit = second_limit.acquire(Duration::from_secs(1)).unwrap();
            send.send(2).unwrap();
        });
        wait_for_waiters(&limit, 2);
        drop(initial);
        assert_eq!(receive.recv_timeout(Duration::from_secs(1)).unwrap(), 1);
        assert_eq!(receive.recv_timeout(Duration::from_secs(1)).unwrap(), 2);
        first.join().unwrap();
        second.join().unwrap();
        assert_eq!(limit.used(), 0);
    }
    #[test]
    fn close_wakes_waiters_without_revoking_active_sockets() {
        let limit = ConnectionLimit::new(1);
        let permit = limit.acquire(Duration::ZERO).unwrap();
        let waiting = Arc::clone(&limit);
        let task = std::thread::spawn(move || waiting.acquire(Duration::from_secs(10)));
        wait_for_waiters(&limit, 1);
        limit.close();
        assert_eq!(task.join().unwrap().unwrap_err(), LimitError::Closed);
        assert_eq!(limit.used(), 1);
        drop(permit);
        assert_eq!(limit.used(), 0);
        assert_eq!(
            limit.acquire(Duration::ZERO).unwrap_err(),
            LimitError::Closed
        );
    }
    #[test]
    fn timed_out_waiter_does_not_block_later_reuse() {
        let limit = ConnectionLimit::new(1);
        let permit = limit.acquire(Duration::ZERO).unwrap();
        assert_eq!(
            limit.acquire(Duration::from_millis(2)).unwrap_err(),
            LimitError::TimedOut
        );
        assert_eq!(limit.snapshot().waiters, 0);
        drop(permit);
        assert!(limit.acquire(Duration::ZERO).is_ok());
    }
    #[test]
    fn zero_capacity_is_rejected_without_waiting() {
        assert_eq!(
            ConnectionLimit::new(0)
                .acquire(Duration::from_secs(1))
                .unwrap_err(),
            LimitError::InvalidCapacity
        );
    }
}
