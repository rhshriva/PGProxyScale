//! Process-wide connection admission, before connection threads or TLS allocation.
use std::{
    sync::{Arc, Condvar, Mutex},
    time::{Duration, Instant},
};

struct State {
    active: usize,
    tokens: f64,
    updated: Instant,
}
pub(crate) struct Admission {
    limit: usize,
    rate: u32,
    state: Mutex<State>,
    drained: Condvar,
}
pub(crate) struct Permit(Arc<Admission>);
impl Admission {
    pub(crate) fn new(limit: usize, rate: u32) -> Arc<Self> {
        assert!(limit > 0 && rate > 0);
        Arc::new(Self {
            limit,
            rate,
            state: Mutex::new(State {
                active: 0,
                tokens: rate as f64,
                updated: Instant::now(),
            }),
            drained: Condvar::new(),
        })
    }
    pub(crate) fn acquire(self: &Arc<Self>) -> Option<Permit> {
        self.acquire_at(Instant::now())
    }
    fn acquire_at(self: &Arc<Self>, now: Instant) -> Option<Permit> {
        let mut state = self.state.lock().expect("admission state poisoned");
        let replenished =
            now.saturating_duration_since(state.updated).as_secs_f64() * self.rate as f64;
        state.tokens = (state.tokens + replenished).min(self.rate as f64);
        state.updated = now;
        if state.active >= self.limit || state.tokens < 1.0 {
            return None;
        }
        state.tokens -= 1.0;
        state.active += 1;
        Some(Permit(Arc::clone(self)))
    }
    pub(crate) fn wait_empty(&self, timeout: Duration) -> bool {
        let state = self.state.lock().expect("admission state poisoned");
        let (state, _) = self
            .drained
            .wait_timeout_while(state, timeout, |state| state.active != 0)
            .expect("admission state poisoned");
        state.active == 0
    }
}
impl Drop for Permit {
    fn drop(&mut self) {
        let mut state = self.0.state.lock().expect("admission state poisoned");
        state.active -= 1;
        if state.active == 0 {
            self.0.drained.notify_all();
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shared_limit_and_raii_release_bound_simultaneous_clients() {
        let admission = Admission::new(2, 100);
        let first = admission.acquire().unwrap();
        let second = admission.acquire().unwrap();
        assert!(admission.acquire().is_none());
        assert!(!admission.wait_empty(Duration::ZERO));
        drop(first);
        let third = admission.acquire().unwrap();
        drop(second);
        drop(third);
        assert!(admission.wait_empty(Duration::ZERO));
    }
    #[test]
    fn login_storm_budget_refills_without_an_unbounded_burst() {
        let admission = Admission::new(100, 2);
        let now = Instant::now();
        drop(admission.acquire_at(now).unwrap());
        drop(admission.acquire_at(now).unwrap());
        assert!(admission.acquire_at(now).is_none());
        drop(
            admission
                .acquire_at(now + Duration::from_millis(500))
                .unwrap(),
        );
        assert!(
            admission
                .acquire_at(now + Duration::from_millis(500))
                .is_none()
        );
        let far = now + Duration::from_secs(100);
        drop(admission.acquire_at(far).unwrap());
        drop(admission.acquire_at(far).unwrap());
        assert!(admission.acquire_at(far).is_none());
    }
    #[test]
    fn shutdown_wait_tracks_connection_lifetimes() {
        let admission = Admission::new(1, 1);
        let permit = admission.acquire().unwrap();
        let waiter = Arc::clone(&admission);
        let thread = std::thread::spawn(move || waiter.wait_empty(Duration::from_secs(2)));
        drop(permit);
        assert!(thread.join().unwrap());
    }
}
