//! Shared weighted request scheduling. Waiting work is bounded and cancellable.
use crate::{
    Principal,
    scheduler::{AdaptiveConcurrency, FairQueue, Priority, QueueError},
};
use std::{
    collections::BTreeMap,
    sync::{Arc, Condvar, Mutex},
    time::{Duration, Instant},
};
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulerConfig {
    pub capacity: usize,
    pub per_principal: usize,
    pub minimum: usize,
    pub maximum: usize,
    pub initial: usize,
    pub queue_target_ms: u64,
    pub adaptive: bool,
}
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SchedulerError {
    #[error(transparent)]
    Queue(#[from] QueueError),
    #[error("scheduler overloaded; retry after backoff")]
    Overloaded,
    #[error("scheduler closed")]
    Closed,
}
struct State {
    queue: FairQueue<u64>,
    tickets: BTreeMap<u64, Option<Instant>>,
    next: u64,
    active: usize,
    active_principals: BTreeMap<Principal, usize>,
    per_principal: usize,
    controller: AdaptiveConcurrency,
    adaptive: bool,
    closed: bool,
}
pub struct SharedScheduler {
    state: Mutex<State>,
    changed: Condvar,
}
pub struct SchedulerPermit {
    scheduler: Arc<SharedScheduler>,
    started: Instant,
    principal: Principal,
}
impl std::fmt::Debug for SharedScheduler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        f.debug_struct("SharedScheduler")
            .field("active", &state.active)
            .field("queued", &state.queue.len())
            .field("limit", &state.controller.limit())
            .finish()
    }
}
impl SharedScheduler {
    pub fn new(
        weights: BTreeMap<Principal, (u32, Priority)>,
        config: SchedulerConfig,
    ) -> Result<Arc<Self>, SchedulerError> {
        if config.maximum > 100000 || config.capacity > 100000 || config.queue_target_ms == 0 {
            return Err(QueueError::Invalid.into());
        }
        let queue = FairQueue::new(weights, config.capacity, config.per_principal)?;
        let controller = AdaptiveConcurrency::new(
            config.minimum,
            config.maximum,
            config.initial,
            Duration::from_millis(config.queue_target_ms),
        )?;
        Ok(Arc::new(Self {
            state: Mutex::new(State {
                queue,
                tickets: BTreeMap::new(),
                next: 0,
                active: 0,
                active_principals: BTreeMap::new(),
                per_principal: config.per_principal,
                controller,
                adaptive: config.adaptive,
                closed: false,
            }),
            changed: Condvar::new(),
        }))
    }
    pub fn try_acquire(
        self: &Arc<Self>,
        principal: &Principal,
    ) -> Result<SchedulerPermit, SchedulerError> {
        self.acquire(principal, Duration::ZERO)
    }
    pub fn acquire(
        self: &Arc<Self>,
        principal: &Principal,
        wait: Duration,
    ) -> Result<SchedulerPermit, SchedulerError> {
        let deadline = Instant::now()
            .checked_add(wait)
            .ok_or(QueueError::Invalid)?;
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.closed {
            return Err(SchedulerError::Closed);
        }
        let ticket = state.next;
        state.next = state
            .next
            .checked_add(1)
            .ok_or(SchedulerError::Overloaded)?;
        state.queue.enqueue(principal, ticket, 1)?;
        state.tickets.insert(ticket, None);
        dispatch(&mut state);
        self.changed.notify_all();
        loop {
            if let Some(Some(started)) = state.tickets.get(&ticket).copied() {
                state.tickets.remove(&ticket);
                return Ok(SchedulerPermit {
                    scheduler: self.clone(),
                    started,
                    principal: principal.clone(),
                });
            }
            if state.closed {
                state.queue.remove_where(|t| *t == ticket);
                state.tickets.remove(&ticket);
                return Err(SchedulerError::Closed);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                state.queue.remove_where(|t| *t == ticket);
                state.tickets.remove(&ticket);
                return Err(SchedulerError::Overloaded);
            }
            let (result, _) = self
                .changed
                .wait_timeout(state, remaining)
                .unwrap_or_else(|e| e.into_inner());
            state = result;
        }
    }
    pub fn close(&self) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.closed = true;
        self.changed.notify_all();
    }
    pub fn active(&self) -> usize {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).active
    }
}
fn dispatch(state: &mut State) {
    if state.closed {
        return;
    }
    while state.active < state.controller.limit() {
        let counts = &state.active_principals;
        let limit = state.per_principal;
        let Some((principal, ticket)) = state
            .queue
            .dispatch_allowed(|p| counts.get(p).copied().unwrap_or(0) < limit)
        else {
            break;
        };
        if let Some(started) = state.tickets.get_mut(&ticket) {
            *started = Some(Instant::now());
            state.active += 1;
            *state.active_principals.entry(principal).or_default() += 1;
        }
    }
}
impl Drop for SchedulerPermit {
    fn drop(&mut self) {
        let mut state = self
            .scheduler
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        state.active -= 1;
        let count = state
            .active_principals
            .get_mut(&self.principal)
            .expect("granted principal");
        *count -= 1;
        if state.adaptive {
            let saturated = !state.queue.is_empty();
            state.controller.observe(self.started.elapsed(), saturated);
        }
        dispatch(&mut state);
        self.scheduler.changed.notify_all();
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn principal(t: &str) -> Principal {
        Principal {
            user: "u".into(),
            tenant: t.into(),
            agent: None,
        }
    }
    fn scheduler() -> Arc<SharedScheduler> {
        SharedScheduler::new(
            [
                (principal("a"), (1, Priority::Interactive)),
                (principal("b"), (1, Priority::Interactive)),
            ]
            .into(),
            SchedulerConfig {
                capacity: 2,
                per_principal: 1,
                minimum: 1,
                maximum: 1,
                initial: 1,
                queue_target_ms: 10,
                adaptive: false,
            },
        )
        .unwrap()
    }
    #[test]
    fn permits_bound_work_and_timeout_cancels_ticket() {
        let s = scheduler();
        let first = s.acquire(&principal("a"), Duration::ZERO).unwrap();
        assert!(matches!(
            s.try_acquire(&principal("b")),
            Err(SchedulerError::Overloaded)
        ));
        assert_eq!(s.active(), 1);
        drop(first);
        let second = s.try_acquire(&principal("b")).unwrap();
        assert_eq!(s.active(), 1);
        drop(second);
        assert_eq!(s.active(), 0);
    }
    #[test]
    fn idle_transactions_cannot_take_another_tenants_slot() {
        let scheduler = SharedScheduler::new(
            [
                (principal("a"), (1, Priority::Interactive)),
                (principal("b"), (1, Priority::Interactive)),
            ]
            .into(),
            SchedulerConfig {
                capacity: 4,
                per_principal: 1,
                minimum: 1,
                maximum: 2,
                initial: 2,
                queue_target_ms: 10,
                adaptive: false,
            },
        )
        .unwrap();
        let noisy = scheduler.try_acquire(&principal("a")).unwrap();
        assert!(matches!(
            scheduler.try_acquire(&principal("a")),
            Err(SchedulerError::Overloaded)
        ));
        let victim = scheduler.try_acquire(&principal("b")).unwrap();
        assert_eq!(scheduler.active(), 2);
        drop(noisy);
        drop(victim);
    }
    #[test]
    fn waiting_tenant_progresses_after_release() {
        let s = scheduler();
        let first = s.try_acquire(&principal("a")).unwrap();
        let copy = s.clone();
        let worker = std::thread::spawn(move || {
            copy.acquire(&principal("b"), Duration::from_secs(1))
                .unwrap()
        });
        drop(first);
        let second = worker.join().unwrap();
        assert_eq!(s.active(), 1);
        drop(second);
        s.close();
        assert!(matches!(
            s.try_acquire(&principal("a")),
            Err(SchedulerError::Closed)
        ));
    }
}
