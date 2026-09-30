//! Bounded weighted fair dispatch and a conservative latency concurrency controller.
//! Runtime callers must submit work through this queue for scheduling to apply.
use crate::Principal;
use std::{
    collections::{BTreeMap, VecDeque},
    time::Duration,
};
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Priority {
    Interactive,
    Batch,
    Analytics,
    Migration,
}
impl Priority {
    fn multiplier(self) -> u32 {
        match self {
            Self::Interactive => 8,
            Self::Batch => 4,
            Self::Analytics => 2,
            Self::Migration => 1,
        }
    }
}
struct Lane<T> {
    queue: VecDeque<(T, u32)>,
    weight: u32,
    finish: u128,
}
pub struct FairQueue<T> {
    lanes: BTreeMap<Principal, Lane<T>>,
    capacity: usize,
    per_principal: usize,
    len: usize,
}
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum QueueError {
    #[error("invalid queue configuration")]
    Invalid,
    #[error("unknown principal")]
    Unknown,
    #[error("queue full")]
    Full,
}
impl<T> FairQueue<T> {
    pub fn new(
        weights: BTreeMap<Principal, (u32, Priority)>,
        capacity: usize,
        per_principal: usize,
    ) -> Result<Self, QueueError> {
        if capacity == 0 || per_principal == 0 || weights.is_empty() {
            return Err(QueueError::Invalid);
        }
        let mut lanes = BTreeMap::new();
        for (p, (weight, priority)) in weights {
            if weight == 0 || weight > 10000 {
                return Err(QueueError::Invalid);
            }
            lanes.insert(
                p,
                Lane {
                    queue: VecDeque::new(),
                    weight: weight * priority.multiplier(),
                    finish: 0,
                },
            );
        }
        Ok(Self {
            lanes,
            capacity,
            per_principal,
            len: 0,
        })
    }
    pub fn enqueue(&mut self, p: &Principal, work: T, cost: u32) -> Result<(), QueueError> {
        if cost == 0 {
            return Err(QueueError::Invalid);
        }
        let floor = self
            .lanes
            .values()
            .filter(|l| !l.queue.is_empty())
            .map(|l| l.finish)
            .min()
            .unwrap_or(0);
        let lane = self.lanes.get_mut(p).ok_or(QueueError::Unknown)?;
        if self.len >= self.capacity || lane.queue.len() >= self.per_principal {
            return Err(QueueError::Full);
        }
        if lane.queue.is_empty() {
            lane.finish = lane.finish.max(floor);
        }
        lane.queue.push_back((work, cost));
        self.len += 1;
        Ok(())
    }
    pub fn dispatch(&mut self) -> Option<(Principal, T)> {
        self.dispatch_allowed(|_| true)
    }
    pub fn dispatch_allowed(
        &mut self,
        mut allowed: impl FnMut(&Principal) -> bool,
    ) -> Option<(Principal, T)> {
        let principal = self
            .lanes
            .iter()
            .filter(|(p, l)| !l.queue.is_empty() && allowed(p))
            .min_by_key(|(_, l)| l.finish)
            .map(|(p, _)| p.clone())?;
        let lane = self.lanes.get_mut(&principal).unwrap();
        let (work, cost) = lane.queue.pop_front().unwrap();
        lane.finish = lane
            .finish
            .saturating_add((u128::from(cost) * 1024).div_ceil(u128::from(lane.weight)));
        self.len -= 1;
        Some((principal, work))
    }
    pub fn remove_where(&mut self, mut predicate: impl FnMut(&T) -> bool) {
        for lane in self.lanes.values_mut() {
            let old = lane.queue.len();
            lane.queue.retain(|(work, _)| !predicate(work));
            self.len -= old - lane.queue.len();
        }
    }
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}
/// Vegas-style queue-delay feedback. Clamp every sample; never admit below 1.
pub struct AdaptiveConcurrency {
    minimum: usize,
    maximum: usize,
    limit: usize,
    baseline: Option<Duration>,
    queue_target: Duration,
}
impl AdaptiveConcurrency {
    pub fn new(
        minimum: usize,
        maximum: usize,
        initial: usize,
        queue_target: Duration,
    ) -> Result<Self, QueueError> {
        if minimum == 0 || minimum > initial || initial > maximum || queue_target.is_zero() {
            return Err(QueueError::Invalid);
        }
        Ok(Self {
            minimum,
            maximum,
            limit: initial,
            baseline: None,
            queue_target,
        })
    }
    pub fn limit(&self) -> usize {
        self.limit
    }
    pub fn observe(&mut self, latency: Duration, saturated: bool) -> usize {
        let baseline = self.baseline.map_or(latency, |b| b.min(latency));
        self.baseline = Some(baseline);
        let queued = latency.saturating_sub(baseline);
        if queued > self.queue_target {
            self.limit = (self.limit / 2).max(self.minimum);
        } else if saturated && queued < self.queue_target / 2 {
            self.limit = self.limit.saturating_add(1).min(self.maximum);
        }
        self.limit
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
    #[test]
    fn weighted_share_and_noisy_neighbor_queue_bound() {
        let a = principal("a");
        let b = principal("b");
        let mut q = FairQueue::new(
            [
                (a.clone(), (2, Priority::Batch)),
                (b.clone(), (1, Priority::Batch)),
            ]
            .into(),
            300,
            150,
        )
        .unwrap();
        for i in 0..150 {
            q.enqueue(&a, i, 1).unwrap();
            q.enqueue(&b, i, 1).unwrap();
        }
        assert_eq!(q.enqueue(&a, 1, 1).unwrap_err(), QueueError::Full);
        let mut counts: [i32; 2] = [0, 0];
        for _ in 0..150 {
            let (p, _) = q.dispatch().unwrap();
            counts[usize::from(p == b)] += 1;
        }
        assert!((counts[0] - 100).abs() <= 2, "{counts:?}");
        assert!((counts[1] - 50).abs() <= 2);
    }
    #[test]
    fn adaptive_limits_react_to_delay_and_stay_bounded() {
        let mut a = AdaptiveConcurrency::new(1, 8, 4, Duration::from_millis(10)).unwrap();
        assert_eq!(a.observe(Duration::from_millis(1), true), 5);
        assert_eq!(a.observe(Duration::from_millis(100), true), 2);
        assert_eq!(a.observe(Duration::from_millis(100), true), 1);
        for _ in 0..100 {
            a.observe(Duration::from_millis(1), true);
        }
        assert_eq!(a.limit(), 8);
    }
}
