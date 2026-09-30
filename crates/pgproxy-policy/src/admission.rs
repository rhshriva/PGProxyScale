//! Per-principal bounded concurrency and monotonic token budgets.
use crate::Principal;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Instant,
};
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Quota {
    pub concurrency: usize,
    pub burst: u32,
    pub per_second: u32,
    pub lifetime_queries: u64,
}
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AdmissionError {
    #[error("principal has no quota")]
    Unknown,
    #[error("quota exhausted")]
    Exhausted,
    #[error("invalid quota")]
    Invalid,
}
struct State {
    active: usize,
    tokens: f64,
    updated: Instant,
    remaining: u64,
}
struct Entry {
    quota: Quota,
    state: Mutex<State>,
}
#[derive(Clone, Default)]
pub struct Admission {
    entries: BTreeMap<Principal, Arc<Entry>>,
}
pub struct Permit {
    entry: Arc<Entry>,
}
impl Admission {
    pub fn new(quotas: BTreeMap<Principal, Quota>) -> Result<Self, AdmissionError> {
        let mut entries = BTreeMap::new();
        for (p, quota) in quotas {
            if quota.concurrency == 0
                || quota.burst == 0
                || quota.per_second == 0
                || quota.lifetime_queries == 0
            {
                return Err(AdmissionError::Invalid);
            }
            let state = State {
                active: 0,
                tokens: f64::from(quota.burst),
                updated: Instant::now(),
                remaining: quota.lifetime_queries,
            };
            entries.insert(
                p,
                Arc::new(Entry {
                    quota,
                    state: Mutex::new(state),
                }),
            );
        }
        Ok(Self { entries })
    }
    pub fn acquire(&self, principal: &Principal) -> Result<Permit, AdmissionError> {
        self.acquire_at(principal, Instant::now())
    }
    fn acquire_at(&self, principal: &Principal, now: Instant) -> Result<Permit, AdmissionError> {
        let entry = self.entries.get(principal).ok_or(AdmissionError::Unknown)?;
        let mut state = entry.state.lock().unwrap_or_else(|e| e.into_inner());
        let elapsed = now.saturating_duration_since(state.updated).as_secs_f64();
        state.tokens = (state.tokens + elapsed * f64::from(entry.quota.per_second))
            .min(f64::from(entry.quota.burst));
        state.updated = state.updated.max(now);
        if state.active >= entry.quota.concurrency || state.tokens < 1.0 || state.remaining == 0 {
            return Err(AdmissionError::Exhausted);
        }
        state.active += 1;
        state.tokens -= 1.0;
        state.remaining -= 1;
        Ok(Permit {
            entry: entry.clone(),
        })
    }
}
impl Drop for Permit {
    fn drop(&mut self) {
        let mut s = self.entry.state.lock().unwrap_or_else(|e| e.into_inner());
        s.active -= 1;
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn noisy_principal_cannot_consume_another_quota() {
        let p = Principal {
            user: "u".into(),
            tenant: "a".into(),
            agent: None,
        };
        let mut q = p.clone();
        q.tenant = "b".into();
        let quota = Quota {
            concurrency: 1,
            burst: 2,
            per_second: 1,
            lifetime_queries: 2,
        };
        let a = Admission::new([(p.clone(), quota.clone()), (q.clone(), quota)].into()).unwrap();
        let permit = a.acquire(&p).unwrap();
        assert!(matches!(a.acquire(&p), Err(AdmissionError::Exhausted)));
        assert!(a.acquire(&q).is_ok());
        drop(permit);
        assert!(a.acquire(&p).is_ok());
        assert!(matches!(
            a.acquire_at(&p, Instant::now() + std::time::Duration::from_secs(100)),
            Err(AdmissionError::Exhausted)
        ));
    }
}
