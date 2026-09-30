//! Immutable authenticated identity and policy provenance for both SQL protocols.
use pgproxy_policy::{
    Policy, PolicyError, Principal,
    admission::{Admission, AdmissionError, Permit},
    shared_scheduler::{SchedulerError, SchedulerPermit, SharedScheduler},
};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
    time::Duration,
};
#[derive(Clone)]
pub struct RouteGovernance {
    pub policy: Policy,
    pub admission: Admission,
    pub principals: BTreeMap<String, Principal>,
    pub scheduler: Option<(Arc<SharedScheduler>, Duration)>,
    pub contexts: BTreeMap<Principal, pgproxy_policy::context::TransactionContext>,
}
impl std::fmt::Debug for RouteGovernance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouteGovernance")
            .field("principals", &self.principals.len())
            .finish_non_exhaustive()
    }
}
#[derive(Debug, thiserror::Error)]
pub enum GovernanceError {
    #[error(transparent)]
    Policy(#[from] PolicyError),
    #[error(transparent)]
    Admission(#[from] AdmissionError),
    #[error(transparent)]
    Scheduler(#[from] SchedulerError),
    #[error("invalid or unsupported protocol request: {0}")]
    Protocol(&'static str),
}
impl RouteGovernance {
    pub fn session(self: &Arc<Self>, user: &str) -> Result<SessionGuard, GovernanceError> {
        let principal = self
            .principals
            .get(user)
            .ok_or(PolicyError::UnknownPrincipal)?
            .clone();
        // Username mapping is trusted configuration, never supplied via startup options.
        if principal.user != user {
            return Err(PolicyError::UnknownPrincipal.into());
        }
        self.policy.capabilities(&principal)?;
        Ok(SessionGuard {
            route: self.clone(),
            principal,
            statements: BTreeMap::new(),
            portals: BTreeMap::new(),
            permits: Vec::new(),
            cycles: VecDeque::new(),
            scheduler_permit: None,
        })
    }
}
pub struct SessionGuard {
    route: Arc<RouteGovernance>,
    principal: Principal,
    statements: BTreeMap<String, Arc<str>>,
    portals: BTreeMap<String, Arc<str>>,
    permits: Vec<Permit>,
    cycles: VecDeque<Vec<Permit>>,
    scheduler_permit: Option<SchedulerPermit>,
}
impl SessionGuard {
    pub fn context_commands(&self) -> Result<Vec<String>, GovernanceError> {
        self.route
            .contexts
            .get(&self.principal)
            .map(|context| context.session_commands())
            .transpose()
            .map(|commands| commands.unwrap_or_default())
            .map_err(Into::into)
    }
    pub fn principal(&self) -> &Principal {
        &self.principal
    }
    pub fn frontend(&mut self, tag: u8, payload: &[u8]) -> Result<(), GovernanceError> {
        match tag {
            b'Q' => {
                let mut bytes = payload;
                let sql = string(&mut bytes)?;
                if !bytes.is_empty() {
                    return Err(GovernanceError::Protocol("query tail"));
                }
                self.authorize(sql)?;
                self.charge()?;
                self.seal_cycle()?;
                self.statements.remove("");
                self.portals.clear();
            }
            b'P' => {
                let mut bytes = payload;
                let name = string(&mut bytes)?.to_owned();
                let sql = string(&mut bytes)?.to_owned();
                let count = u16::from_be_bytes(take::<2>(&mut bytes)?) as usize;
                for _ in 0..count {
                    let oid = u32::from_be_bytes(take::<4>(&mut bytes)?);
                    if !matches!(
                        oid,
                        0 | 16
                            | 17
                            | 18
                            | 19
                            | 20
                            | 21
                            | 23
                            | 25
                            | 26
                            | 700
                            | 701
                            | 1042
                            | 1043
                            | 1082
                            | 1083
                            | 1114
                            | 1184
                            | 1186
                            | 1700
                            | 2950
                            | 3802
                    ) {
                        return Err(GovernanceError::Protocol("custom parameter type"));
                    }
                }
                if !bytes.is_empty() {
                    return Err(GovernanceError::Protocol("parse tail"));
                }
                self.authorize(&sql)?;
                if name.len() > 256
                    || self.statements.len() >= 1024
                    || self.statements.values().map(|s| s.len()).sum::<usize>() + sql.len()
                        > 1024 * 1024
                {
                    return Err(GovernanceError::Protocol("statement budget"));
                }
                self.reserve_scheduler()?;
                self.statements.insert(name, Arc::from(sql));
            }
            b'B' => {
                let mut bytes = payload;
                let portal = string(&mut bytes)?.to_owned();
                let statement = string(&mut bytes)?;
                let sql = self
                    .statements
                    .get(statement)
                    .ok_or(GovernanceError::Protocol("unauthorized statement"))?
                    .clone();
                if portal.len() > 256 || self.portals.len() >= 1024 {
                    return Err(GovernanceError::Protocol("portal budget"));
                }
                // Bind framing/format validation is the existing wire codec/backend's job;
                // policy has already refused casts, operators and custom parameter types.
                self.portals.insert(portal, sql);
            }
            b'E' => {
                let mut bytes = payload;
                let portal = string(&mut bytes)?;
                let _rows = take::<4>(&mut bytes)?;
                if !bytes.is_empty() {
                    return Err(GovernanceError::Protocol("execute tail"));
                }
                let sql = self
                    .portals
                    .get(portal)
                    .ok_or(GovernanceError::Protocol("unauthorized portal"))?
                    .clone();
                self.authorize(&sql)?;
                self.charge()?;
            }
            b'D' => {
                let mut bytes = payload;
                let kind = take::<1>(&mut bytes)?[0];
                let name = string(&mut bytes)?;
                if !bytes.is_empty() {
                    return Err(GovernanceError::Protocol("describe tail"));
                }
                let known = match kind {
                    b'S' => self.statements.contains_key(name),
                    b'P' => self.portals.contains_key(name),
                    _ => false,
                };
                if !known {
                    return Err(GovernanceError::Protocol("unauthorized describe"));
                }
            }
            b'C' => {
                let mut bytes = payload;
                let kind = take::<1>(&mut bytes)?[0];
                let name = string(&mut bytes)?;
                if !bytes.is_empty() {
                    return Err(GovernanceError::Protocol("close tail"));
                }
                match kind {
                    b'S' => {
                        self.statements.remove(name);
                    }
                    b'P' => {
                        self.portals.remove(name);
                    }
                    _ => return Err(GovernanceError::Protocol("close kind")),
                }
            }
            b'S' => {
                if !payload.is_empty() {
                    return Err(GovernanceError::Protocol("control tail"));
                }
                self.seal_cycle()?;
            }
            b'H' | b'X' => {
                if !payload.is_empty() {
                    return Err(GovernanceError::Protocol("control tail"));
                }
            }
            _ => return Err(GovernanceError::Protocol("unsupported frontend message")),
        }
        Ok(())
    }
    fn authorize(&self, sql: &str) -> Result<(), GovernanceError> {
        let result = self
            .route
            .policy
            .authorize(sql, Default::default(), &self.principal);
        match &result {
            Ok(d) => {
                tracing::info!(user=%self.principal.user,tenant=%self.principal.tenant,agent=?self.principal.agent,fingerprint=d.fingerprint.hash,writes=d.writes,allowed=true,"SQL policy decision")
            }
            Err(_) => {
                tracing::warn!(user=%self.principal.user,tenant=%self.principal.tenant,agent=?self.principal.agent,allowed=false,"SQL policy decision")
            }
        }
        result.map(|_| ()).map_err(Into::into)
    }
    fn seal_cycle(&mut self) -> Result<(), GovernanceError> {
        if self.cycles.len() >= 1024 {
            return Err(GovernanceError::Protocol("cycle budget"));
        }
        self.cycles.push_back(std::mem::take(&mut self.permits));
        Ok(())
    }
    fn charge(&mut self) -> Result<(), GovernanceError> {
        if self.permits.len() + self.cycles.iter().map(Vec::len).sum::<usize>() >= 1024 {
            return Err(GovernanceError::Protocol("pipeline budget"));
        }
        let quota = self.route.admission.acquire(&self.principal)?;
        self.reserve_scheduler()?;
        self.permits.push(quota);
        Ok(())
    }
    fn reserve_scheduler(&mut self) -> Result<(), GovernanceError> {
        if self.scheduler_permit.is_some() {
            return Ok(());
        }
        if let Some((scheduler, wait)) = &self.route.scheduler {
            self.scheduler_permit = Some(scheduler.acquire(&self.principal, *wait)?);
        }
        Ok(())
    }
    /// MUST be called for every backend ErrorResponse. Failed Parse/Bind must not
    /// leave optimistic provenance authorizing an older backend statement/portal.
    pub fn backend_error(&mut self) {
        self.statements.clear();
        self.portals.clear();
    }
    /// Call only for the matching ReadyForQuery. Transaction-scoped portals expire
    /// on idle; held cursor SQL is denied by policy.
    pub fn ready(&mut self, status: u8) {
        self.cycles.pop_front();
        if status == b'I' {
            if self.cycles.is_empty() && self.permits.is_empty() {
                self.scheduler_permit.take();
            }
            self.portals.clear();
        }
    }
}
fn string<'a>(bytes: &mut &'a [u8]) -> Result<&'a str, GovernanceError> {
    let end = bytes
        .iter()
        .position(|b| *b == 0)
        .ok_or(GovernanceError::Protocol("missing terminator"))?;
    let value =
        std::str::from_utf8(&bytes[..end]).map_err(|_| GovernanceError::Protocol("non-UTF8"))?;
    *bytes = &bytes[end + 1..];
    Ok(value)
}
fn take<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N], GovernanceError> {
    if bytes.len() < N {
        return Err(GovernanceError::Protocol("short message"));
    }
    let value = bytes[..N].try_into().unwrap();
    *bytes = &bytes[N..];
    Ok(value)
}
#[cfg(test)]
mod tests {
    use super::*;
    use pgproxy_policy::{Capabilities, admission::Quota};
    fn guard() -> SessionGuard {
        let p = Principal {
            user: "app".into(),
            tenant: "one".into(),
            agent: None,
        };
        let policy = Policy::new(
            [(
                p.clone(),
                Capabilities {
                    read: ["public.allowed".into()].into(),
                    ..Default::default()
                },
            )]
            .into(),
        )
        .unwrap();
        let admission = Admission::new(
            [(
                p.clone(),
                Quota {
                    concurrency: 2,
                    burst: 10,
                    per_second: 10,
                    lifetime_queries: 20,
                },
            )]
            .into(),
        )
        .unwrap();
        Arc::new(RouteGovernance {
            policy,
            admission,
            principals: [("app".into(), p)].into(),
            scheduler: None,
            contexts: BTreeMap::new(),
        })
        .session("app")
        .unwrap()
    }
    #[test]
    fn extended_provenance_cannot_reuse_failed_parse() {
        let mut g = guard();
        g.frontend(b'P', b"s\0SELECT 1\0\0\0").unwrap();
        g.frontend(b'B', b"p\0s\0\0\0\0\0\0\0").unwrap();
        g.frontend(b'E', b"p\0\0\0\0\0").unwrap();
        g.frontend(b'S', b"").unwrap();
        g.ready(b'I');
        assert!(g.frontend(b'E', b"p\0\0\0\0\0").is_err());
        g.backend_error();
        assert!(g.frontend(b'B', b"p\0s\0").is_err());
    }
    #[test]
    fn parse_reserves_global_slot_until_matching_sync_ready() {
        use pgproxy_policy::{scheduler::Priority, shared_scheduler::SchedulerConfig};
        let mut g = guard();
        let scheduler = SharedScheduler::new(
            [(g.principal.clone(), (1, Priority::Interactive))].into(),
            SchedulerConfig {
                capacity: 2,
                per_principal: 2,
                minimum: 1,
                maximum: 1,
                initial: 1,
                queue_target_ms: 10,
                adaptive: false,
            },
        )
        .unwrap();
        Arc::get_mut(&mut g.route).unwrap().scheduler = Some((scheduler.clone(), Duration::ZERO));
        g.frontend(b'P', b"s\0SELECT 1\0\0\0").unwrap();
        assert_eq!(scheduler.active(), 1);
        g.frontend(b'B', b"p\0s\0\0\0\0\0\0\0").unwrap();
        g.frontend(b'E', b"p\0\0\0\0\0").unwrap();
        assert_eq!(scheduler.active(), 1);
        g.frontend(b'S', b"").unwrap();
        g.ready(b'T');
        assert_eq!(scheduler.active(), 1);
        g.frontend(b'Q', b"COMMIT\0").unwrap();
        g.ready(b'I');
        assert_eq!(scheduler.active(), 0);
    }
    #[test]
    fn unknown_or_custom_oid_and_multi_query_denied() {
        let mut g = guard();
        assert!(g.frontend(b'Q', b"SELECT 1; SELECT 2\0").is_err());
        assert!(
            g.frontend(b'P', b"s\0SELECT $1\0\0\x01\0\0\x40\x01")
                .is_err()
        );
        assert!(g.frontend(b'E', b"p\0\0\0\0\0").is_err());
    }
}
