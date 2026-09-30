//! Transport-independent agent tools. Executors receive only authorized requests.
use crate::shared_scheduler::{SchedulerError, SchedulerPermit, SharedScheduler};
use crate::{
    Decision, Policy, PolicyError, Principal,
    admission::{Admission, AdmissionError, Permit},
};
use pgproxy_parser::ParseOptions;
use std::{sync::Arc, time::Duration};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tool {
    Query,
    Explain,
    DescribeSchema,
}
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error(transparent)]
    Policy(#[from] PolicyError),
    #[error(transparent)]
    Admission(#[from] AdmissionError),
    #[error(transparent)]
    Scheduler(#[from] SchedulerError),
    #[error("query result budget exceeded")]
    ResultLimit,
    #[error("agent principal required")]
    Identity,
    #[error("invalid result limits")]
    Limits,
}
pub struct AuthorizedRequest {
    sql: String,
    pub decision: Decision,
    _permit: Permit,
    _scheduler: Option<SchedulerPermit>,
    max_rows: usize,
    max_bytes: usize,
}
impl AuthorizedRequest {
    pub fn remaining_limits(&self) -> (usize, usize) {
        (self.max_rows, self.max_bytes)
    }
    pub fn sql(&self) -> &str {
        &self.sql
    }
    /// Call before emitting each result, including binary bytes. Overflow emits no data.
    pub fn consume_result(&mut self, rows: usize, bytes: usize) -> Result<(), AgentError> {
        if rows > self.max_rows || bytes > self.max_bytes {
            return Err(AgentError::ResultLimit);
        }
        self.max_rows -= rows;
        self.max_bytes -= bytes;
        Ok(())
    }
}
pub struct AgentGateway {
    policy: Policy,
    admission: Admission,
    max_rows: usize,
    max_bytes: usize,
    scheduler: Option<(Arc<SharedScheduler>, Duration)>,
}
impl AgentGateway {
    pub fn new(
        policy: Policy,
        admission: Admission,
        max_rows: usize,
        max_bytes: usize,
    ) -> Result<Self, AgentError> {
        if max_rows == 0 || max_bytes == 0 {
            return Err(AgentError::Limits);
        }
        Ok(Self {
            policy,
            admission,
            max_rows,
            max_bytes,
            scheduler: None,
        })
    }
    pub fn with_scheduler(mut self, scheduler: Arc<SharedScheduler>, wait: Duration) -> Self {
        self.scheduler = Some((scheduler, wait));
        self
    }
    fn schedule(&self, principal: &Principal) -> Result<Option<SchedulerPermit>, AgentError> {
        match &self.scheduler {
            Some((scheduler, wait)) => Ok(Some(scheduler.acquire(principal, *wait)?)),
            None => Ok(None),
        }
    }
    pub fn authorize(
        &self,
        principal: &Principal,
        tool: Tool,
        sql: &str,
        options: ParseOptions,
    ) -> Result<AuthorizedRequest, AgentError> {
        if principal.agent.as_ref().is_none_or(|a| a.is_empty()) {
            return Err(AgentError::Identity);
        }
        if tool == Tool::DescribeSchema {
            return Err(
                PolicyError::Denied("use filtered_schema for schema discovery".into()).into(),
            );
        }
        let decision = self.policy.authorize(sql, options, principal)?;
        if !decision.read_only {
            return Err(PolicyError::Denied("agent tools are read-only".into()).into());
        }
        let permit = self.admission.acquire(principal)?;
        let scheduler = self.schedule(principal)?;
        let sql = if tool == Tool::Explain {
            format!("EXPLAIN (FORMAT JSON) {sql}")
        } else {
            sql.to_owned()
        };
        Ok(AuthorizedRequest {
            sql,
            decision,
            _permit: permit,
            _scheduler: scheduler,
            max_rows: self.max_rows,
            max_bytes: self.max_bytes,
        })
    }
    pub fn authorize_schema(&self, principal: &Principal) -> Result<AuthorizedSchema, AgentError> {
        if principal.agent.as_ref().is_none_or(|a| a.is_empty()) {
            return Err(AgentError::Identity);
        }
        let caps = self.policy.capabilities(principal)?;
        let permit = self.admission.acquire(principal)?;
        let scheduler = self.schedule(principal)?;
        Ok(AuthorizedSchema {
            tables: caps.read.iter().take(self.max_rows).cloned().collect(),
            denied_columns: caps.denied_columns.iter().cloned().collect(),
            max_rows: self.max_rows,
            max_bytes: self.max_bytes,
            _permit: permit,
            _scheduler: scheduler,
        })
    }
    /// Filter server-derived schema metadata before serializing it to the agent.
    pub fn filtered_schema<'a>(
        &self,
        principal: &Principal,
        tables: impl IntoIterator<Item = &'a str>,
    ) -> Result<Vec<String>, AgentError> {
        if principal.agent.is_none() {
            return Err(AgentError::Identity);
        }
        let caps = self.policy.capabilities(principal)?;
        let _permit = self.admission.acquire(principal)?;
        Ok(tables
            .into_iter()
            .filter(|t| caps.read.contains(*t))
            .map(str::to_owned)
            .take(self.max_rows)
            .collect())
    }
}
pub struct AuthorizedSchema {
    pub tables: Vec<String>,
    pub denied_columns: Vec<String>,
    pub max_rows: usize,
    pub max_bytes: usize,
    _permit: Permit,
    _scheduler: Option<SchedulerPermit>,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn agent_tools_cannot_bypass_policy_or_result_budget() {
        let (p, policy) = crate::tests::fixture();
        let a = Admission::new(
            [(
                p.clone(),
                crate::admission::Quota {
                    concurrency: 1,
                    burst: 10,
                    per_second: 10,
                    lifetime_queries: 10,
                },
            )]
            .into(),
        )
        .unwrap();
        let gateway = AgentGateway::new(policy, a, 2, 10).unwrap();
        assert!(
            gateway
                .authorize(
                    &p,
                    Tool::Explain,
                    "DELETE FROM public.allowed",
                    Default::default()
                )
                .is_err()
        );
        assert!(
            gateway
                .authorize(
                    &p,
                    Tool::Query,
                    "SELECT pg_catalog.pg_read_file('/etc/passwd')",
                    Default::default()
                )
                .is_err()
        );
        assert_eq!(
            gateway
                .filtered_schema(&p, ["public.allowed", "private.secret"])
                .unwrap(),
            vec!["public.allowed"]
        );
        let mut req = gateway
            .authorize(&p, Tool::Explain, "SELECT 1", Default::default())
            .unwrap();
        assert!(req.sql().starts_with("EXPLAIN (FORMAT JSON)"));
        req.consume_result(1, 8).unwrap();
        assert!(matches!(
            req.consume_result(1, 3),
            Err(AgentError::ResultLimit)
        ));
    }
}
