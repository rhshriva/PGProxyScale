//! Fail-closed SQL capabilities shared by wire and agent transports.
#![forbid(unsafe_code)]
use pgproxy_parser::{Fingerprint, ParseOptions};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
pub mod admission;
pub mod agent;
pub mod context;
pub mod mcp;
pub mod relation_cache;
pub mod resilience;
pub mod scheduler;
pub mod shared_scheduler;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Principal {
    pub user: String,
    pub tenant: String,
    pub agent: Option<String>,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capabilities {
    pub read: BTreeSet<String>,
    pub write: BTreeSet<String>,
    /// Only fully qualified functions. Operators, casts, custom types and CTEs are refused.
    pub functions: BTreeSet<String>,
    /// Column names that may not appear in results. Wildcards are refused when populated.
    pub denied_columns: BTreeSet<String>,
}
#[derive(Debug, Clone, Default)]
pub struct Policy {
    grants: BTreeMap<Principal, Capabilities>,
}
#[derive(Debug, Clone)]
pub struct Decision {
    pub fingerprint: Fingerprint,
    pub tables: BTreeSet<String>,
    pub writes: bool,
    pub read_only: bool,
}
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PolicyError {
    #[error("principal has no capabilities")]
    UnknownPrincipal,
    #[error("SQL parse failed: {0}")]
    Parse(String),
    #[error("SQL capability denied: {0}")]
    Denied(String),
}
impl Policy {
    pub fn new(grants: BTreeMap<Principal, Capabilities>) -> Result<Self, PolicyError> {
        for capability in grants.values() {
            if capability.functions.contains("pg_catalog.set_config") {
                return Err(deny("set_config may override trusted principal context"));
            }

            for name in capability
                .read
                .iter()
                .chain(&capability.write)
                .chain(&capability.functions)
            {
                if name.split('.').count() != 2 || name.split('.').any(|p| p.is_empty()) {
                    return Err(PolicyError::Denied(
                        "capabilities require schema-qualified names".into(),
                    ));
                }
            }
        }
        Ok(Self { grants })
    }
    pub fn capabilities(&self, principal: &Principal) -> Result<&Capabilities, PolicyError> {
        self.grants
            .get(principal)
            .ok_or(PolicyError::UnknownPrincipal)
    }
    pub fn authorize(
        &self,
        sql: &str,
        options: ParseOptions,
        principal: &Principal,
    ) -> Result<Decision, PolicyError> {
        let grants = self.capabilities(principal)?;
        let parsed = pgproxy_parser::parse(sql, options, 64 * 1024, 4 * 1024 * 1024)
            .map_err(|e| PolicyError::Parse(e.to_string()))?;
        let mut decision = Decision {
            fingerprint: parsed.fingerprint,
            tables: BTreeSet::new(),
            writes: false,
            read_only: false,
        };
        let statements: Vec<_> = parsed.statements().collect();
        if statements.len() != 1 {
            return Err(PolicyError::Denied("exactly one statement required".into()));
        }
        let kind = statements[0]
            .as_object()
            .and_then(|m| m.keys().next())
            .ok_or_else(|| PolicyError::Denied("missing statement".into()))?;
        if kind == "TransactionStmt" {
            let transaction = &statements[0]["TransactionStmt"];
            if matches!(
                transaction.get("kind").and_then(Value::as_str),
                Some(
                    "TRANS_STMT_BEGIN"
                        | "TRANS_STMT_START"
                        | "TRANS_STMT_COMMIT"
                        | "TRANS_STMT_ROLLBACK"
                )
            ) && transaction.get("options").is_none()
                && transaction.get("gid").is_none()
            {
                return Ok(decision);
            }
            return Err(deny("unsupported transaction control"));
        }
        decision.read_only = kind == "SelectStmt";
        decision.writes = matches!(kind.as_str(), "InsertStmt" | "UpdateStmt" | "DeleteStmt");
        if !matches!(
            kind.as_str(),
            "SelectStmt" | "InsertStmt" | "UpdateStmt" | "DeleteStmt"
        ) {
            return Err(PolicyError::Denied(format!("statement {kind}")));
        }
        if !grants.denied_columns.is_empty() {
            let mut row_names = BTreeSet::new();
            collect_row_names(statements[0], &mut row_names);
            reject_protected_row_access(statements[0], &row_names)?;
        }
        inspect(statements[0], grants, &mut decision)?;
        Ok(decision)
    }
}
fn deny(reason: impl Into<String>) -> PolicyError {
    PolicyError::Denied(reason.into())
}
// A composite whole-row value contains every column, including denied columns.
// PostgreSQL resolves a bare relation/alias name as a whole-row reference when no
// column of that name exists. We cannot resolve that ambiguity without a catalog,
// so protected-column policies conservatively reject those references.
fn collect_row_names(value: &Value, names: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            if let Some(relation) = map.get("RangeVar") {
                if let Some(name) = relation.get("relname").and_then(Value::as_str) {
                    names.insert(name.to_owned());
                }
                if let Some(name) = relation
                    .get("alias")
                    .and_then(|alias| alias.get("aliasname"))
                    .and_then(Value::as_str)
                {
                    names.insert(name.to_owned());
                }
            }
            for child in map.values() {
                collect_row_names(child, names);
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_row_names(child, names);
            }
        }
        _ => {}
    }
}
fn reject_protected_row_access(value: &Value, names: &BTreeSet<String>) -> Result<(), PolicyError> {
    match value {
        Value::Object(map) => {
            if map
                .get("RangeVar")
                .and_then(|relation| relation.get("alias"))
                .and_then(|alias| alias.get("colnames"))
                .and_then(Value::as_array)
                .is_some_and(|columns| !columns.is_empty())
            {
                return Err(deny("column aliases may rename protected columns"));
            }
            if map
                .get("ColumnRef")
                .and_then(|reference| reference.get("fields"))
                .and_then(Value::as_array)
                .and_then(|fields| fields.last())
                .and_then(|field| field.get("String"))
                .and_then(|name| name.get("sval"))
                .and_then(Value::as_str)
                .is_some_and(|name| names.contains(name))
            {
                return Err(deny("whole-row references may expose protected columns"));
            }
            for child in map.values() {
                reject_protected_row_access(child, names)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                reject_protected_row_access(child, names)?;
            }
        }
        _ => {}
    }
    Ok(())
}
fn inspect(
    value: &Value,
    grants: &Capabilities,
    decision: &mut Decision,
) -> Result<(), PolicyError> {
    match value {
        Value::Object(map) => {
            for (key, node) in map {
                if matches!(
                    key.as_str(),
                    "intoClause" | "withClause" | "lockingClause" | "onConflictClause"
                ) {
                    return Err(deny(format!("unsupported SQL clause {key}")));
                }
                // Do not whitelist all PostgreSQL expression nodes: custom operators and casts
                // can call arbitrary user-defined functions without a FuncCall node.
                if key.chars().next().is_some_and(char::is_uppercase)
                    && !matches!(
                        key.as_str(),
                        "SelectStmt"
                            | "InsertStmt"
                            | "UpdateStmt"
                            | "DeleteStmt"
                            | "RangeVar"
                            | "ColumnRef"
                            | "String"
                            | "Integer"
                            | "Float"
                            | "Boolean"
                            | "A_Const"
                            | "A_Star"
                            | "ResTarget"
                            | "ParamRef"
                            | "FuncCall"
                            | "SortBy"
                            | "Alias"
                    )
                {
                    return Err(deny(format!("unsupported AST node {key}")));
                }
                if key == "RangeVar" {
                    let schema = node
                        .get("schemaname")
                        .and_then(Value::as_str)
                        .ok_or_else(|| deny("relation must be schema-qualified"))?;
                    let relation = node
                        .get("relname")
                        .and_then(Value::as_str)
                        .ok_or_else(|| deny("missing relation"))?;
                    let name = format!("{schema}.{relation}");
                    if !grants.read.contains(&name)
                        || (decision.writes && !grants.write.contains(&name))
                    {
                        return Err(deny(format!("relation {name}")));
                    }
                    decision.tables.insert(name);
                }
                if key == "FuncCall" {
                    let parts: Vec<_> = node
                        .get("funcname")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .filter_map(|v| v.get("String")?.get("sval")?.as_str())
                        .collect();
                    if parts.len() != 2 || !grants.functions.contains(&parts.join(".")) {
                        return Err(deny("function requires explicit qualified capability"));
                    }
                }
                if !grants.denied_columns.is_empty() {
                    if key == "A_Star" {
                        return Err(deny("wildcards may expose protected columns"));
                    }
                    if key == "ColumnRef" {
                        for field in node
                            .get("fields")
                            .and_then(Value::as_array)
                            .into_iter()
                            .flatten()
                        {
                            if field
                                .get("String")
                                .and_then(|s| s.get("sval"))
                                .and_then(Value::as_str)
                                .is_some_and(|s| grants.denied_columns.contains(s))
                            {
                                return Err(deny("protected column"));
                            }
                        }
                    }
                }
                inspect(node, grants, decision)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                inspect(value, grants, decision)?;
            }
        }
        _ => {}
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    pub fn fixture() -> (Principal, Policy) {
        let principal = Principal {
            user: "app".into(),
            tenant: "one".into(),
            agent: Some("bot".into()),
        };
        let caps = Capabilities {
            read: ["public.allowed".into()].into(),
            functions: ["pg_catalog.count".into()].into(),
            ..Default::default()
        };
        let policy = Policy::new([(principal.clone(), caps)].into()).unwrap();
        (principal, policy)
    }
    #[test]
    fn reads_and_principal_isolation() {
        let (p, policy) = fixture();
        assert!(
            policy
                .authorize("SELECT id FROM public.allowed", Default::default(), &p)
                .is_ok()
        );
        let mut other = p.clone();
        other.tenant = "two".into();
        assert_eq!(
            policy
                .authorize("SELECT 1", Default::default(), &other)
                .unwrap_err(),
            PolicyError::UnknownPrincipal
        );
    }
    #[test]
    fn bypass_corpus() {
        let (p, policy) = fixture();
        for sql in [
            "SELECT * FROM private.secret",
            "SELECT pg_read_file('/etc/passwd')",
            "SELECT * FROM pg_catalog.pg_read_file('/etc/passwd')",
            "DO $$ BEGIN EXECUTE 'SELECT 1'; END $$",
            "COPY public.allowed TO PROGRAM 'id'",
            "SET ROLE admin",
            "SELECT 1; SELECT 2",
            "SELECT 1 OPERATOR(public.+) 2",
            "SELECT 'x'::public.custom",
            "WITH x AS (DELETE FROM public.allowed RETURNING *) SELECT * FROM x",
            "SELECT * FROM allowed",
            "SELECT public.evil(id) FROM public.allowed",
            "SELECT * INTO public.stolen FROM public.allowed",
            "EXPLAIN ANALYZE DELETE FROM public.allowed",
        ] {
            assert!(
                policy.authorize(sql, Default::default(), &p).is_err(),
                "{sql}"
            );
        }
    }
    #[test]
    fn principal_context_mutators_cannot_be_granted() {
        let (p, _) = fixture();
        let caps = Capabilities {
            functions: ["pg_catalog.set_config".into()].into(),
            ..Default::default()
        };
        assert!(Policy::new([(p, caps)].into()).is_err());
    }
    #[test]
    fn ordinary_transaction_controls_only() {
        let (p, policy) = fixture();
        for sql in ["BEGIN", "COMMIT", "ROLLBACK"] {
            assert!(
                policy.authorize(sql, Default::default(), &p).is_ok(),
                "{sql}"
            );
        }
        for sql in [
            "PREPARE TRANSACTION 'x'",
            "COMMIT PREPARED 'x'",
            "BEGIN ISOLATION LEVEL SERIALIZABLE",
        ] {
            assert!(
                policy.authorize(sql, Default::default(), &p).is_err(),
                "{sql}"
            );
        }
    }
    #[test]
    fn protected_columns_and_wildcards() {
        let (p, mut policy) = fixture();
        policy
            .grants
            .get_mut(&p)
            .unwrap()
            .denied_columns
            .insert("ssn".into());
        for sql in [
            "SELECT * FROM public.allowed",
            "SELECT a.ssn AS harmless FROM public.allowed a",
            "SELECT ssn FROM public.allowed",
            "SELECT a FROM public.allowed AS a",
            "SELECT allowed FROM public.allowed",
            "SELECT public.allowed FROM public.allowed",
            "SELECT pg_catalog.count(a) FROM public.allowed AS a",
            "SELECT safe FROM public.allowed AS a(id, safe)",
            "SELECT \"Hidden\" FROM public.allowed AS \"Hidden\"",
        ] {
            assert!(
                policy.authorize(sql, Default::default(), &p).is_err(),
                "{sql}"
            );
        }
        assert!(
            policy
                .authorize("SELECT id FROM public.allowed", Default::default(), &p)
                .is_ok()
        );
    }
}
