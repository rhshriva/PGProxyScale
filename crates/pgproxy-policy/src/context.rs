//! Typed trusted transaction context. Apply after BEGIN, before client Parse/Query,
//! and reset through transaction completion. Never append this to client SQL.
use crate::PolicyError;
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionContext {
    pub role: String,
    pub tenant: String,
    pub statement_timeout_ms: u32,
    pub read_only: bool,
}
impl TransactionContext {
    /// Apply only outside a transaction, before restoring prepared statements.
    /// Root runtime verifies writable-primary status before this trusted context.
    pub fn session_commands(&self) -> Result<Vec<String>, PolicyError> {
        self.statements()?;
        let role = self.role.replace('"', "\"\"");
        let tenant = self.tenant.replace('\\', "\\\\").replace('\'', "''");
        Ok(vec![
            format!("SET ROLE \"{role}\""),
            format!("SELECT pg_catalog.set_config('pgproxy.tenant', E'{tenant}', false)"),
            format!("SET statement_timeout = '{}'", self.statement_timeout_ms),
            format!(
                "SET default_transaction_read_only = {}",
                if self.read_only { "on" } else { "off" }
            ),
        ])
    }
    pub fn statements(&self) -> Result<Vec<String>, PolicyError> {
        if self.role.is_empty()
            || self.role.len() > 63
            || self.role.contains('\0')
            || self.tenant.contains('\0')
            || self.tenant.len() > 4096
            || self.statement_timeout_ms == 0
        {
            return Err(PolicyError::Denied("invalid transaction context".into()));
        }
        let role = self.role.replace('"', "\"\"");
        let tenant = self.tenant.replace('\\', "\\\\").replace('\'', "''");
        let mut sql = vec![
            format!("SET LOCAL ROLE \"{role}\""),
            format!("SELECT pg_catalog.set_config('pgproxy.tenant', E'{tenant}', true)"),
            format!(
                "SET LOCAL statement_timeout = '{}'",
                self.statement_timeout_ms
            ),
        ];
        if self.read_only {
            sql.push("SET TRANSACTION READ ONLY".into());
        }
        Ok(sql)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hostile_identifiers_and_values_are_not_executable_sql() {
        let c = TransactionContext {
            role: "a\"; RESET ROLE; --".into(),
            tenant: "a\\'; RESET ROLE; --".into(),
            statement_timeout_ms: 100,
            read_only: true,
        };
        let mut statements = c.statements().unwrap();
        statements.extend(c.session_commands().unwrap());
        for sql in statements {
            let parsed = pgproxy_parser::parse(&sql, Default::default(), 65536, 1 << 20).unwrap();
            assert_eq!(parsed.statements().count(), 1, "{sql}");
        }
    }
    #[test]
    fn zero_timeout_and_nul_denied() {
        let mut c = TransactionContext {
            role: "a".into(),
            tenant: "b".into(),
            statement_timeout_ms: 0,
            read_only: true,
        };
        assert!(c.statements().is_err());
        c.statement_timeout_ms = 1;
        c.role.push('\0');
        assert!(c.statements().is_err());
    }
}
