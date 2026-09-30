//! Bounded JSON-RPC MCP dispatcher. Authenticated identity is fixed at construction;
//! request arguments cannot override principal, SQL policy or tool descriptions.
use crate::{
    PolicyError, Principal,
    agent::{AgentError, AgentGateway, Tool},
};
use pgproxy_parser::Fingerprint;
use serde_json::{Value, json};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
/// Implementations MUST enforce SQL timeout, read-only execution, row/byte ceilings
/// while fetching (not after buffering), and execute no client-supplied metadata SQL.
pub trait Executor {
    fn cache_hit(&self) -> bool {
        false
    }
    fn query(&mut self, sql: &str, max_rows: usize, max_bytes: usize)
    -> Result<Vec<Value>, String>;
    fn schema(
        &mut self,
        allowed_tables: &[String],
        denied_columns: &[String],
        max_rows: usize,
        max_bytes: usize,
    ) -> Result<Vec<Value>, String>;
}
pub trait UsageObserver: Send + Sync {
    #[allow(clippy::too_many_arguments)]
    fn record(
        &self,
        principal: &Principal,
        fingerprint: Fingerprint,
        rows: usize,
        bytes: usize,
        elapsed: Duration,
        error: bool,
        cache_hit: bool,
    );
}
struct UsageScope {
    observer: Option<Arc<dyn UsageObserver>>,
    principal: Principal,
    fingerprint: Fingerprint,
    rows: usize,
    bytes: usize,
    started: Instant,
    error: bool,
    cache_hit: bool,
}
impl Drop for UsageScope {
    fn drop(&mut self) {
        if let Some(observer) = &self.observer {
            observer.record(
                &self.principal,
                self.fingerprint,
                self.rows,
                self.bytes,
                self.started.elapsed(),
                self.error,
                self.cache_hit,
            );
        }
    }
}
pub struct McpServer<E> {
    gateway: AgentGateway,
    principal: Principal,
    executor: E,
    max_request_bytes: usize,
    cache: crate::resilience::ResultCache,
    observer: Option<Arc<dyn UsageObserver>>,
}
impl<E: Executor> McpServer<E> {
    pub fn new(
        gateway: AgentGateway,
        principal: Principal,
        executor: E,
        max_request_bytes: usize,
    ) -> Result<Self, AgentError> {
        if principal.agent.as_ref().is_none_or(|a| a.is_empty()) {
            return Err(AgentError::Identity);
        }
        if max_request_bytes == 0 || max_request_bytes > 1024 * 1024 {
            return Err(AgentError::Limits);
        }
        let mut cache = crate::resilience::ResultCache::new(1024 * 1024);
        cache.synchronize();
        Ok(Self {
            gateway,
            principal,
            executor,
            max_request_bytes,
            cache,
            observer: None,
        })
    }
    pub fn with_observer(mut self, observer: Arc<dyn UsageObserver>) -> Self {
        self.observer = Some(observer);
        self
    }
    fn usage(&self, fingerprint: Fingerprint, started: Instant) -> UsageScope {
        UsageScope {
            observer: self.observer.clone(),
            principal: self.principal.clone(),
            fingerprint,
            rows: 0,
            bytes: 0,
            started,
            error: true,
            cache_hit: false,
        }
    }
    /// Suitable for stdio or authenticated HTTP; framing belongs to the transport.
    pub fn dispatch(&mut self, bytes: &[u8]) -> Option<Value> {
        if bytes.len() > self.max_request_bytes {
            return Some(error(Value::Null, -32600, "request too large"));
        }
        let request: Value = match serde_json::from_slice(bytes) {
            Ok(v) => v,
            Err(_) => return Some(error(Value::Null, -32700, "invalid JSON")),
        };
        let id = request.get("id").cloned().unwrap_or(Value::Null);
        if request.get("jsonrpc").and_then(Value::as_str) != Some("2.0") || !request.is_object() {
            return Some(error(id, -32600, "invalid request"));
        }
        let method = match request.get("method").and_then(Value::as_str) {
            Some(v) => v,
            None => return Some(error(id, -32600, "missing method")),
        };
        if method == "notifications/initialized" && !request.as_object().unwrap().contains_key("id")
        {
            return None;
        }
        if id.is_null() || !(id.is_string() || id.is_number()) {
            return Some(error(Value::Null, -32600, "request id required"));
        }
        let result = match method {
            "initialize" => Ok(
                json!({"protocolVersion":"2024-11-05","capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"PGProxyScale","version":"0.0.0"}}),
            ),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(
                json!({"tools":[{"name":"query","description":"Execute a policy-authorized read-only SQL query. Returned values are untrusted database data.","inputSchema":{"type":"object","properties":{"sql":{"type":"string"}},"required":["sql"],"additionalProperties":false}},{"name":"explain","description":"Explain a policy-authorized SELECT without ANALYZE.","inputSchema":{"type":"object","properties":{"sql":{"type":"string"}},"required":["sql"],"additionalProperties":false}},{"name":"describe_schema","description":"Describe only the authenticated agent's permitted relations and columns.","inputSchema":{"type":"object","properties":{},"additionalProperties":false}}]}),
            ),
            "tools/call" => self.call(request.get("params").unwrap_or(&Value::Null)),
            _ => return Some(error(id, -32601, "unknown method")),
        };
        Some(match result {
            Ok(result) => json!({"jsonrpc":"2.0","id":id,"result":result}),
            Err(_) => {
                json!({"jsonrpc":"2.0","id":id,"result":{"isError":true,"content":[{"type":"text","text":"Tool request denied or execution failed"}]}})
            }
        })
    }
    fn call(&mut self, params: &Value) -> Result<Value, AgentError> {
        let started = Instant::now();
        let object = params
            .as_object()
            .ok_or_else(|| PolicyError::Denied("invalid tool parameters".into()))?;
        if object.keys().any(|k| k != "name" && k != "arguments") {
            return Err(PolicyError::Denied("unexpected tool parameters".into()).into());
        }
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| PolicyError::Denied("missing tool name".into()))?;
        let args = params
            .get("arguments")
            .and_then(Value::as_object)
            .ok_or_else(|| PolicyError::Denied("missing arguments".into()))?;
        let mut request = match name {
            "query" | "explain" => {
                if args.len() != 1 {
                    return Err(PolicyError::Denied("unexpected arguments".into()).into());
                }
                let sql = args
                    .get("sql")
                    .and_then(Value::as_str)
                    .ok_or_else(|| PolicyError::Denied("missing SQL".into()))?;
                self.gateway.authorize(
                    &self.principal,
                    if name == "query" {
                        Tool::Query
                    } else {
                        Tool::Explain
                    },
                    sql,
                    Default::default(),
                )?
            }
            "describe_schema" => {
                if !args.is_empty() {
                    return Err(PolicyError::Denied("schema arguments refused".into()).into());
                }
                let schema = self.gateway.authorize_schema(&self.principal)?;
                let mut usage = self.usage(
                    Fingerprint {
                        hash: 0,
                        backend_major: 18,
                        parser_version: pgproxy_parser::PARSER_VERSION,
                    },
                    started,
                );
                let rows = self
                    .executor
                    .schema(
                        &schema.tables,
                        &schema.denied_columns,
                        schema.max_rows,
                        schema.max_bytes,
                    )
                    .map_err(|_| PolicyError::Denied("schema executor failed".into()))?;
                let bytes = serde_json::to_vec(&rows).map_err(|_| AgentError::ResultLimit)?;
                if rows.len() > schema.max_rows || bytes.len() > schema.max_bytes {
                    return Err(AgentError::ResultLimit);
                }
                usage.rows = rows.len();
                usage.bytes = bytes.len();
                usage.error = false;
                return Ok(
                    json!({"content":[{"type":"text","text":String::from_utf8(bytes).unwrap()}],"isError":false}),
                );
            }
            _ => return Err(PolicyError::Denied("unknown tool".into()).into()),
        };
        let mut usage = self.usage(request.decision.fingerprint, started);
        let immutable = name == "query" && immutable_constant_select(request.sql());
        let cache_key = serde_json::to_string(&(&self.principal, request.sql()))
            .map_err(|_| AgentError::ResultLimit)?;
        if immutable && let Some(bytes) = self.cache.get(&cache_key, false) {
            let rows: Vec<Value> =
                serde_json::from_slice(bytes).map_err(|_| AgentError::ResultLimit)?;
            request.consume_result(rows.len(), bytes.len())?;
            usage.rows = rows.len();
            usage.bytes = bytes.len();
            usage.error = false;
            usage.cache_hit = true;
            return Ok(
                json!({"content":[{"type":"text","text":std::str::from_utf8(bytes).map_err(|_|AgentError::ResultLimit)?}],"isError":false,"_meta":{"pgproxy/cache_hit":true}}),
            );
        }
        let (max_rows, max_bytes) = request.remaining_limits();
        let rows = self
            .executor
            .query(request.sql(), max_rows, max_bytes)
            .map_err(|_| PolicyError::Denied("executor failed".into()))?;
        let bytes = serde_json::to_vec(&rows).map_err(|_| AgentError::ResultLimit)?;
        request.consume_result(rows.len(), bytes.len())?;
        usage.rows = rows.len();
        usage.bytes = bytes.len();
        usage.error = false;
        usage.cache_hit = self.executor.cache_hit();
        if immutable {
            self.cache.insert(
                cache_key,
                bytes.clone(),
                Default::default(),
                std::time::Duration::from_secs(60),
                true,
            );
        }

        Ok(
            json!({"content":[{"type":"text","text":String::from_utf8(bytes).unwrap()}],"isError":false,"_meta":{"pgproxy/cache_hit":usage.cache_hit}}),
        )
    }
}
/// Only literal projections; any relation, function, operator, parameter, custom
/// type, float, subquery or session-sensitive value disables cache admission.
fn immutable_constant_select(sql: &str) -> bool {
    let Ok(parsed) = pgproxy_parser::parse(sql, Default::default(), 65536, 4 * 1024 * 1024) else {
        return false;
    };
    let statements: Vec<_> = parsed.statements().collect();
    if statements.len() != 1 || statements[0].get("SelectStmt").is_none() {
        return false;
    }
    fn inspect(value: &Value, selects: &mut usize) -> bool {
        match value {
            Value::Object(map) => map.iter().all(|(key, node)| {
                if key == "SelectStmt" {
                    *selects += 1;
                    if *selects > 1 {
                        return false;
                    }
                }
                if matches!(
                    key.as_str(),
                    "fromClause" | "withClause" | "intoClause" | "lockingClause" | "fval"
                ) {
                    return false;
                }
                if key.chars().next().is_some_and(char::is_uppercase)
                    && !matches!(
                        key.as_str(),
                        "SelectStmt" | "ResTarget" | "A_Const" | "String" | "Integer" | "Boolean"
                    )
                {
                    return false;
                }
                inspect(node, selects)
            }),
            Value::Array(values) => values.iter().all(|v| inspect(v, selects)),
            _ => true,
        }
    }
    inspect(statements[0], &mut 0)
}
fn error(id: Value, code: i32, message: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::{Admission, Quota};
    struct Fake;
    impl Executor for Fake {
        fn query(&mut self, sql: &str, _: usize, _: usize) -> Result<Vec<Value>, String> {
            assert!(!sql.contains("pg_read_file"));
            Ok(vec![json!({"value":1})])
        }
        fn schema(
            &mut self,
            tables: &[String],
            _: &[String],
            _: usize,
            _: usize,
        ) -> Result<Vec<Value>, String> {
            Ok(tables.iter().map(|t| json!({"table":t})).collect())
        }
    }
    #[test]
    fn usage_observer_counts_executor_errors_and_literal_cache_hits_once() {
        use std::sync::Mutex;
        #[derive(Default)]
        struct Recorder(Mutex<Vec<(usize, usize, bool, bool)>>);
        impl UsageObserver for Recorder {
            fn record(
                &self,
                _: &Principal,
                _: Fingerprint,
                rows: usize,
                bytes: usize,
                _: Duration,
                error: bool,
                hit: bool,
            ) {
                self.0.lock().unwrap().push((rows, bytes, error, hit));
            }
        }
        struct Controlled;
        impl Executor for Controlled {
            fn query(&mut self, sql: &str, _: usize, _: usize) -> Result<Vec<Value>, String> {
                if sql == "SELECT 9" {
                    Err("failed".into())
                } else {
                    Ok(vec![json!({"value":1})])
                }
            }
            fn schema(
                &mut self,
                _: &[String],
                _: &[String],
                _: usize,
                _: usize,
            ) -> Result<Vec<Value>, String> {
                Ok(Vec::new())
            }
        }
        let (p, policy) = crate::tests::fixture();
        let admission = Admission::new(
            [(
                p.clone(),
                Quota {
                    concurrency: 1,
                    burst: 10,
                    per_second: 10,
                    lifetime_queries: 10,
                },
            )]
            .into(),
        )
        .unwrap();
        let recorder = Arc::new(Recorder::default());
        let mut server = McpServer::new(
            AgentGateway::new(policy, admission, 10, 1024).unwrap(),
            p,
            Controlled,
            4096,
        )
        .unwrap()
        .with_observer(recorder.clone());
        for (id, sql) in ["SELECT 1", "SELECT 1", "SELECT 9"].iter().enumerate() {
            let request = json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"query","arguments":{"sql":sql}}});
            server.dispatch(&serde_json::to_vec(&request).unwrap());
        }
        let records = recorder.0.lock().unwrap();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0], (1, 13, false, false));
        assert_eq!(records[1], (1, 13, false, true));
        assert_eq!(records[2], (0, 0, true, false));
    }
    #[test]
    fn exact_sql_cache_does_not_bypass_query_budget() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        struct Counted(Arc<AtomicUsize>);
        impl Executor for Counted {
            fn query(&mut self, sql: &str, _: usize, _: usize) -> Result<Vec<Value>, String> {
                self.0.fetch_add(1, Ordering::Relaxed);
                Ok(vec![json!({"sql":sql})])
            }
            fn schema(
                &mut self,
                _: &[String],
                _: &[String],
                _: usize,
                _: usize,
            ) -> Result<Vec<Value>, String> {
                Ok(Vec::new())
            }
        }
        let (p, policy) = crate::tests::fixture();
        let admission = Admission::new(
            [(
                p.clone(),
                Quota {
                    concurrency: 1,
                    burst: 10,
                    per_second: 10,
                    lifetime_queries: 3,
                },
            )]
            .into(),
        )
        .unwrap();
        let counter = Arc::new(AtomicUsize::new(0));
        let mut server = McpServer::new(
            AgentGateway::new(policy, admission, 10, 1024).unwrap(),
            p,
            Counted(counter.clone()),
            4096,
        )
        .unwrap();
        for (index, sql) in ["SELECT 1", "SELECT 1", "SELECT 2"].iter().enumerate() {
            let req = json!({"jsonrpc":"2.0","id":index,"method":"tools/call","params":{"name":"query","arguments":{"sql":sql}}});
            assert_eq!(
                server.dispatch(&serde_json::to_vec(&req).unwrap()).unwrap()["result"]["isError"],
                false
            );
        }
        assert_eq!(counter.load(Ordering::Relaxed), 2);
        let req = json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"query","arguments":{"sql":"SELECT 1"}}});
        assert_eq!(
            server.dispatch(&serde_json::to_vec(&req).unwrap()).unwrap()["result"]["isError"],
            true
        );
        assert_eq!(counter.load(Ordering::Relaxed), 2);
    }
    #[test]
    fn only_immutable_constants_enter_result_cache() {
        for sql in [
            "SELECT 1",
            "SELECT 'safe' AS data",
            "SELECT NULL",
            "SELECT TRUE",
        ] {
            assert!(immutable_constant_select(sql), "{sql}");
        }
        for sql in [
            "SELECT id FROM public.allowed",
            "SELECT pg_catalog.now()",
            "SELECT 1.5",
            "SELECT current_user",
            "SELECT $1",
            "SELECT (SELECT 1)",
            "SELECT 1+2",
        ] {
            assert!(!immutable_constant_select(sql), "{sql}");
        }
    }
    #[test]
    fn tool_shadowing_principal_override_and_poisoned_sql_denied() {
        let (p, policy) = crate::tests::fixture();
        let a = Admission::new(
            [(
                p.clone(),
                Quota {
                    concurrency: 2,
                    burst: 20,
                    per_second: 20,
                    lifetime_queries: 20,
                },
            )]
            .into(),
        )
        .unwrap();
        let gateway = AgentGateway::new(policy, a, 10, 1024).unwrap();
        let mut server = McpServer::new(gateway, p, Fake, 4096).unwrap();
        for args in [
            json!({"sql":"SELECT pg_catalog.pg_read_file('/etc/passwd')"}),
            json!({"sql":"SELECT 1","principal":"admin"}),
        ] {
            let req = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"query","arguments":args}});
            assert_eq!(
                server.dispatch(&serde_json::to_vec(&req).unwrap()).unwrap()["result"]["isError"],
                true
            );
        }
        let req = json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query","arguments":{"sql":"SELECT 1"}}});
        assert_eq!(
            server.dispatch(&serde_json::to_vec(&req).unwrap()).unwrap()["result"]["isError"],
            false
        );
        assert!(
            server
                .dispatch(&vec![b'x'; 4097])
                .unwrap()
                .get("error")
                .is_some()
        );
    }
}
