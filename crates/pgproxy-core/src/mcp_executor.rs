//! Fresh, read-only PostgreSQL transactions for authenticated MCP requests.
use pgproxy_policy::{
    Principal,
    mcp::Executor,
    relation_cache::{CacheStatistics, SnapshotResultCache, SnapshotStamp, relation_projection},
};
use pgproxy_wire::{BackendConnection, ResolvedBackend, SessionOptions};
use serde_json::{Value, json};
use std::time::Instant;
pub struct PgExecutor {
    route: ResolvedBackend,
    options: SessionOptions,
    context: Option<pgproxy_policy::context::TransactionContext>,
    principal: Option<Principal>,
    cache: SnapshotResultCache,
    cache_hit: bool,
}
impl PgExecutor {
    pub fn new(route: ResolvedBackend, options: SessionOptions) -> Result<Self, String> {
        if route.credentials.is_none() {
            return Err("MCP requires terminated backend credentials".into());
        }
        if options.query_timeout.is_zero() {
            return Err("MCP query timeout must be positive".into());
        }
        Ok(Self {
            route,
            options,
            context: None,
            principal: None,
            cache: SnapshotResultCache::new(1024 * 1024),
            cache_hit: false,
        })
    }
    pub fn with_context(
        mut self,
        context: Option<pgproxy_policy::context::TransactionContext>,
    ) -> Self {
        self.cache.disconnect();
        self.context = context;
        self
    }
    pub fn with_principal(mut self, principal: Principal) -> Self {
        self.cache.disconnect();
        self.principal = Some(principal);
        self
    }
    pub fn cache_statistics(&self) -> CacheStatistics {
        self.cache.statistics()
    }
    fn execute(
        &mut self,
        sql: &str,
        max_rows: usize,
        max_bytes: usize,
    ) -> Result<Vec<Value>, String> {
        self.cache_hit = false;
        let result = self.execute_inner(sql, max_rows, max_bytes);
        if result.is_err() {
            self.cache_hit = false;
            self.cache.disconnect();
        }
        result
    }
    fn execute_inner(
        &mut self,
        sql: &str,
        max_rows: usize,
        max_bytes: usize,
    ) -> Result<Vec<Value>, String> {
        if max_rows == 0 || max_bytes < 2 {
            return Err("invalid result limits".into());
        }
        let deadline = Instant::now() + self.route.connect_timeout;
        let capacity = self
            .options
            .backend_capacity
            .acquire(self.route.connect_timeout)
            .map_err(|e| e.to_string())?;
        let limit = self
            .options
            .max_message_len
            .min(max_bytes.saturating_add(65536));
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or("backend acquisition deadline")?;
        let mut backend = self
            .route
            .connect_backend(remaining, limit)
            .map_err(|_| "backend acquisition failed")?
            .with_capacity_permit(capacity);
        let deadline = Instant::now() + self.options.query_timeout;
        if backend.parameter("client_encoding") != Some("UTF8") {
            return Err("MCP requires UTF8".into());
        }
        if self.route.pool.require_primary {
            backend
                .verify_primary_with_deadline(deadline)
                .map_err(|e| e.to_string())?;
        }
        let candidate = relation_projection(sql).filter(|_| self.principal.is_some());
        let identity = if candidate.is_some() {
            let reply = collect_rows(
                &mut backend,
                "SELECT s.system_identifier::text, c.timeline_id::text, pg_catalog.pg_postmaster_start_time()::text, pg_catalog.pg_is_in_recovery()::text FROM pg_catalog.pg_control_system() s CROSS JOIN pg_catalog.pg_control_checkpoint() c",
                1,
                8192,
                b'I',
                deadline,
            )?;
            if reply.error.is_none() {
                reply
                    .rows
                    .first()
                    .and_then(|row| row.get("values"))
                    .and_then(Value::as_array)
                    .filter(|v| v.len() == 4 && v[3] == "false")
                    .and_then(|v| {
                        Some((
                            v[0].as_str()?.to_owned(),
                            format!("{}/{}", v[1].as_str()?, v[2].as_str()?),
                        ))
                    })
            } else {
                None
            }
        } else {
            None
        };
        if let Some(context) = &self.context {
            command(
                &mut backend,
                &context
                    .session_commands()
                    .map_err(|e| e.to_string())?
                    .join(";"),
                b'I',
                deadline,
            )?;
        }
        let mut cache_probe = None;
        if let (Some(relation), Some((cluster, incarnation))) = (candidate, identity) {
            let metadata = format!(
                "SELECT c.oid::text, c.xmin::text, c.relfilenode::text, (c.relkind='r' AND c.relpersistence='p' AND NOT c.relrowsecurity AND NOT c.relforcerowsecurity AND NOT c.relhasrules AND NOT c.relispartition AND pg_catalog.has_table_privilege(c.oid,'SELECT') AND NOT EXISTS (SELECT FROM pg_catalog.pg_inherits i WHERE i.inhrelid=c.oid OR i.inhparent=c.oid) AND NOT EXISTS (SELECT FROM pg_catalog.pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped AND a.atttypid NOT IN (16,18,19,20,21,23,25,1042,1043,2950)))::text, pg_catalog.pg_current_snapshot()::text FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname={} AND c.relname={}",
                literal(&relation.schema),
                literal(&relation.table)
            );
            let eligible = collect_rows(&mut backend, &metadata, 1, 32768, b'I', deadline)?;
            if eligible.error.is_none()
                && eligible
                    .rows
                    .first()
                    .and_then(|row| row.get("values"))
                    .and_then(Value::as_array)
                    .is_some_and(|values| values.len() == 5 && values[3] == "true")
            {
                cache_probe = Some((relation, cluster, incarnation, metadata));
            }
        }
        let millis = self
            .remaining_time(deadline)?
            .as_millis()
            .clamp(1, u128::from(u32::MAX))
            .min(
                self.context
                    .as_ref()
                    .map_or(u128::MAX, |ctx| u128::from(ctx.statement_timeout_ms)),
            );
        let setup = format!(
            "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SET LOCAL statement_timeout = '{millis}'; SET LOCAL search_path = pg_catalog; SET LOCAL standard_conforming_strings = on"
        );
        command(&mut backend, &setup, b'T', deadline)?;
        let mut stamp = None;
        if let Some((relation, cluster, incarnation, metadata)) = cache_probe {
            let quoted = format!(
                "\"{}\".\"{}\"",
                relation.schema.replace('"', "\"\""),
                relation.table.replace('"', "\"\"")
            );
            // LOCK must precede the first snapshot-bearing SELECT. TRUNCATE is
            // not MVCC-safe; a pre-lock snapshot cannot prove unchanged contents.
            command(
                &mut backend,
                &format!("LOCK TABLE ONLY {quoted} IN ACCESS SHARE MODE"),
                b'T',
                deadline,
            )?;
            let proof = collect_rows(&mut backend, &metadata, 1, 32768, b'T', deadline)?;
            if proof.error.is_some() {
                return Err("cache snapshot validation failed".into());
            }
            if let Some(values) = proof
                .rows
                .first()
                .and_then(|row| row.get("values"))
                .and_then(Value::as_array)
                .filter(|values| values.len() == 5 && values[3] == "true")
            {
                stamp = Some(SnapshotStamp {
                    cluster,
                    incarnation,
                    snapshot: values[4].as_str().ok_or("invalid snapshot")?.to_owned(),
                    relation: serde_json::to_string(&values[..4]).map_err(|e| e.to_string())?,
                });
            }
        }
        let key = serde_json::to_string(&(
            &self.principal,
            &self.context,
            backend.user(),
            backend.database(),
            backend.backend_address().to_string(),
            sql,
            max_rows,
            max_bytes,
        ))
        .map_err(|e| e.to_string())?;
        let remaining_ms = self
            .remaining_time(deadline)?
            .as_millis()
            .clamp(1, u128::from(u32::MAX));
        command(
            &mut backend,
            &format!("SET LOCAL statement_timeout = '{remaining_ms}'"),
            b'T',
            deadline,
        )?;
        let rows = if let Some(stamp) = &stamp {
            if let Some(bytes) = self.cache.get(&key, stamp) {
                self.cache_hit = true;
                serde_json::from_slice(bytes).map_err(|_| "invalid cached result")?
            } else {
                let reply = collect_rows(&mut backend, sql, max_rows, max_bytes, b'T', deadline)?;
                if reply.error.is_some() {
                    return Err("PostgreSQL query failed".into());
                }
                reply.rows
            }
        } else {
            self.cache.bypass();
            let reply = collect_rows(&mut backend, sql, max_rows, max_bytes, b'T', deadline)?;
            if reply.error.is_some() {
                return Err("PostgreSQL query failed".into());
            }
            reply.rows
        };
        if !backend.generation_is_current() || !backend.credentials_are_current() {
            return Err("backend ownership expired".into());
        }
        command(&mut backend, "COMMIT", b'I', deadline)?;
        backend.terminate();
        if let Some(stamp) = stamp
            && !self.cache_hit
        {
            self.cache.insert(
                key,
                &stamp,
                serde_json::to_vec(&rows).map_err(|e| e.to_string())?,
            );
        }
        Ok(rows)
    }
    fn remaining_time(&self, deadline: Instant) -> Result<std::time::Duration, String> {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or("tool deadline")?;
        Ok(remaining.min(std::time::Duration::from_millis(
            self.context
                .as_ref()
                .map_or(u64::MAX, |context| u64::from(context.statement_timeout_ms)),
        )))
    }
}
impl Executor for PgExecutor {
    fn cache_hit(&self) -> bool {
        self.cache_hit
    }
    fn query(
        &mut self,
        sql: &str,
        max_rows: usize,
        max_bytes: usize,
    ) -> Result<Vec<Value>, String> {
        self.execute(sql, max_rows, max_bytes)
    }
    fn schema(
        &mut self,
        tables: &[String],
        denied_columns: &[String],
        max_rows: usize,
        max_bytes: usize,
    ) -> Result<Vec<Value>, String> {
        if tables.is_empty() {
            return Ok(Vec::new());
        }
        let names = tables
            .iter()
            .map(|s| literal(s))
            .collect::<Vec<_>>()
            .join(",");
        let denied = if denied_columns.is_empty() {
            String::new()
        } else {
            format!(
                " AND a.attname NOT IN ({})",
                denied_columns
                    .iter()
                    .map(|s| literal(s))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        };
        let sql = format!(
            "SELECT n.nspname AS schema_name, c.relname AS table_name, a.attname AS column_name, t.typname AS type_name FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace JOIN pg_catalog.pg_attribute a ON a.attrelid=c.oid JOIN pg_catalog.pg_type t ON t.oid=a.atttypid WHERE n.nspname || '.' || c.relname IN ({names}) AND a.attnum>0 AND NOT a.attisdropped{denied} ORDER BY n.nspname,c.relname,a.attnum LIMIT {}",
            max_rows.saturating_add(1)
        );
        self.execute(&sql, max_rows, max_bytes)
    }
}
struct DbReply {
    rows: Vec<Value>,
    error: Option<()>,
}
fn command(
    backend: &mut BackendConnection,
    sql: &str,
    status: u8,
    deadline: Instant,
) -> Result<(), String> {
    // Trusted context setup may contain one set_config SELECT as well as SETs.
    let reply = collect_rows(backend, sql, 1, 65536, status, deadline)?;
    if reply.error.is_some() {
        return Err("trusted backend setup failed".into());
    }
    Ok(())
}
fn collect_rows(
    backend: &mut BackendConnection,
    sql: &str,
    max_rows: usize,
    max_bytes: usize,
    status: u8,
    deadline: Instant,
) -> Result<DbReply, String> {
    if !backend.generation_is_current() || !backend.credentials_are_current() {
        return Err("backend ownership expired".into());
    }
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or("tool deadline")?;
    backend
        .set_write_timeout(Some(remaining))
        .map_err(|_| "tool timeout setup failed")?;
    let mut payload = sql.as_bytes().to_vec();
    payload.push(0);
    {
        let (_, writer) = backend.split();
        writer
            .write_message(b'Q', &payload)
            .and_then(|_| writer.flush())
            .map_err(|e| e.to_string())?;
    }
    let mut columns = Vec::new();
    let mut rows = Vec::new();
    let mut bytes_used = 2usize;
    let mut error = None;
    loop {
        let frame = backend
            .read_message_with_deadline(deadline)
            .map_err(|e| e.to_string())?
            .ok_or("backend closed")?;
        match frame.tag {
            b'T' => {
                if !columns.is_empty() {
                    return Err("multiple result sets refused".into());
                }
                columns = parse_columns(frame.payload)?;
            }
            b'D' => {
                if rows.len() >= max_rows {
                    return Err("row limit exceeded".into());
                }
                let values = parse_row(frame.payload, columns.len())?;
                let row = json!({"columns":columns,"values":values});
                bytes_used = bytes_used
                    .checked_add(serde_json::to_vec(&row).map_err(|e| e.to_string())?.len() + 1)
                    .ok_or("result size overflow")?;
                if bytes_used > max_bytes {
                    return Err("result byte limit exceeded".into());
                }
                rows.push(row);
            }
            b'E' => {
                error = Some(());
                rows.clear();
            }
            b'Z' => {
                if frame.payload != [status] && !(error.is_some() && frame.payload == [b'E']) {
                    return Err("unexpected transaction state".into());
                }
                let transaction_status = frame.payload[0];
                backend.set_transaction_status(transaction_status);
                break;
            }
            b'C' | b'N' | b'S' => {}
            _ => return Err("unsupported backend result".into()),
        }
    }
    Ok(DbReply { rows, error })
}
fn literal(value: &str) -> String {
    format!("E'{}'", value.replace('\\', "\\\\").replace('\'', "''"))
}
fn parse_columns(mut bytes: &[u8]) -> Result<Vec<String>, String> {
    let count = u16::from_be_bytes(take::<2>(&mut bytes)?) as usize;
    if count > bytes.len() / 19 {
        return Err("column count exceeds description size".into());
    }
    let mut columns = Vec::with_capacity(count);
    for _ in 0..count {
        let end = bytes
            .iter()
            .position(|b| *b == 0)
            .ok_or("column terminator missing")?;
        columns.push(
            std::str::from_utf8(&bytes[..end])
                .map_err(|_| "invalid column name")?
                .to_owned(),
        );
        bytes = &bytes[end + 1..];
        let metadata = take::<18>(&mut bytes)?;
        if metadata[16..] != [0, 0] {
            return Err("binary result refused".into());
        }
    }
    if !bytes.is_empty() {
        return Err("column description tail".into());
    }
    Ok(columns)
}
fn parse_row(mut bytes: &[u8], columns: usize) -> Result<Vec<Option<String>>, String> {
    let count = u16::from_be_bytes(take::<2>(&mut bytes)?) as usize;
    if count != columns {
        return Err("row shape mismatch".into());
    }
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        let len = i32::from_be_bytes(take::<4>(&mut bytes)?);
        if len == -1 {
            values.push(None);
            continue;
        }
        if len < 0 || len as usize > bytes.len() {
            return Err("invalid field length".into());
        }
        values.push(Some(
            std::str::from_utf8(&bytes[..len as usize])
                .map_err(|_| "invalid UTF8 field")?
                .to_owned(),
        ));
        bytes = &bytes[len as usize..];
    }
    if !bytes.is_empty() {
        return Err("row tail".into());
    }
    Ok(values)
}
fn take<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N], String> {
    if bytes.len() < N {
        return Err("short result".into());
    }
    let value = bytes[..N].try_into().unwrap();
    *bytes = &bytes[N..];
    Ok(value)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_rows_and_nulls() {
        assert_eq!(
            parse_row(&[0, 1, 255, 255, 255, 255], 1).unwrap(),
            vec![None]
        );
        assert!(parse_row(&[0, 1, 255, 255, 255, 254], 1).is_err());
        assert!(parse_row(&[0, 1, 0, 0, 0, 2, b'a'], 1).is_err());
        assert!(parse_row(&[0, 0, 0], 0).is_err());
    }
    #[test]
    fn metadata_and_literal_escape() {
        assert!(parse_columns(&[0, 1, b'x', 0]).is_err());
        assert!(parse_columns(&[255, 255]).is_err());
        assert_eq!(literal("x\\';SELECT 1;--"), "E'x\\\\'';SELECT 1;--'");
    }
    #[test]
    fn partial_backend_frame_cannot_extend_the_total_tool_deadline() {
        use pgproxy_wire::{BackendCredentials, BackendTarget};
        use std::{
            io::{Read, Write},
            net::TcpListener,
            thread,
            time::Duration,
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let peer = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut length = [0; 4];
            socket.read_exact(&mut length).unwrap();
            let mut startup = vec![0; u32::from_be_bytes(length) as usize - 4];
            socket.read_exact(&mut startup).unwrap();
            socket
                .write_all(b"R\0\0\0\x08\0\0\0\0Z\0\0\0\x05I")
                .unwrap();
            let mut header = [0; 5];
            socket.read_exact(&mut header).unwrap();
            let mut query =
                vec![0; u32::from_be_bytes(header[1..].try_into().unwrap()) as usize - 4];
            socket.read_exact(&mut query).unwrap();
            // Each byte arrives sooner than a per-read timeout; the overall
            // deadline must still stop this incomplete NoticeResponse.
            socket.write_all(b"N\0\0\0\x64").unwrap();
            for _ in 0..60 {
                thread::sleep(Duration::from_millis(25));
                if socket.write_all(b"x").is_err() {
                    break;
                }
            }
        });
        let mut backend = BackendConnection::connect(
            &BackendTarget {
                host: address.ip().to_string(),
                port: address.port(),
                database: Some("test".into()),
                user: None,
            },
            &BackendCredentials {
                user: "test".into(),
                password: None,
                database: None,
                application_name: None,
            },
            Duration::from_secs(2),
            65536,
        )
        .unwrap();
        let started = Instant::now();
        assert!(
            collect_rows(
                &mut backend,
                "SELECT 1",
                1,
                65536,
                b'I',
                started + Duration::from_millis(100)
            )
            .is_err()
        );
        assert!(started.elapsed() < Duration::from_millis(500));
        drop(backend);
        peer.join().unwrap();
    }
}
