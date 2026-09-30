//! Operator-triggered server measurements. No query text, counter subtraction,
//! CPU estimates, or exclusive tenant assignment is performed.
use pgproxy_admin::usage::{ServerCostReport, ServerStatementCost};
use pgproxy_wire::{BackendConnection, ResolvedBackend, SessionOptions};
use serde_json::Value;
use std::time::Instant;
const MAX_ROWS: usize = 4096;
const MAX_BYTES: usize = 8 * 1024 * 1024;

pub fn collect_server_cost(
    route: &ResolvedBackend,
    options: &SessionOptions,
) -> Result<ServerCostReport, String> {
    let deadline = Instant::now() + route.connect_timeout + options.query_timeout;
    let permit = options
        .backend_capacity
        .acquire(route.connect_timeout)
        .map_err(|_| "server-cost capacity unavailable")?;
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or("server-cost deadline")?;
    let mut backend = route
        .connect_backend(remaining.min(route.connect_timeout), MAX_BYTES)
        .map_err(|_| "server-cost backend unavailable")?
        .with_capacity_permit(permit);
    backend.require_primary(route.pool.require_primary);
    backend
        .verify_primary_with_deadline(deadline)
        .map_err(|_| "server-cost backend role unavailable")?;
    let metadata = read_json(
        &mut backend,
        "SELECT pg_catalog.json_build_object('can_read_all',pg_catalog.pg_has_role(CURRENT_USER,'pg_read_all_stats','USAGE'),'cluster',s.system_identifier::text,'started',pg_catalog.pg_postmaster_start_time()::text,'collected',pg_catalog.clock_timestamp()::text,'major',pg_catalog.current_setting('server_version_num')::integer/10000,'database',pg_catalog.current_database(),'oid',(SELECT oid::bigint FROM pg_catalog.pg_database WHERE datname=pg_catalog.current_database()))::text FROM pg_catalog.pg_control_system() s",
        deadline,
    )?;
    let metadata = metadata.first().ok_or("server-cost metadata unavailable")?;
    if metadata["can_read_all"] != true {
        return Err(
            "server-cost collection requires pg_read_all_stats monitoring privileges".into(),
        );
    }
    let extensions = read_json(
        &mut backend,
        "SELECT pg_catalog.json_build_object('name',e.extname,'schema',n.nspname)::text FROM pg_catalog.pg_extension e JOIN pg_catalog.pg_namespace n ON n.oid=e.extnamespace WHERE e.extname IN ('pg_stat_statements','pg_stat_kcache')",
        deadline,
    )?;
    let schema = |name: &str| {
        extensions
            .iter()
            .find(|e| e["name"] == name)
            .and_then(|e| e["schema"].as_str())
    };
    let statements_schema = identifier(
        schema("pg_stat_statements").ok_or("pg_stat_statements extension is required")?,
    )?;
    let info = read_json(
        &mut backend,
        &format!(
            "SELECT pg_catalog.row_to_json(i)::text FROM {statements_schema}.pg_stat_statements_info i"
        ),
        deadline,
    )?;
    let info = info
        .first()
        .ok_or("server-cost reset metadata unavailable")?;
    let cpu_schema = schema("pg_stat_kcache").map(identifier).transpose()?;
    let (cpu_columns, cpu_join) = if let Some(schema) = &cpu_schema {
        (
            "'execution_user_cpu_seconds',k.exec_user_time,'execution_system_cpu_seconds',k.exec_system_time,",
            format!(
                " LEFT JOIN {schema}.pg_stat_kcache() k ON k.dbid=s.dbid AND k.userid=s.userid AND k.queryid=s.queryid AND k.top=s.toplevel"
            ),
        )
    } else {
        (
            "'execution_user_cpu_seconds',NULL,'execution_system_cpu_seconds',NULL,",
            String::new(),
        )
    };
    let sql = format!(
        "SELECT pg_catalog.json_build_object('database_oid',s.dbid::bigint,'role_oid',s.userid::bigint,'role',COALESCE(r.rolname::text,'<dropped>'),'query_id',s.queryid::text,'top_level',s.toplevel,'calls',s.calls,'statistics_since',pg_catalog.to_jsonb(s)->>'stats_since','rows',s.rows,'execution_ms',s.total_exec_time,'shared_blocks_hit',s.shared_blks_hit,'shared_blocks_read',s.shared_blks_read,'shared_blocks_dirtied',s.shared_blks_dirtied,'shared_blocks_written',s.shared_blks_written,'local_blocks_hit',s.local_blks_hit,'local_blocks_read',s.local_blks_read,'local_blocks_dirtied',s.local_blks_dirtied,'local_blocks_written',s.local_blks_written,'temp_blocks_read',s.temp_blks_read,'temp_blocks_written',s.temp_blks_written,'wal_bytes',s.wal_bytes::text,'wal_records',s.wal_records,'wal_full_page_images',s.wal_fpi,{cpu_columns}'reserved',NULL)::text FROM {statements_schema}.pg_stat_statements(false) s LEFT JOIN pg_catalog.pg_roles r ON r.oid=s.userid{cpu_join} WHERE s.dbid={} AND s.toplevel AND s.queryid IS NOT NULL ORDER BY s.userid,s.queryid LIMIT {}",
        metadata["oid"]
            .as_u64()
            .ok_or("invalid database identity")?,
        MAX_ROWS + 1
    );
    let rows = read_json(&mut backend, &sql, deadline)?;
    let mut statements = Vec::with_capacity(rows.len());
    for mut row in rows {
        row.as_object_mut()
            .ok_or("invalid server cost row")?
            .remove("reserved");
        let cost: ServerStatementCost =
            serde_json::from_value(row).map_err(|_| "invalid server cost counters")?;
        validate_cost(&cost)?;
        statements.push(cost);
    }
    backend.terminate();
    Ok(ServerCostReport {
        scope: "cumulative_database_role_query_aggregate",
        cluster_system_identifier: text(metadata, "cluster")?,
        postmaster_started_at: text(metadata, "started")?,
        collected_at: text(metadata, "collected")?,
        server_major: metadata["major"]
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .ok_or("invalid server version")?,
        database: text(metadata, "database")?,
        statistics_reset_at: text(info, "stats_reset")?,
        statement_evictions: info["dealloc"].as_u64().ok_or("invalid eviction counter")?,
        cpu_source: if cpu_schema.is_some() {
            "pg_stat_kcache_execution_rusage"
        } else {
            "unavailable_pg_stat_kcache_not_installed"
        },
        limitations: vec![
            "All activity under the same PostgreSQL role is aggregated, including outside proxy writers; no exclusive tenant or request allocation.",
            "Execution time is elapsed server time, never CPU time. CPU is optional measured user/system execution rusage from pg_stat_kcache.",
            "Only top-level statements are exported to avoid nested double counting. CPU extension accounting may omit parallel-worker CPU.",
            "Extension statistics are live cumulative counters, not an atomic snapshot. The report reset epoch covers global pg_stat_statements resets; per-entry statistics_since exposes targeted resets when supported (PostgreSQL17+), otherwise is null. pg_stat_kcache resets independently without an exported reset epoch. Eviction, failures and extension tracking settings affect completeness; no counter deltas are inferred.",
            "Query IDs are PostgreSQL-version-specific and are distinct from proxy parser fingerprints. WAL bytes measure statement WAL generation, not commit durability or exclusive physical storage growth.",
        ],
        statements,
    })
}
fn text(value: &Value, key: &str) -> Result<String, String> {
    value[key]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| "invalid server metadata".into())
}
fn identifier(name: &str) -> Result<String, String> {
    if name.is_empty() || name.len() > 63 || name.contains('\0') {
        return Err("invalid extension schema".into());
    }
    Ok(format!("\"{}\"", name.replace('"', "\"\"")))
}
fn validate_cost(cost: &ServerStatementCost) -> Result<(), String> {
    if !cost.wal_bytes.bytes().any(|b| b.is_ascii_digit())
        || !cost.execution_ms.is_finite()
        || cost.execution_ms < 0.0
        || [
            cost.execution_user_cpu_seconds,
            cost.execution_system_cpu_seconds,
        ]
        .into_iter()
        .flatten()
        .any(|n| !n.is_finite() || n < 0.0)
        || cost.wal_bytes.is_empty()
        || !cost
            .wal_bytes
            .bytes()
            .all(|b| b.is_ascii_digit() || b == b'.')
        || cost.wal_bytes.bytes().filter(|b| *b == b'.').count() > 1
    {
        return Err("invalid measured server counter".into());
    }
    Ok(())
}
fn read_json(
    backend: &mut BackendConnection,
    sql: &str,
    deadline: Instant,
) -> Result<Vec<Value>, String> {
    if !backend.credentials_are_current() || !backend.generation_is_current() {
        return Err("server-cost backend ownership expired".into());
    }
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or("server-cost deadline")?;
    backend
        .set_read_timeout(Some(remaining))
        .map_err(|_| "server-cost timeout unavailable")?;
    backend
        .set_write_timeout(Some(remaining))
        .map_err(|_| "server-cost timeout unavailable")?;
    let mut payload = sql.as_bytes().to_vec();
    payload.push(0);
    {
        let (_, writer) = backend.split();
        writer
            .write_message(b'Q', &payload)
            .and_then(|_| writer.flush())
            .map_err(|_| "server-cost request failed")?;
    }
    let mut rows = Vec::new();
    let mut bytes = 0usize;
    loop {
        if Instant::now() >= deadline {
            return Err("server-cost deadline".into());
        }
        let frame = backend
            .read_message_with_deadline(deadline)
            .map_err(|_| "server-cost response failed")?
            .ok_or("server-cost backend closed")?;
        match frame.tag {
            b'D' => {
                if rows.len() >= MAX_ROWS {
                    return Err("server-cost row limit exceeded".into());
                }
                bytes = bytes
                    .checked_add(frame.payload.len())
                    .ok_or("server-cost size overflow")?;
                if bytes > MAX_BYTES {
                    return Err("server-cost byte limit exceeded".into());
                }
                rows.push(parse_json_row(frame.payload)?);
            }
            b'E' => {
                return Err(
                    "server-cost query unavailable; verify extensions and monitoring privileges"
                        .into(),
                );
            }
            b'Z' => {
                if frame.payload != [b'I'] {
                    return Err("server-cost unexpected transaction".into());
                }
                backend.set_transaction_status(b'I');
                return Ok(rows);
            }
            b'T' | b'C' | b'N' | b'S' => {}
            _ => return Err("server-cost unsupported protocol".into()),
        }
    }
}
fn parse_json_row(bytes: &[u8]) -> Result<Value, String> {
    if bytes.len() < 6 || bytes[..2] != [0, 1] {
        return Err("invalid server-cost row".into());
    }
    let len = i32::from_be_bytes(bytes[2..6].try_into().unwrap());
    if len < 0 || len as usize != bytes.len() - 6 {
        return Err("invalid server-cost field".into());
    }
    serde_json::from_slice(&bytes[6..]).map_err(|_| "invalid server-cost JSON".into())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identifiers_and_payloads_are_bounded_and_escaped() {
        assert_eq!(identifier("x\"y").unwrap(), "\"x\"\"y\"");
        assert!(identifier("bad\0").is_err());
        assert!(parse_json_row(&[0, 1, 255, 255, 255, 255]).is_err());
        assert!(parse_json_row(&[0, 2, 0, 0, 0, 0]).is_err());
    }
    #[test]
    fn measured_cpu_double_precision_survives_export_exactly() {
        let value: Value = serde_json::from_str("0.22146700000000002").unwrap();
        let measured = value.as_f64().unwrap();
        assert_eq!(measured.to_bits(), 0.22146700000000002_f64.to_bits());
        let exported = serde_json::to_string(&measured).unwrap();
        assert_eq!(
            serde_json::from_str::<f64>(&exported).unwrap().to_bits(),
            measured.to_bits()
        );
    }
    #[test]
    fn cumulative_counters_preserve_wal_and_do_not_estimate_cpu() {
        let row = serde_json::json!({"database_oid":1,"role_oid":2,"role":"shared","query_id":"-9223372036854775808","top_level":true,"calls":3,"rows":4,"execution_ms":42.5,"shared_blocks_hit":1,"shared_blocks_read":0,"shared_blocks_dirtied":0,"shared_blocks_written":0,"local_blocks_hit":0,"local_blocks_read":0,"local_blocks_dirtied":0,"local_blocks_written":0,"temp_blocks_read":0,"temp_blocks_written":0,"wal_bytes":"18446744073709551616","wal_records":1,"wal_full_page_images":0,"execution_user_cpu_seconds":null,"execution_system_cpu_seconds":null});
        let mut cost: ServerStatementCost = serde_json::from_value(row).unwrap();
        validate_cost(&cost).unwrap();
        assert!(cost.execution_user_cpu_seconds.is_none());
        cost.execution_ms = f64::NAN;
        assert!(validate_cost(&cost).is_err());
    }
}
