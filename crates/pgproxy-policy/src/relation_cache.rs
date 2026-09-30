//! Relation-cache admission and transaction-visible snapshot validation.
//! The executor must acquire table locks and obtain these stamps in the SAME
//! repeatable-read transaction that validates privileges and returns the result.
use crate::resilience::ResultCache;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotStamp {
    pub cluster: String,
    pub incarnation: String,
    pub snapshot: String,
    pub relation: String,
}
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct CacheStatistics {
    pub hits: u64,
    pub misses: u64,
    pub invalidations: u64,
    pub bypasses: u64,
}
pub struct SnapshotResultCache {
    cache: ResultCache,
    stamp: Option<SnapshotStamp>,
    statistics: CacheStatistics,
}
impl SnapshotResultCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            cache: ResultCache::new(capacity),
            stamp: None,
            statistics: Default::default(),
        }
    }
    fn observe(&mut self, stamp: &SnapshotStamp) -> bool {
        if stamp.cluster.len() > 4096
            || stamp.incarnation.len() > 4096
            || stamp.snapshot.len() > 32768
            || stamp.relation.len() > 4096
            || stamp.cluster.is_empty()
            || stamp.snapshot.is_empty()
        {
            self.disconnect();
            return false;
        }
        if self.stamp.as_ref() != Some(stamp) {
            if self.stamp.is_some() {
                self.statistics.invalidations += 1;
            }
            self.cache.clear();
            self.cache.synchronize();
            self.stamp = Some(stamp.clone());
        }
        true
    }
    pub fn get(&mut self, key: &str, stamp: &SnapshotStamp) -> Option<&[u8]> {
        if !self.observe(stamp) {
            return None;
        }
        let value = self.cache.get(key, false);
        if value.is_some() {
            self.statistics.hits += 1;
        } else {
            self.statistics.misses += 1;
        }
        value
    }
    pub fn insert(&mut self, key: String, stamp: &SnapshotStamp, bytes: Vec<u8>) -> bool {
        self.observe(stamp)
            && self.cache.insert(
                key,
                bytes,
                Default::default(),
                Duration::from_secs(30),
                true,
            )
    }
    pub fn disconnect(&mut self) {
        self.cache.disconnect();
        self.stamp = None;
    }
    pub fn bypass(&mut self) {
        self.statistics.bypasses += 1;
    }
    pub fn statistics(&self) -> CacheStatistics {
        self.statistics
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelationProjection {
    pub schema: String,
    pub table: String,
}
/// Only projections from exactly one qualified relation. No hidden function,
/// operator, parameter, system-column or session-sensitive expression is cached.
pub fn relation_projection(sql: &str) -> Option<RelationProjection> {
    let parsed = pgproxy_parser::parse(sql, Default::default(), 65536, 4 * 1024 * 1024).ok()?;
    let statements: Vec<_> = parsed.statements().collect();
    if statements.len() != 1 {
        return None;
    }
    let select = statements[0].get("SelectStmt")?;
    if select.get("whereClause").is_some()
        || select.get("withClause").is_some()
        || select.get("intoClause").is_some()
        || select.get("lockingClause").is_some()
        || select.get("larg").is_some()
        || select.get("rarg").is_some()
        || select.get("sortClause").is_some()
        || select.get("limitCount").is_some()
        || select.get("limitOffset").is_some()
    {
        return None;
    }
    let from = select.get("fromClause")?.as_array()?;
    if from.len() != 1 {
        return None;
    }
    let range = from[0].get("RangeVar")?;
    let schema = range.get("schemaname")?.as_str()?.to_owned();
    let table = range.get("relname")?.as_str()?.to_owned();
    if schema.starts_with("pg_") || schema == "information_schema" {
        return None;
    }
    fn inspect(value: &Value) -> bool {
        match value {
            Value::Object(map) => map.iter().all(|(key, node)| {
                if key.chars().next().is_some_and(char::is_uppercase)
                    && !matches!(
                        key.as_str(),
                        "SelectStmt"
                            | "RangeVar"
                            | "Alias"
                            | "ResTarget"
                            | "ColumnRef"
                            | "String"
                            | "A_Star"
                            | "A_Const"
                            | "Integer"
                            | "Boolean"
                    )
                {
                    return false;
                }
                if key == "fval" {
                    return false;
                }
                if key == "ColumnRef"
                    && node
                        .get("fields")
                        .and_then(Value::as_array)
                        .is_some_and(|fields| {
                            fields.iter().any(|f| {
                                f.get("String")
                                    .and_then(|s| s.get("sval"))
                                    .and_then(Value::as_str)
                                    .is_some_and(|name| {
                                        matches!(
                                            name,
                                            "ctid" | "xmin" | "xmax" | "cmin" | "cmax" | "tableoid"
                                        )
                                    })
                            })
                        })
                {
                    return false;
                }
                inspect(node)
            }),
            Value::Array(values) => values.iter().all(inspect),
            _ => true,
        }
    }
    inspect(statements[0]).then_some(RelationProjection { schema, table })
}
#[cfg(test)]
mod tests {
    use super::*;
    fn stamp(snapshot: &str) -> SnapshotStamp {
        SnapshotStamp {
            cluster: "cluster1".into(),
            incarnation: "timeline1/start1".into(),
            snapshot: snapshot.into(),
            relation: "123/type1".into(),
        }
    }
    #[test]
    fn external_commits_rollbacks_ddl_and_restarts_invalidate() {
        let mut c = SnapshotResultCache::new(4096);
        let first = stamp("10:20:11");
        assert!(c.insert("sql+principal".into(), &first, vec![1]));
        assert_eq!(c.get("sql+principal", &first), Some([1].as_slice()));
        for next in [
            stamp("10:20:"),
            stamp("10:21:11"),
            SnapshotStamp {
                relation: "124/type2".into(),
                ..first.clone()
            },
            SnapshotStamp {
                incarnation: "timeline2/start2".into(),
                ..first.clone()
            },
        ] {
            assert!(c.get("sql+principal", &next).is_none());
            assert!(c.insert("sql+principal".into(), &next, vec![2]));
        }
        c.disconnect();
        assert!(c.get("sql+principal", &first).is_none());
    }
    #[test]
    fn volatile_and_hidden_dependencies_never_admitted() {
        assert!(relation_projection("SELECT id FROM public.a").is_some());
        assert!(relation_projection("SELECT a.* FROM public.a a").is_some());
        for sql in [
            "SELECT pg_catalog.random() FROM public.a",
            "SELECT current_user FROM public.a",
            "SELECT xmin FROM public.a",
            "SELECT id FROM pg_catalog.pg_class",
            "SELECT $1 FROM public.a",
            "SELECT * FROM public.a,public.b",
            "SELECT id FROM public.a ORDER BY id",
            "SELECT id FROM public.a LIMIT 1",
            "SELECT (SELECT id FROM public.a) FROM public.a",
            "SELECT id::text FROM public.a",
        ] {
            assert!(relation_projection(sql).is_none(), "{sql}");
        }
    }
}
