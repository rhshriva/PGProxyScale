//! Pinned PostgreSQL grammar, versioned fingerprints, and a bounded per-principal cache.
#![allow(unsafe_code)] // Audited FFI is confined to this crate.
#![deny(clippy::undocumented_unsafe_blocks)]
use serde_json::Value;
use std::{
    collections::HashMap,
    ffi::{CStr, CString},
    os::raw::{c_char, c_int},
    sync::Arc,
};

pub const PARSER_VERSION: &str = "libpg-query-18.0.0/pg-18.4";
pub const DEFAULT_MAX_SQL_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ParseOptions {
    pub backend_major: u16,
    pub standard_conforming_strings: bool,
    pub backslash_quote: bool,
}
impl Default for ParseOptions {
    fn default() -> Self {
        Self {
            backend_major: 18,
            standard_conforming_strings: true,
            backslash_quote: true,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fingerprint {
    pub hash: u64,
    pub backend_major: u16,
    pub parser_version: &'static str,
}
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("SQL exceeds the {0}-byte parser limit")]
    TooLarge(usize),
    #[error("SQL contains a NUL byte")]
    InteriorNul,
    #[error("unsupported PostgreSQL major version {0}")]
    UnsupportedVersion(u16),
    #[error("{0}")]
    Syntax(String),
    #[error("parser returned an invalid tree")]
    InvalidTree,
    #[error("parse tree exceeds the {0}-byte cache budget")]
    Budget(usize),
}
#[repr(C)]
struct CError {
    message: *mut c_char,
    funcname: *mut c_char,
    filename: *mut c_char,
    lineno: c_int,
    cursorpos: c_int,
    context: *mut c_char,
}
#[repr(C)]
struct CParse {
    tree: *mut c_char,
    stderr: *mut c_char,
    error: *mut CError,
}
#[repr(C)]
struct CFingerprint {
    hash: u64,
    text: *mut c_char,
    stderr: *mut c_char,
    error: *mut CError,
}
unsafe extern "C" {
    fn pg_query_parse_opts(sql: *const c_char, options: c_int) -> CParse;
    fn pg_query_free_parse_result(result: CParse);
    fn pg_query_fingerprint_opts(sql: *const c_char, options: c_int) -> CFingerprint;
    fn pg_query_free_fingerprint_result(result: CFingerprint);
}
struct ParseOwner(Option<CParse>);
impl Drop for ParseOwner {
    fn drop(&mut self) {
        if let Some(result) = self.0.take() {
            // SAFETY: The result is owned by this guard and freed exactly once using its matching allocator.
            unsafe {
                pg_query_free_parse_result(result);
            }
        }
    }
}
struct FingerprintOwner(Option<CFingerprint>);
impl Drop for FingerprintOwner {
    fn drop(&mut self) {
        if let Some(result) = self.0.take() {
            // SAFETY: The result is owned by this guard and freed exactly once using its matching allocator.
            unsafe {
                pg_query_free_fingerprint_result(result);
            }
        }
    }
}
fn error_message(error: *mut CError) -> Option<String> {
    if error.is_null() {
        return None;
    }
    // SAFETY: Called only while the owning libpg_query result remains alive; its error and message pointers are library-owned valid C strings.
    unsafe {
        Some(if (*error).message.is_null() {
            "PostgreSQL parse failed".into()
        } else {
            CStr::from_ptr((*error).message)
                .to_string_lossy()
                .into_owned()
        })
    }
}

/// Rust-owned JSON tree. All public AST views borrow this owner; no C pointer escapes.
#[derive(Debug)]
pub struct ParsedQuery {
    tree: Value,
    pub fingerprint: Fingerprint,
    pub charged_bytes: usize,
}
impl ParsedQuery {
    pub fn statements(&self) -> impl Iterator<Item = &Value> {
        self.tree
            .get("stmts")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|raw| raw.get("stmt"))
    }
    pub fn tree(&self) -> &Value {
        &self.tree
    }
}
fn memory_charge(value: &Value) -> usize {
    std::mem::size_of::<Value>()
        + match value {
            Value::String(s) => s.capacity(),
            Value::Array(v) => {
                v.capacity() * std::mem::size_of::<Value>()
                    + v.iter().map(memory_charge).sum::<usize>()
            }
            Value::Object(m) => m
                .iter()
                .map(|(k, v)| k.capacity() + 128 + memory_charge(v))
                .sum(),
            _ => 0,
        }
}
pub fn parse(
    sql: &str,
    options: ParseOptions,
    max_sql_bytes: usize,
    max_tree_bytes: usize,
) -> Result<ParsedQuery, ParseError> {
    if sql.len() > max_sql_bytes {
        return Err(ParseError::TooLarge(max_sql_bytes));
    }
    if !(14..=18).contains(&options.backend_major) {
        return Err(ParseError::UnsupportedVersion(options.backend_major));
    }
    let input = CString::new(sql).map_err(|_| ParseError::InteriorNul)?;
    let flags = if options.standard_conforming_strings {
        0
    } else {
        32
    } | if options.backslash_quote { 0 } else { 16 };
    // SAFETY: input is NUL-terminated and alive for the call; flags match the pinned upstream API. The returned ownership is immediately guarded.
    let owner = ParseOwner(Some(unsafe { pg_query_parse_opts(input.as_ptr(), flags) }));
    let result = owner.0.as_ref().ok_or(ParseError::InvalidTree)?;
    if let Some(error) = error_message(result.error) {
        return Err(ParseError::Syntax(error));
    }
    if result.tree.is_null() {
        return Err(ParseError::InvalidTree);
    }
    // SAFETY: result.tree is a library-owned NUL-terminated string; owner remains alive until after deserialization.
    let json = unsafe { CStr::from_ptr(result.tree) }.to_bytes();
    if json.len() > max_tree_bytes {
        return Err(ParseError::Budget(max_tree_bytes));
    }
    let tree: Value = serde_json::from_slice(json).map_err(|_| ParseError::InvalidTree)?;
    let charged_bytes = memory_charge(&tree);
    if charged_bytes > max_tree_bytes {
        return Err(ParseError::Budget(max_tree_bytes));
    }
    // SAFETY: input/flags meet the same preconditions as parse; a matching guard frees the independent result.
    let fp_owner = FingerprintOwner(Some(unsafe {
        pg_query_fingerprint_opts(input.as_ptr(), flags)
    }));
    let fp = fp_owner.0.as_ref().ok_or(ParseError::InvalidTree)?;
    if let Some(error) = error_message(fp.error) {
        return Err(ParseError::Syntax(error));
    }
    Ok(ParsedQuery {
        tree,
        fingerprint: Fingerprint {
            hash: fp.hash,
            backend_major: options.backend_major,
            parser_version: PARSER_VERSION,
        },
        charged_bytes,
    })
}

#[derive(Hash, PartialEq, Eq)]
struct CacheKey {
    sql: String,
    options: ParseOptions,
}
struct Entry {
    query: Arc<ParsedQuery>,
    stamp: u64,
    charge: usize,
}
/// Own one instance per principal/session. Cache keys compare SQL bytes after hashing,
/// so a hash collision can never authorize or restore a different query.
pub struct ParseCache {
    entries: HashMap<CacheKey, Entry>,
    budget: usize,
    max_sql: usize,
    used: usize,
    stamp: u64,
    hits: u64,
    misses: u64,
}
impl ParseCache {
    pub fn new(budget: usize, max_sql: usize) -> Self {
        Self {
            entries: HashMap::new(),
            budget,
            max_sql,
            used: 0,
            stamp: 0,
            hits: 0,
            misses: 0,
        }
    }
    pub fn parse(
        &mut self,
        sql: &str,
        options: ParseOptions,
    ) -> Result<Arc<ParsedQuery>, ParseError> {
        if sql.len() > self.max_sql {
            return Err(ParseError::TooLarge(self.max_sql));
        }
        let key = CacheKey {
            sql: sql.into(),
            options,
        };
        self.stamp = self.stamp.wrapping_add(1);
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.stamp = self.stamp;
            self.hits += 1;
            return Ok(Arc::clone(&entry.query));
        }
        self.misses += 1;
        let query = Arc::new(parse(sql, options, self.max_sql, self.budget)?);
        let charge = query.charged_bytes + key.sql.capacity() + 256;
        if charge > self.budget {
            return Err(ParseError::Budget(self.budget));
        }
        while self.used + charge > self.budget {
            let oldest = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.stamp)
                .map(|(key, _)| CacheKey {
                    sql: key.sql.clone(),
                    options: key.options,
                });
            if let Some(oldest) = oldest
                && let Some(entry) = self.entries.remove(&oldest)
            {
                self.used -= entry.charge;
            } else {
                break;
            }
        }
        self.used += charge;
        self.entries.insert(
            key,
            Entry {
                query: Arc::clone(&query),
                stamp: self.stamp,
                charge,
            },
        );
        Ok(query)
    }
    pub fn used_bytes(&self) -> usize {
        self.used
    }
    pub fn hits(&self) -> u64 {
        self.hits
    }
    pub fn misses(&self) -> u64 {
        self.misses
    }
}
/// Routing-only decisions do not need SQL or an AST at all.
#[derive(Debug, PartialEq, Eq)]
pub enum ParseTier {
    TransactionStatus,
    Cached,
    Full,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn postgres_grammar_and_literal_normalized_fingerprint() {
        let a = parse("SELECT 1", ParseOptions::default(), 1024, 65536).unwrap();
        let b = parse("select 2", ParseOptions::default(), 1024, 65536).unwrap();
        assert_eq!(a.fingerprint, b.fingerprint);
        assert!(a.statements().next().unwrap().get("SelectStmt").is_some());
        assert!(parse("SELECT FROM", ParseOptions::default(), 1024, 65536).is_err());
    }
    #[test]
    fn hostile_inputs_and_versions_are_bounded() {
        assert!(matches!(
            parse("a\0b", ParseOptions::default(), 10, 1024),
            Err(ParseError::InteriorNul)
        ));
        assert!(matches!(
            parse(&"x".repeat(11), ParseOptions::default(), 10, 1024),
            Err(ParseError::TooLarge(10))
        ));
        assert!(matches!(
            parse(
                "SELECT 1",
                ParseOptions {
                    backend_major: 19,
                    ..Default::default()
                },
                1024,
                65536
            ),
            Err(ParseError::UnsupportedVersion(19))
        ));
        assert!(matches!(
            parse("SELECT 1", ParseOptions::default(), 1024, 1),
            Err(ParseError::Budget(1))
        ));
    }
    #[test]
    fn cache_is_bounded_and_parser_settings_are_part_of_identity() {
        let mut cache = ParseCache::new(18000, 1024);
        let a = cache.parse("SELECT 1", ParseOptions::default()).unwrap();
        assert!(Arc::ptr_eq(
            &a,
            &cache.parse("SELECT 1", ParseOptions::default()).unwrap()
        ));
        assert_eq!(cache.hits(), 1);
        let b = cache
            .parse(
                "SELECT 1",
                ParseOptions {
                    standard_conforming_strings: false,
                    ..Default::default()
                },
            )
            .unwrap();
        assert!(!Arc::ptr_eq(&a, &b));
        for i in 0..100 {
            cache
                .parse(&format!("SELECT {i}"), ParseOptions::default())
                .unwrap();
            assert!(cache.used_bytes() <= 18000);
        }
        assert!(cache.misses() > 1);
    }
    #[test]
    fn parallel_ffi_calls_keep_ownership_independent() {
        let threads: Vec<_> = (0..8)
            .map(|_| {
                std::thread::spawn(|| {
                    for _ in 0..100 {
                        assert!(
                            parse(
                                "WITH t AS (SELECT 1) SELECT * FROM t",
                                ParseOptions::default(),
                                1024,
                                65536
                            )
                            .is_ok()
                        );
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
    }
}
