   Compiling pgquery-spike v0.0.0 (/work/harness)
warning: variable `bytes_total` is assigned to, but never used
   --> src/main.rs:245:9
    |
245 |     let mut bytes_total = 0usize;
    |         ^^^^^^^^^^^^^^^
    |
    = note: consider using `_bytes_total` instead
    = note: `#[warn(unused_variables)]` (part of `#[warn(unused)]`) on by default

warning: unused variable: `bs_no_bq`
   --> src/main.rs:352:9
    |
352 |     let bs_no_bq = fingerprint(BACKSLASH_SQL, DISABLE_BACKSLASH_QUOTE);
    |         ^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_bs_no_bq`

warning: value assigned to `bytes_total` is never read
   --> src/main.rs:261:9
    |
261 |         bytes_total += sql.len();
    |         ^^^^^^^^^^^^^^^^^^^^^^^^
    |
    = help: maybe it is overwritten before being read?
    = note: `#[warn(unused_assignments)]` (part of `#[warn(unused)]`) on by default

warning: function `pg_query_parse` is never used
  --> src/main.rs:55:8
   |
55 |     fn pg_query_parse(input: *const c_char) -> PgQueryParseResult;
   |        ^^^^^^^^^^^^^^
   |
   = note: `#[warn(dead_code)]` (part of `#[warn(unused)]`) on by default

warning: function `pg_query_fingerprint` is never used
  --> src/main.rs:58:8
   |
58 |     fn pg_query_fingerprint(input: *const c_char) -> PgQueryFingerprintResult;
   |        ^^^^^^^^^^^^^^^^^^^^

warning: `pgquery-spike` (bin "pgquery-spike") generated 5 warnings (run `cargo fix --bin "pgquery-spike" -p pgquery-spike` to apply 1 suggestion)
    Finished `release` profile [optimized] target(s) in 1.57s
     Running `target/release/pgquery-spike`
# Spike S3 — libpg_query measurement report

libpg_query commit: 7632d03
parser major version: 18
build: release, lto, codegen-units=1

## 1. Parse throughput by API shape

| statement | bytes | JSON tree (B) | JSON ns/op | JSON ops/s | protobuf ns/op | protobuf ops/s | speedup |
|---|---|---|---|---|---|---|---|
| pk_select | 41 | 637 | 2438 | 410107 | 8665 | 115409 | 0.28x |
| select_literal | 41 | 644 | 2486 | 402304 | 8730 | 114554 | 0.28x |
| oltp_update | 89 | 886 | 3446 | 290209 | 11899 | 84040 | 0.29x |
| join_agg | 160 | 1944 | 7222 | 138463 | 26184 | 38191 | 0.28x |
| insert_multi | 115 | 1137 | 4542 | 220183 | 15996 | 62516 | 0.28x |
| cte | 109 | 1368 | 4605 | 217159 | 15906 | 62871 | 0.29x |
| ddl_alter | 64 | 588 | 2001 | 499678 | 5328 | 187671 | 0.38x |
| plpgsql_do | 114 | 280 | 1032 | 968988 | 2272 | 440196 | 0.45x |
| wide_8kb | 6225 | 77761 | 334151 | 2993 | 1472480 | 679 | 0.23x |

Mean across corpus: JSON 40214 ns/op, protobuf 174162 ns/op (0.23x).

## 2. T0 fast path versus T2 full parse

| statement | bytes | hash ns/op | JSON parse ns/op | parse/hash |
|---|---|---|---|---|
| pk_select (small) | 41 | 18 | 2533 | **142x** |
| wide_8kb | 6225 | 6123 | 333044 | **54x** |

A T0 decision (hash the text, look it up) is one to two orders of magnitude cheaper than a
full parse. This is the quantitative case for the tiered design: a proxy that parses every
statement pays the right-hand column on every message, and for large statements that cost
is hundreds of microseconds.

## 3. Cheap classification without a full AST

`pg_query_is_utility_stmt`: BEGIN -> true, SELECT 1 -> false. Usable as a T1 signal, but it still runs the parser, so it is not a T0 replacement.

## 4. Fingerprint stability

| test | expected | result |
|---|---|---|
| literals differ, structure identical -> same fingerprint | yes | PASS |
| whitespace + case + comment differences -> same fingerprint | yes | PASS |
| inline comment -> same fingerprint | yes | PASS |

## 5. Parser options are part of the cache key (corroborates S2)

Query: `SELECT 'a\'b' AS s`

| parser options | parse result | fingerprint |
|---|---|---|
| default (standard_conforming_strings=on) | ERROR: unterminated bit string literal at or near "b' AS s" | ERROR: unterminated bit string literal at or near "b' AS s" |
| DISABLE_STANDARD_CONFORMING_STRINGS | ok | 0x50fde20626009aba |
| DISABLE_BACKSLASH_QUOTE | ERROR: unterminated bit string literal at or near "b' AS s" | ERROR: unterminated bit string literal at or near "b' AS s" |

Fingerprint changes when `standard_conforming_strings` changes: **yes**.
This is direct confirmation of the spike S2 finding: the parse-cache key must include the
session's parser-affecting GUCs, and libpg_query already exposes the switches for the two
that matter (`PG_QUERY_DISABLE_STANDARD_CONFORMING_STRINGS`, `PG_QUERY_DISABLE_BACKSLASH_QUOTE`).

## 6. FFI boundary under hostile input

Ran **7087** malformed/truncated/mutated inputs through `pg_query_parse_opts`.
- parsed without error: 5132
- returned a structured error: 1955
- crashes, panics or aborts: **0**

Every failure was reported through `PgQueryError`, never through a signal. No memory-safety
failure was observed in this pass. **This is a smoke test, not a fuzzing campaign** — a real
`cargo-fuzz` target over the same boundary is a Phase 0 deliverable (gate G5).

## 7. Version pinning

This build reports `PG_MAJORVERSION = 18`. libpg_query vendors a *specific* PostgreSQL
parser, so **a single libpg_query build cannot validate fingerprints produced by a different
server major**. The parser used to decide a policy must match the server's grammar, and
fingerprint values must not be assumed comparable across majors — which is exactly why
ADR-0002 requires a version tag in the fingerprint key.

