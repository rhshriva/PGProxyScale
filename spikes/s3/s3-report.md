# Spike S3 — libpg_query measurement report

libpg_query commit: (unset)
parser major version: (unset)
build: release, lto, codegen-units=1

## 1. Parse throughput by API shape

| statement | bytes | JSON tree (B) | JSON ns/op | JSON ops/s | protobuf ns/op | protobuf ops/s | speedup |
|---|---|---|---|---|---|---|---|
| pk_select | 41 | 637 | 2217 | 451119 | 8573 | 116647 | 0.26x |
| select_literal | 41 | 644 | 2207 | 453093 | 8515 | 117442 | 0.26x |
| oltp_update | 89 | 886 | 3297 | 303278 | 12140 | 82372 | 0.27x |
| join_agg | 160 | 1944 | 6750 | 148140 | 25936 | 38556 | 0.26x |
| insert_multi | 115 | 1137 | 4199 | 238169 | 15981 | 62576 | 0.26x |
| cte | 109 | 1368 | 4691 | 213173 | 16280 | 61426 | 0.29x |
| ddl_alter | 64 | 588 | 1916 | 522023 | 5226 | 191340 | 0.37x |
| plpgsql_do | 114 | 280 | 991 | 1008988 | 2272 | 440140 | 0.44x |
| wide_8kb | 6225 | 77761 | 300830 | 3324 | 1389390 | 720 | 0.22x |

Mean across corpus: JSON 36344 ns/op, protobuf 164924 ns/op (0.22x).

## 2. T0 fast path versus T2 full parse

| statement | bytes | hash ns/op | JSON parse ns/op | parse/hash |
|---|---|---|---|---|
| pk_select (small) | 41 | 16 | 2257 | **144x** |
| wide_8kb | 6225 | 5574 | 308127 | **55x** |

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

