# Spike Findings

Outcomes of the Phase 0 risk spikes (see [`phase-0-foundations.md`](phase-0-foundations.md) §W0).
Each spike exists to kill an assumption cheaply, and each result is recorded whether or not it was
the expected one.

| Spike | Question | Status |
|---|---|---|
| S1 | Can a Rust proxy match PgBouncer at low concurrency, with a bypass path? | *in progress* |
| S2 | What exactly is PostgreSQL session state, and what can be virtualised? | **done** — see below |
| S3 | Is `libpg_query` fast and stable enough, and how should we bind it? | **done** — see below |

---

## S2 — Session-state taxonomy

**Outcome: the central design assumption is confirmed, and the case is stronger than expected.**

Full deliverable: [`../architecture/session-state-taxonomy.md`](../architecture/session-state-taxonomy.md).
Raw data: `spikes/s2/`.

Headline numbers, extracted from the PostgreSQL source for PG 14–18:

| | PG14 | PG18 |
|---|---|---|
| Total GUCs | 357 | **406** |
| Client-settable (`PGC_USERSET`) | — | **154** |
| **Reported to the client (`GUC_REPORT`)** | 13 | **15** |
| **Client-settable *and* reported** | 9 | **10** |

**144 of 154 client-settable GUCs are never reported to any client by any PostgreSQL version.**
This is the quantified proof that `track_extra_parameters` — the only passive channel a pooler has —
is structurally incapable of tracking session state, not merely incomplete.

Two findings that change downstream design:

1. **`search_path` only became reportable in PostgreSQL 18.** On PG 14–17 there is no protocol
   mechanism for a pooler to observe it at all. This is the precise mechanism behind the documented
   cross-tenant schema leak. Our design does not use that channel, which is why it is correct on
   every version rather than only on 18+.
2. **63 of the 154 client-settable GUCs are planner-relevant**, and **9 are parser-affecting**.
   A prepared-statement cache key must include the first group, and the proxy's *own parser* must
   mirror the second. This converts two vague risks into concrete, testable requirements.

---

## S3 — `libpg_query` viability

**Outcome: viable, but ADR-0002's binding recommendation was wrong and is corrected.**

Harness: `spikes/s3/harness/` · raw report: `spikes/s3/s3-report.md` ·
libpg_query commit `7632d03`, PG major 18, release + LTO, in a `rust:1-slim-bookworm` container.

### 1. Parse throughput (the surprise)

| statement | bytes | JSON ns/op | protobuf ns/op | protobuf vs JSON |
|---|---|---|---|---|
| `pk_select` | 41 | 2,194 | 8,631 | **3.9× slower** |
| `oltp_update` | 89 | 3,089 | 11,636 | 3.8× slower |
| `join_agg` | 160 | 6,743 | 26,159 | 3.9× slower |
| `plpgsql_do` | 114 | 963 | 2,226 | 2.3× slower |
| `wide_8kb` | 6,225 | 311,030 | 1,415,299 | **4.6× slower** |

**Protobuf is 2–5× *slower* than JSON, not faster.** This contradicted the premise in ADR-0002, so it
was verified in the source rather than taken on faith:

- `pg_query_parse_opts` → `pg_query_raw_parse` → `pg_query_nodes_to_json` — a hand-written JSON writer.
- `pg_query_parse_protobuf_opts` → `pg_query_raw_parse` → `pg_query_nodes_to_protobuf` — protobuf-c.

Both parse the same tree; they differ only in the serialiser, and protobuf-c loses badly.
The correct reading of PgDog's "replacing protobuf with Rust to go 5× faster" is that they stopped
serialising **at all**, not that they switched serialisation formats.

**Neither public API is the destination.** Both materialise a serialised copy of the tree. The fast
path is to walk the raw C `RawStmt`/`Node` tree in place — and **that tree is deliberately not in
`pg_query.h`**, which is exactly why PgDog wrote a separate crate (`pg_raw_parse`) to reach it.

**Decision recorded in ADR-0002:** bind the **JSON** API for Phase 0 (it is the best available public
API, ~4× better than protobuf), always behind the fingerprint-keyed cache, and treat a raw-tree
accessor as a measured optimisation rather than a prerequisite. Do not use protobuf.

### 2. The tiered design is quantitatively justified

| statement | bytes | T0 hash ns/op | T2 parse ns/op | parse ÷ hash |
|---|---|---|---|---|
| `pk_select` | 41 | 18 | 2,533 | **142×** |
| `wide_8kb` | 6,225 | 6,123 | 333,044 | **54×** |

A T0 decision costs tens of nanoseconds; a full parse costs microseconds to *hundreds of*
microseconds. At 50k queries/s, parsing every small statement would consume roughly 11% of a core,
and a single 8 KB statement costs 333 µs — which is why "parse once per unique statement, keyed by
hash" is an architectural requirement rather than an optimisation.

### 3. Fingerprint stability — 3/3 pass

| Test | Result |
|---|---|
| Different literals, identical structure → same fingerprint | **PASS** |
| Whitespace / case / inline comment differences → same fingerprint | **PASS** |
| Commented vs plain query → same fingerprint | **PASS** |

Fingerprints are fit to key a cache, a statement registry and a chargeback ledger.

### 4. Parser options change the result — independent corroboration of S2

Query: `SELECT 'a\'b' AS s`

| parser options | parse | fingerprint |
|---|---|---|
| default (`standard_conforming_strings=on`) | **ERROR** | **ERROR** |
| `DISABLE_STANDARD_CONFORMING_STRINGS` | ok | `0x50fde20626009aba` |
| `DISABLE_BACKSLASH_QUOTE` | **ERROR** | **ERROR** |

The same bytes are a syntax error or a valid statement depending on a session GUC — and
`libpg_query` exposes exactly the switches for the two that matter. This closes the loop with S2:
**the parse cache key must include the session's parser-affecting GUCs**, and the capability is
already available in the library we intend to use. A parser that ignores them is both wrong and, in
Phase 2, a policy bypass.

### 5. FFI boundary smoke test

7,087 malformed, truncated and byte-mutated inputs through `pg_query_parse_opts`:
5,132 parsed, 1,955 returned a structured `PgQueryError`, **0 crashes, panics or aborts**.
Every failure came back through the error struct, never a signal.

This is a smoke test, not a fuzzing campaign. A sustained `cargo-fuzz` target remains Phase 0 gate G5.

### 6. Version pinning is mandatory

The build reports `PG_MAJORVERSION = 18`. A single libpg_query build vendors a single PostgreSQL
grammar, so fingerprints are **not** comparable across server majors, and a PG14 server's syntax must
be parsed by a PG14 grammar. This confirms ADR-0002's requirement for a version tag in the
fingerprint key, and adds a build-matrix requirement: **one libpg_query build per supported server
major**, selected at runtime.

---

## S1 — Runtime and data-path overhead

*In progress.*
