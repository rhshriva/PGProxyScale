# Roadmap — What to Build First, and Why

**Status:** proposed, awaiting decision on open questions (§8)
**Scope:** all features target vanilla PostgreSQL 14–18 first (see §7).

---

## 1. The answer up front

**Build the Session-State Ledger before anything else.**

Of the twelve innovation areas in the research, four things could plausibly be "first:"

| Candidate | Why it might be first | Why it is not first |
|---|---|---|
| **Session-State Ledger** | Substrate for 6 of the 12 top pain points; unlocks prepared statements, DDL-safe migrations, `LISTEN`, advisory locks, temp tables, cursors, `SET`/`search_path` | None serious — see §2 |
| Policy engine | Most urgent market need (CVE-2026-85620); highest revenue | **Depends on the ledger.** Per-statement `SET LOCAL role`, RLS context and masking *is* session-state injection. Building it first means building the ledger first anyway. |
| Data-path performance | Table stakes | Necessary but not differentiating. Do it in Phase 0 as a *gate*, not as a phase. |
| Sharding | Biggest headline | Hardest correctness problem, provably constrained (FLP, blocking 2PC), and two funded teams (PgDog, Multigres) already fight there. Last, and only on customer pull. |

**Ordering principle** — each phase is ranked by:

1. **Dependency depth** — how much later work it unblocks.
2. **Risk retirement** — the scariest unknowns get spiked earliest.
3. **Adoption vs monetisation** — the drop-in win comes before the trust-based sale.
4. **Measurable claim** — every phase must end with a sentence you can put on a website and defend with a benchmark.

---

## 2. Why the Session-State Ledger wins

**It is the shared substrate.** Prepared statements (named *and* anonymous), DDL-safe plan invalidation, `SET`/`search_path`/`SET ROLE` replay, temp tables, cursors, `LISTEN`/`NOTIFY` fan-out and advisory-lock leases are all the same primitive: a per-client record of what was asked of the session, that the proxy can replay, dedupe and undo. The pain-point research and the internals research reached this conclusion independently.

**It makes the policy engine correct.** Enforcing a per-statement role, RLS context or `search_path` for a tenant is literally "inject session state onto the checked-out backend, then restore it." Phase 1 *is* the policy engine's execution engine. Phase 2 adds the decision layer (capabilities, AST rules, masking) on top.

**It is the adoption wedge.** Replacing PgBouncer with something that stops breaking stateful applications requires **zero change to customer code or behaviour**. A policy engine requires the customer to put a new component in their authentication and authorization path — a trust decision you earn by first being the pooler that doesn't corrupt sessions.

**It is objectively measurable.** "Pinning ratio 0" and "migrations run through the pooler with no drain" are claims no competitor can make and any evaluator can verify.

**The counter-argument, answered.** The security need is more urgent. True — but the delay is small, because Phase 2 reuses roughly 70% of Phase 1's machinery. Building policy first would mean building the ledger first under time pressure, badly.

---

## 3. Phases

### Phase 0 — Foundations and the correctness spine

**Goal:** a proxy that is *correct* on the full driver matrix and *not embarrassing* on latency, with the measurement harness already in place.

Nothing here is a differentiator. All of it is a prerequisite, and the harness is what stops every later phase from being self-assessed.

**Deliverables**
- Rust workspace, config loading, logging, admin/metrics skeleton, CI.
- **`pgproxy-wire`** — protocol v3 startup and 3.2 negotiation; auth (trust, MD5, SCRAM-SHA-256, cert); extended-protocol state machine (`Parse`/`Bind`/`Describe`/`Execute`/`Sync`/`Flush`/`Close`); simple query; `COPY` framing passthrough; `CancelRequest` routing; completion counted by `ReadyForQuery` (not `CommandComplete`); error→`Sync` skip semantics; pipelining within `Sync`-delimited batches.
- **`pgproxy-parser`** — `libpg_query` FFI, fingerprinting, hash-keyed parse cache, and a "do I even need to parse?" fast path that skips SQL entirely when routing needs only the status byte.
- **`pgproxy-pool`** — transaction pooling with per-core pools, health checks, timeouts, LIFO/round-robin/replica selection.
- **Conformance harness** — drivers (psycopg3, asyncpg, pgjdbc, node-postgres, pgx, npgsql, Rails/ActiveRecord) × PostgreSQL 14–18, in Docker.
- **Hard-case benchmark suite** — the thing nobody has published: prepared statements, DDL-during-traffic, mixed OLTP + analytics, agent-style N+1, `LISTEN` under load, advisory-lock contention, and a failover drill.

**Exit gates**
- Zero conformance failures across the driver × version matrix.
- p50 latency overhead ≤ PgBouncer at 4 clients; ≥ 2× PgBouncer TPS at ≥ 64 clients.
- Parsing adds < 2% CPU on a pgbench simple-protocol run (fast path working).
- Benchmark suite reproduces on a documented Hetzner-class box.

**Risk spikes resolved:** S1 (can Rust reach low-concurrency parity?), S3 (is `libpg_query` fast enough?).

---

### Phase 1 — Session-State Ledger  ← *first differentiator*

**Goal:** transaction pooling that does not break stateful applications, and schema migrations that do not require draining the pooler.

**Deliverables**
- Session-image model: capture what the client *asked for* (never rely on server-reported `ParameterStatus`, which is the wall PgBouncer hits with `track_extra_parameters`).
- Batched, pipelined restore on checkout — one round trip, not one per GUC.
- **Prepared-statement registry**: named *and* anonymous `Parse`; fingerprint-keyed; `Close`/`DEALLOCATE`/`DISCARD ALL` handled correctly; SQL-level `PREPARE`/`EXECUTE`/`DEALLOCATE` tracked (PgBouncer forwards these blind).
- **Plan-invalidation protocol**: DDL event stream synthesised from (i) the wire stream we uniquely see in full, (ii) server-side `ddl_command_end` event triggers, (iii) catalog-fingerprint polling as the out-of-band fail-safe — because **logical decoding does not carry DDL**.
- **Advisory-lock lease manager**: virtualised `pg_advisory_lock` with heartbeats and re-acquisition, **routed by lock key** so contenders land on the same backend. Nobody does this today; everyone pins, rejects or leaks.
- **`LISTEN`/`NOTIFY` fan-out**: few long-lived server listeners, many multiplexed subscribers, **exactly-once** delivery bound to the client's transaction (beating PgDog's opt-in, at-most-once implementation).
- **Temp tables**: per-client schema namespacing where possible; otherwise *minimal* pinning with an eviction-cost model — pin only while the state exists.
- **Cursors**: `DECLARE`/`FETCH`/`CLOSE` support (the Django `queryset.iterator()` case that currently forces people to disable a feature).
- **Fail-closed semantics**: if a statement uses state we cannot virtualise, return a specific, actionable error. Never hand a client a dirty session (`pgagroal`'s silent leak is the anti-pattern).
- Diagnostics: a queryable view of exactly what is virtualised, pinned, or refused, per client.

**Exit gates**
- Pinning ratio **0** on a stateful workload suite (Prisma/`SET`-heavy, temp-table-using, `LISTEN`-using, advisory-lock-using).
- A schema migration (`ALTER TABLE … ADD COLUMN`) executed during live traffic produces **zero** `cached plan must not change result type` errors and zero drains.
- `LISTEN` delivery is exactly-once under fault injection (backend kill, proxy restart).
- Advisory-lock leader election survives backend switches without split-brain.

---

### Phase 2 — Policy Engine  ← *first revenue*

**Goal:** make policy enforcement impossible to bypass, on the wire.

**Deliverables**
- Principal model: database user, tenant, and agent as distinct identities.
- Credential vending: IAM, Vault dynamic roles, PostgreSQL 18 `OAUTHBEARER`, and RFC 8693 token exchange for per-agent audience-bound credentials (agents today get long-lived DSNs that leak through MCP client configs and chat history).
- Capability model (`read:<table>`, `write:<table>`, `ddl`, `copy`, `filesystem`, `extension`) with **deny-by-default** enforcement on AST semantics — covering `FROM`-clause functions, CTEs, `DO` blocks, dynamic SQL in PL/pgSQL, `COPY … FROM PROGRAM`, `lo_import`, `dblink`, `postgres_fdw`.
- Per-statement injection via the Phase 1 ledger: `SET LOCAL role`, RLS context, `statement_timeout`, read-only mode.
- Column masking and PII rules.
- Policy as code: parse, validate, dry-run, diff, canary.
- Audit stream: principal, policy decision, statement fingerprint, rows, cost, trace id.
- Simple-query-protocol enforcement too (PgBouncer's `disable_pqexec` is all-or-nothing).

**Exit gates**
- A published bypass corpus passes, explicitly including the CVE-2026-85620 class (`SELECT * FROM pg_read_file('/etc/passwd')`, `FuncCall` vs `RangeFunction`) and dynamic-SQL escape attempts.
- Policy evaluation adds < 0.1 ms p99 on the fast path, and is skipped entirely for statements that cannot violate it.
- Independent security review completed before any production claim.

---

### Phase 3 — Fairness, admission control, attribution

**Goal:** one tenant or agent cannot degrade another, and every query has a price.

**Deliverables**
- Per-principal token buckets, weighted fair queueing (max-min fair, as Multigres argued for), priority classes: interactive ≫ batch ≫ analytics ≫ migration.
- Adaptive concurrency limits from Little's Law on observed latency with Vegas/Gradient2-style control, replacing static `default_pool_size`.
- Google-SRE overload discipline: per-customer quotas, criticality classes (sheddable vs critical), bounded retry budgets, typed retryable shedding errors.
- Chargeback-grade attribution from a fingerprint→`queryid` map so it works **without** `pg_read_all_stats`: per-principal CPU time, rows read, buffers, WAL bytes, result bytes.
- Pool arithmetic: compute and enforce the safe total across direct + pooled + admin backends against `max_connections` (a chore Supabase's own docs leave to the user).

**Exit gates**
- Noisy-neighbour containment test: a saturating tenant cannot move another's p99 by more than a documented bound.
- Chargeback report reconciles with server-side `pg_stat_statements` within a stated tolerance.

---

### Phase 4 — Agent-native access (MCP)

**Goal:** ride the fastest-growing traffic source with a safety story no incumbent can tell.

Depends on Phase 2; it is mostly a thin protocol adapter, which is why it is high value per unit of work.

**Deliverables**
- MCP termination at the proxy, exposing safe tools (`query`, `describe_schema`, `explain`) backed by the **same** policy engine as wire clients — one policy, two protocols. Nobody has this.
- Per-agent scopes, budgets, rate limits, and schema-context filtering (the model must not be able to infer tables the agent cannot read).
- Guardrails against agent pathologies: query floods, N+1 loops, runaway analytics, accidental full-table scans (`statement_timeout`, row ceilings, cost-based admission).
- Defences against the known agent attack classes: tool poisoning, rug-pull description mutation, cross-server shadowing, indirect prompt injection through data, text-to-SQL backdoors (ToxicSQL).
- Semantic result caching for repeated LLM-generated SQL (fingerprint-normalised).

**Exit gates**
- An agent cannot exceed its scope or budget under adversarial prompting; publish a red-team report.

---

### Phase 5 — Resilience and caching

**Goal:** survive infrastructure events without dropping work; cache without lying.

**Deliverables**
- Zero-dropped-work planned switchover: quiesce → drain in-flight transactions → promote → resume, with no client-visible errors. Today's best measured planned switchover still leaks ~200 ms of real errors.
- Never hand out a connection to a demoted primary (PgBouncer currently does, until first use fails).
- Idempotency-key write replay with proxy-side dedupe; auto-retry for read-only and idempotent transactions.
- Live certificate rotation and config hot-swap with no connection recycling (PgBouncer recycles TLS connections on TLS config change).
- Read-your-writes: LSN-tagged sessions, replica admission only when replay has caught up, per-query consistency levels, delegating to PostgreSQL 19's `WAIT FOR` where available.
- Snapshot-correct caching: dependency-tracked invalidation via logical decoding, volatility refusal, never serving a cached read inside a transaction that has already written, and DDL invalidation from Phase 1.

**Exit gates**
- Zero client errors on planned switchover, verified by a repeatable drill.
- Cache correctness under concurrent DML + DDL, with a falsification test that tries to produce a stale read.

---

### Phase 6 — Sharding (optional, gated)

Only if customers pull hard. Requires a cross-shard query engine, 2PC or saga semantics, and online resharding — the hardest correctness problem in the space, contested by a funded team shipping weekly. Do not start this to have a feature; start it because a customer is paying for it.

---

## 4. Phase summary

| Phase | Innovation | Type | Primary claim at exit |
|---|---|---|---|
| 0 | Foundation + harness | Prerequisite | "Correct on every driver; competitive on latency" |
| 1 | **Session-State Ledger** | Differentiator | "Stateful apps and DDL migrations work in transaction mode, with zero pinning" |
| 2 | **Policy Engine** | Revenue | "Policy enforcement that cannot be bypassed" |
| 3 | Fairness + attribution | Enterprise value | "Noisy neighbours contained; every query priced" |
| 4 | Agent/MCP termination | Growth | "Safe agent access to Postgres, one policy for both protocols" |
| 5 | Resilience + caching | Retention | "Zero dropped work, honest caches" |
| 6 | Sharding | Optional | — |

---

## 5. Risk register and spikes

| # | Risk | Spike (do during) | Kill/continue criterion |
|---|---|---|---|
| S1 | Rust cannot match libevent's low-concurrency latency | Phase 0 | If we cannot get within 10% of PgBouncer at 4 clients after the bypass path, revisit the runtime (not the language). |
| S2 | Session-state virtualisation is wrong for `search_path`, `SET ROLE`, RLS, PL/pgSQL dynamic SQL | Phase 0 → 1 | Enumerate the full taxonomy of Postgres session state from the source tree *before* coding. If any class cannot be virtualised safely, it must be detected and refused — never guessed. |
| S3 | `libpg_query` is too slow, or its C surface is a liability | Phase 0 | Measure parse throughput and fuzz the FFI. If parsing cannot be skipped on the fast path, redesign the routing decision. |
| S4 | DDL cannot be detected reliably (logical decoding does not carry it) | Phase 1 | Measure end-to-end DDL detection latency from wire + event trigger + catalog polling. If it exceeds ~100 ms, plan invalidation is not viable and the feature must degrade to "reconnect on demand". |
| S5 | WASM plugin overhead | Phase 5+ | Only if we ship plugins. |

---

## 6. Explicit non-goals

- Sharding before it is paid for.
- A control-plane UI before the data plane is trustworthy.
- Multi-cloud and every driver's prepared-statement quirk in v1 (Cloudflare Hyperdrive's "named statements in two drivers only" is a mistake to learn from, not repeat — but parity with *common* drivers comes first).
- Our own storage engine. We keep PostgreSQL; we do not replace it. That is the lesson from CockroachDB/Yugabyte trade-offs and the reason a proxy is the right shape.
- A MySQL proxy.
- Caching as the headline product. PolyScale is the cautionary tale: a standalone transparent Postgres caching proxy is the most absorbable layer in the stack — the database vendor bundles equivalent routing for free. Caching ships as a *feature* of a product whose core value is policy, correctness and attribution.

---

## 7. PostgreSQL backend policy

All features are developed against **vanilla PostgreSQL** first.

- **Version matrix:** 14, 15, 16, 17, 18 via Docker (14/15 only where the feature is version-agnostic; 18 is the primary development target because it brings protocol 3.2, `OAUTHBEARER`, and variable-length cancel keys that break the fixed 12-byte assumption).
- **No cloud-specific behaviour in core.** IAM, RDS, Aurora and Neon adapters are optional plugins behind a trait (PgDog already demonstrates `rds_iam`, `azure_workload_identity`, `vault_dynamic` as separate server-auth backends — copy the *shape*, not the implementation).
- **Extensions are opaque by default.** We do not presume `pg_stat_statements`, `pgvector`, or Citus. Where an extension changes protocol-visible behaviour (Citus 12+ reports `search_path` back to clients; pgvector's ANN scans are memory-spiky), we model it explicitly and behind a feature flag.
- **No superuser requirement.** Everything must work as a least-privilege role; anything needing elevated grants is opt-in and documented.
- **Linux is the primary target** (`io_uring`, `splice`, `SO_REUSEPORT`); macOS is for development only, with the Linux-specific fast paths feature-gated.

---

## 8. Open questions blocking the start

1. **Licence** — AGPL-3.0 with a paid enterprise edition (PgDog's model) vs permissive Apache-2.0 (maximum adoption, no direct moat) vs BSL. This determines whether platforms can embed us and is hard to reverse.
2. **First deliverable shape** — self-hosted single binary, Kubernetes sidecar/operator, or an embeddable library. The research argues the sidecar/embedded mode is an unserved differentiator, but it constrains the runtime model.
3. **Scope of v1 conformance** — is "correct on the six main drivers + PG 16–18" acceptable as v1, or is the full matrix a launch requirement?
