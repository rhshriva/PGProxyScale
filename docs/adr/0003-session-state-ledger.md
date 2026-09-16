# ADR 0003 — Session-State Ledger

- **Status:** Accepted (design); taxonomy of virtualisable state is an open spike (S2)
- **Date:** 2026-09-16
- **Depends on:** ADR 0001, ADR 0002

---

## Context

This is the central architectural decision of the product. It is the substrate for the first differentiator and the execution engine of the second (policy).

Today every pooler treats session state one of four ways:

| Behaviour | Who | Failure |
|---|---|---|
| Forbid it (document it as unsupported) | PgBouncer transaction mode | Breaks `SET`, `LISTEN`, `WITH HOLD`, advisory locks, `PREPARE`; official feature matrix marks them "Never" |
| Pin silently | PgDog (advisory locks), RDS Proxy (everything) | Multiplexing is defeated invisibly; `/aws` operators cannot diagnose it |
| Reject it | pg_doorman | Correct but hostile; apps simply fail |
| Leak it | pgagroal (no `DISCARD ALL` in the transaction pipeline) | **Cross-client state bleed — a correctness and tenant-isolation bug** |

None of these is a model. We need one.

---

## Decision

Maintain a **per-client, versioned session image** with an explicit, three-class taxonomy of state, and never rely on the server to tell us what the client asked for.

### The core rule

**Track what the client requested, not what the server reports.**

PgBouncer's `track_extra_parameters` is fundamentally limited because it can only track GUCs that PostgreSQL *chooses to report* to the client via `ParameterStatus` — a short, protocol-defined list. Anything outside it can only be `ignore_startup_parameters`, i.e. silently dropped. We instead record the client's intent from the wire stream (parsed at T2 per ADR 0002) and maintain our own authoritative image.

### State taxonomy

| Class | Examples | Strategy |
|---|---|---|
| **A — Virtualisable** | `SET`/`RESET` of known GUCs, `search_path`, `SET ROLE`, `application_name`, `statement_timeout`, `DateStyle`, `TimeZone`, `client_encoding` | Record in the image. Replay on checkout as **one batched, pipelined restore** — never one round trip per GUC. Prefer scoping with `SET LOCAL` inside the client's transaction where semantics permit, so state self-reverts and restore cost drops to zero. |
| **B — Emulatable** | Advisory locks, `LISTEN`/`NOTIFY`, cursors (`DECLARE`/`FETCH`/`CLOSE`), temp tables (where namespaceable) | Provide the *semantics* at the proxy rather than the mechanism at the backend. |
| **C — Non-virtualisable** | Unknown extension GUCs, session state from extensions we do not model, anything requiring a stable backend identity we cannot provide | **Detect and refuse with a specific, actionable error — or pin with an explicit, reported cost.** Never guess, never leak. |

Class C is the honest part. The requirement is not "support everything"; it is **"never hand a client a session that is not what it thinks it is."**

### Class B specifics

- **Advisory locks → lease manager.** Virtualise `pg_advisory_lock` as a proxy-held lease with heartbeating and re-acquisition across backend switches, **routed by lock key** so two contenders on the same key land on the same backend. Today no product does this: implementations pin (PgDog, RDS Proxy), reject (pg_doorman), or leak (pgagroal). This is also why Alembic advisory-lock migration runners deadlock through a transaction-mode pooler.
- **`LISTEN`/`NOTIFY` → fan-out.** Maintain a small number of long-lived server listeners; fan out to multiplexed subscribers; bind delivery to the client's transaction so delivery is **exactly-once** (PgDog's is opt-in, off by default, and at-most-once).
- **Cursors → owned backend identity for the cursor's lifetime.** This is the Django `queryset.iterator()` case, which currently forces teams to disable a feature because server-side cursors do not survive pooling.
- **Temp tables → per-client schema namespacing** where possible; otherwise *minimal* pinning with an eviction-cost model that reports its cost rather than hiding it.

### Ownership invariant

> A server connection may carry session state across a transaction boundary **only** if the ledger says a specific client owns it. Otherwise it is returned to a fully reset state.

This single invariant is what prevents the pgagroal-class leak and makes "pinning ratio" a meaningful, reportable metric rather than a mystery.

---

## Prepared statements and plan invalidation

The statement registry is part of the ledger, not a separate subsystem:

- Track **named and anonymous** `Parse`, plus SQL-level `PREPARE`/`EXECUTE`/`DEALLOCATE` (which PgBouncer forwards blind).
- Key statements on `(fingerprint, parameter type OIDs, relation OID set, rowtype version)`.
- On any component change, transparently re-`Parse` instead of surfacing `ERROR: cached plan must not change result type`.

### The DDL problem

**PostgreSQL logical decoding does not carry DDL.** `pgoutput` replicates row changes only. A proxy therefore cannot learn about a `DROP COLUMN` from the replication stream, which breaks both plan invalidation and any dependency-tracked cache.

We synthesise a DDL event stream from three sources:

1. **The wire stream** — we see every statement from every pooled client and can parse DDL directly. This is a genuine advantage: the proxy has the best view of schema change in the system.
2. **Server-side `ddl_command_end` event triggers** — to catch DDL issued through channels the proxy did not carry.
3. **Catalog-fingerprint polling** — cheap periodic fingerprints of `pg_class`/`pg_attribute` as the out-of-band fail-safe.

Detection latency from this hybrid is spike **S4**; if it cannot be kept under ~100 ms, plan invalidation degrades to "reconnect on demand" rather than shipping a lie.

---

## Consequences

**Positive**
- Removes the largest single class of pooler breakage instead of documenting it.
- Becomes the execution engine for the policy engine: per-statement `SET LOCAL role` / RLS / masking injection is the same mechanism.
- Makes pinning an accountable number, not a mystery — directly countering the RDS Proxy failure mode.
- Enables exactly-once `LISTEN` and correct advisory-lock routing, both of which are unclaimed.

**Negative / risky**
- Genuinely hard. `search_path`, `SET ROLE`, RLS interaction and PL/pgSQL dynamic SQL all have corner cases. Mitigation: an exhaustive taxonomy derived from the PostgreSQL source tree (spike S2) *before* implementation, and fail-closed behaviour for anything unclassified.
- Every virtualisation adds work to the checkout path. Mitigation: the batched single-round-trip restore, `SET LOCAL` scoping, and C++-free fast paths measured against the Phase 0 gates.
- A bug here is a correctness or tenant-isolation bug, which is worse than a performance bug. Mitigation: adversarial test suite in `tests/conformance` from Phase 0, including a test that deliberately tries to observe another client's state.

---

## Open questions

1. Classification of extension GUCs — is there a reliable way to enumerate a server's GUC surface and decide virtualisability, or must it be a declared allowlist?
2. Whether `SET LOCAL`-scoped injection can replace most explicit restores, and what the semantic gaps are inside explicit transactions.
3. Interaction with RLS: does per-statement role injection interact correctly with connection-level `SET ROLE` and prepared plans chosen under a different role?
4. How to detect state created by PL/pgSQL dynamic SQL that the proxy sees only as an opaque `SELECT my_function()`.
