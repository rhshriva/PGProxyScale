# Session-State Taxonomy (PostgreSQL 14–18)

> **Spike S2 outcome.** This is the specification for Phase 1 (the Session-State Ledger, ADR-0003).
> Derived from the PostgreSQL source, not from documentation summaries.
> Raw data: `spikes/s2/gucs.json`, `spikes/s2/userset-guc-inventory.tsv`, `spikes/s2/guc_tables_pg{14..18}.c`.

---

## 1. Method

The complete GUC surface was extracted by parsing the authoritative tables out of the PostgreSQL
source tree for every supported major:

| Version | Source file | Reason |
|---|---|---|
| 14, 15 | `src/backend/utils/misc/guc.c` | The GUC tables lived in `guc.c` before PG 16 |
| 16, 17, 18 | `src/backend/utils/misc/guc.c` → `guc_tables.c` | Tables were split into their own file in PG 16 |

For each GUC we extracted its **name**, **context** (`PGC_USERSET`, `PGC_SUSET`, `PGC_SIGHUP`,
`PGC_POSTMASTER`, `PGC_BACKEND`, `PGC_SU_BACKEND`, `PGC_INTERNAL`) and its **flags** — specifically
`GUC_REPORT`, which is the flag that causes the server to push the value to the client via
`ParameterStatus`.

`GUC_REPORT` matters more than anything else here, because it defines the *only* channel a pooler has
for passively learning what a client changed.

---

## 2. The headline finding

| Metric | PG14 | PG15 | PG16 | PG17 | PG18 |
|---|---|---|---|---|---|
| Total GUCs | 357 | 364 | 372 | 387 | **406** |
| Client-settable (`PGC_USERSET`) | — | — | — | — | **154** |
| Superuser-only (`PGC_SUSET`) | — | — | — | — | 60 |
| Server/config-only (`PGC_SIGHUP`/`POSTMASTER`/`INTERNAL`) | — | — | — | — | 186 |
| **GUCs reported to the client** | 13 | 13 | 14 | 14 | **15** |
| **Client-settable *and* reported** | 9 | 9 | 10 | 10 | **10** |

**144 of the 154 client-settable GUCs are never reported to the client by any PostgreSQL version.**

This quantifies precisely why PgBouncer's `track_extra_parameters` is structurally insufficient
rather than merely incomplete: it can only ever track the handful of GUCs the server chooses to
volunteer. Everything else must either be declared in `ignore_startup_parameters` (i.e. silently
dropped) or is simply invisible. There is no configuration that fixes this — the channel does not
carry the information.

### The reported set, and how it changed

```
PG14/15 (13): DateStyle, IntervalStyle, TimeZone, application_name, client_encoding,
              default_transaction_read_only, in_hot_standby, integer_datetimes, is_superuser,
              server_encoding, server_version, session_authorization, standard_conforming_strings

PG16/17 (14): + scram_iterations

PG18    (15): + search_path
```

Of these, only **10 are client-settable**: `DateStyle`, `IntervalStyle`, `TimeZone`,
`application_name`, `client_encoding`, `default_transaction_read_only`, `scram_iterations`,
`search_path`, `session_authorization`, `standard_conforming_strings`. The other five
(`in_hot_standby`, `integer_datetimes`, `is_superuser`, `server_encoding`, `server_version`) are
server-controlled facts about the connection, not session state.

**`search_path` became reportable only in PostgreSQL 18.** On PG 14–17 there is no protocol mechanism
whatsoever for a pooler to observe a client's `search_path`. This is the precise mechanism behind the
documented cross-tenant leak where `postgres_fdw` leaves `search_path` modified and a
transaction-mode pooler then resolves subsequent unqualified queries against the wrong schema. Our
design does not depend on this channel at all, which is why it is correct on every version rather
than only on 18+.

---

## 3. Classification rules

Per ADR-0003:

- **A — Virtualisable.** Record the client's intent from the wire, replay on checkout. Never read it
  back from the server.
- **B — Emulatable.** Provide the *semantics* at the proxy rather than the mechanism at the backend.
- **C — Refuse or pin, explicitly.** Detect, report the cost, and fail closed. Never guess, never leak.

Two cross-cutting flags apply to class-A GUCs and are **not optional**:

- **`A-parser`** — the GUC changes how SQL text is parsed or how values are rendered. The proxy's own
  parser must mirror it, or we will mis-parse the client's own statements. 9 GUCs.
- **`A-planner`** — the GUC changes plan selection. It must be part of the prepared-statement cache
  key, or two clients will share a plan chosen under the other's settings. 63 GUCs.

---

## 4. Class-A GUCs

All 154 `PGC_USERSET` GUCs are class A (record + replay), subdivided as follows. The full
machine-readable inventory is `spikes/s2/userset-guc-inventory.tsv`.

- **82 plain A** — recorded and replayed, no additional consequence.
- **63 A-planner** — additionally feed the prepared-statement cache key (§6).
- **9 A-parser** — additionally feed the proxy's own parser state (§7).

### Class A-parser (9) — the ones that can corrupt our own parsing

| GUC | Why it matters to *us*, not just to the server |
|---|---|
| `standard_conforming_strings` | Changes whether `\` is an escape character inside string literals. If a client turns this off and we do not mirror it, **our parser mis-tokenises the client's own SQL** — which is a policy bypass in Phase 2, not merely a bug. |
| `backslash_quote` | Governs whether `\'` is accepted in strings. Same class of hazard. |
| `escape_string_warning` | Emits warnings on backslash escapes; affects diagnostics only, tracked for fidelity. |
| `client_encoding` | Byte-level decoding of string literals. Also affects how we interpret identifiers. |
| `DateStyle` / `IntervalStyle` | Governing output rendering and some input parsing of date/interval literals. |
| `bytea_output` | `hex` vs `escape`; affects result rendering and any comparison we do on values. |
| `extra_float_digits` | Float rendering; affects result comparison and caching. |
| `default_text_search_config` | Affects `to_tsvector` semantics in parsed expressions. |

> **Consequence for ADR-0002.** This was not explicit in the original parser ADR and is now recorded
> there: the parser is **not** stateless with respect to the session. `standard_conforming_strings`
> and `backslash_quote` must be part of the parse-cache key, and must be applied to the parser
> configuration used for that client. A parser that ignores them is both wrong and, in Phase 2,
> exploitable.

### Class A-planner (63) — the ones that change plan choice

`enable_*` (26 of them), `*_cost` parameters, `geqo*`, `from_collapse_limit`, `join_collapse_limit`,
`cursor_tuple_fraction`, `default_statistics_target`, `default_table_access_method`,
`effective_cache_size`, `work_mem`, `maintenance_work_mem`, `random_page_cost`, `seq_page_cost`,
`min_parallel_*`, `parallel_*_cost`, `jit*`, `plan_cache_mode`, `recursive_worktable_factor`,
`constraint_exclusion`, `vacuum_cost_*`, `logical_decoding_work_mem`.

This validates the design choice (also made independently by pg_doorman) of including a
**planner-GUC digest** in the anonymous-prepared-statement key. Without it, a client running with
`enable_seqscan=off` could execute a plan cached by a client running with defaults. `plan_cache_mode`
is the sharpest case: it explicitly selects `force_custom_plan` vs `force_generic_plan`.

### Class-C GUCs

The 60 `PGC_SUSET` GUCs are class C **by default**: a client can only set them if it is a superuser,
and we cannot replay them onto a backend unless our own backend role is also superuser. Notable:
`session_replication_role`, `fsync`, `synchronous_commit` (SUSET since PG 16 for some cases),
`track_commit_timestamp`, `wal_*`. Handling: if the client is not capable of setting it, PostgreSQL
already rejects it; if it is capable, we must either route it to a dedicated session-mode backend or
refuse with a clear error. Silently dropping is the one unacceptable option.

---

## 5. Non-GUC session state

The GUC surface is only part of the problem. The following state is not a GUC at all:

| State | Class | Handling in Phase 1 |
|---|---|---|
| **Named prepared statements** | A | Fingerprint-keyed registry; transparent re-`Parse` on backend switch; invalidated by the DDL stream. |
| **Unnamed prepared statement** | A | Protocol semantics: the unnamed statement is destroyed by the next `Parse` *and by any simple `Query`* — we must reproduce that exactly, and may cache the underlying plan internally (pg_doorman's `DOORMAN_<N>` approach, with correct invalidation instead of expiry). |
| **SQL-level `PREPARE`/`EXECUTE`/`DEALLOCATE`** | A | Parse-tracked. PgBouncer forwards these blind. |
| **Transaction-scoped state** — `SET LOCAL`, `SET CONSTRAINTS`, deferred triggers, `NOTIFY` queue, xact advisory locks, non-hold cursors, portals | A | No work required beyond correct transaction boundaries; must never outlive the transaction. |
| **`SET ROLE` / `SET SESSION AUTHORIZATION`** | A | Part of the session image; interacts with RLS and with plan caching (a plan may be role-dependent). |
| **`search_path`** | A | Part of the image. Security-critical: an unqualified query must never resolve in another tenant's schema. |
| **`row_security`** | A | Part of the image; security-critical. |
| **GUCs passed via `options=` / `PGOPTIONS` in the startup packet** | A | Captured at startup and treated as the initial image. PgBouncer requires these to be declared in `track_extra_parameters` or they are dropped. |
| **Session advisory locks** (`pg_advisory_lock`) | B | Proxy-level lease manager with heartbeats and re-acquisition, **routed by lock key** so contenders share a backend. |
| **`LISTEN` / `UNLISTEN` registrations** | B | Few backend listeners, many multiplexed subscribers; delivery bound to the client's transaction for exactly-once. |
| **`WITH HOLD` cursors** | B | Session-scoped; require backend ownership for the cursor's lifetime, or materialisation. |
| **Temp tables and the `pg_temp` schema** | B → C | Per-client schema namespacing where possible (the temp schema name is backend-specific and created lazily on first temp object); otherwise **minimal, reported** pinning. |
| **`BackendKeyData` (cancel key)** | B | Must be virtualised: the proxy issues its own key and routes `CancelRequest`. PG18 makes keys variable-length (to 256 bits), breaking the fixed 12-byte assumption. |
| **`lastval()` / `currval()`** | **C** | Session-local sequence state. Cannot be virtualised. Refuse or pin explicitly. |
| **Large-object handles (`lo_open`)** | **C** | Backend-local file descriptors. Refuse or pin. |
| **Two-phase commit (`PREPARE TRANSACTION`)** | **C** | Inherently session- and cluster-global; PostgreSQL's own documentation advises against application use. Refuse. |
| **Backend identity** (`pg_backend_pid()`, `inet_server_addr()`) | **C** | Genuinely tied to a backend. Report honestly; do not pretend. |

---

## 6. Derived Phase 1 requirements

1. The session image is keyed on **client intent captured from the wire**, never on `ParameterStatus`.
   The reported set is a 15-element subset of a 406-element surface and must not be the source of truth.
2. The **parse-cache key** must include `standard_conforming_strings`, `backslash_quote`, and
   `client_encoding`, because the parser is session-sensitive.
3. The **prepared-statement key** must include a planner-GUC digest over the 63 class A-planner GUCs.
4. `search_path` and `row_security` are security-critical; their handling needs its own adversarial
   tests (query must never resolve in another tenant's schema).
5. Restore must be **one batched, pipelined round trip**; on a 154-GUC surface a per-GUC restore would
   be catastrophic on the checkout path.
6. Every class-C item needs a specific, actionable error — and the ledger must be introspectable so an
   operator can see exactly which client is pinned and why.
7. The taxonomy must be re-generated per PostgreSQL major at build time (or checked in per version),
   because the surface grows: 357 → 406 GUCs between PG 14 and PG 18, with `search_path` newly
   reportable and `scram_iterations` added in the middle.

---

## 7. Open questions carried into Phase 1

1. Is there a reliable way to enumerate a server's GUC surface (including extension-registered GUCs)
   at runtime, or must virtualisability be a declared allowlist? Extensions register GUCs we cannot
   know statically.
2. How much of the restore cost can `SET LOCAL` scoping eliminate inside explicit transactions, and
   what are the semantic gaps (e.g. a client that reads a GUC back via `SHOW` mid-transaction)?
3. Does per-statement role injection interact correctly with plans cached under a different role?
4. Can PL/pgSQL dynamic SQL create session state we never observe on the wire? If so, what is the
   detection strategy? (This is the largest remaining hole in the model.)
5. `currval`/`lastval`/large-object handles: is pinning or explicit refusal the better product
   behaviour? Refusal is safer; pinning is friendlier. Needs a decision before Phase 1 ships.
