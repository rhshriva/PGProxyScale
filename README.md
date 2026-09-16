# PGProxyScale

A protocol-aware PostgreSQL gateway. The thesis, the competitive research and the
sequencing plan all live in `docs/`.

**Start here:** [`docs/vision/roadmap.md`](docs/vision/roadmap.md) — what to build, in what order,
and why the Session-State Ledger comes before the policy engine.

## What this is

Three differentiators, in build order:

1. **Session-State Ledger** — transaction pooling that does not break stateful applications, and
   schema migrations that do not require draining the pooler. Today every pooler either forbids
   session state, pins silently, rejects it, or leaks it between clients.
2. **Protocol-enforced policy** — capability-based, deny-by-default SQL policy enforced on the wire
   with the real PostgreSQL grammar, so it cannot be bypassed the way an application-layer allowlist
   can (cf. CVE-2026-85620).
3. **Per-principal fairness and attribution** — quotas, admission control and chargeback-grade cost
   attribution, so one tenant or agent cannot degrade another.

Explicitly *not* the product: raw pooling speed, and sharding-first. See `docs/vision/roadmap.md` §6.

## Status

Pre-alpha. Nothing is implemented yet — this repository currently contains the research base, the
decision records, and the plan.

## Layout

```
docs/
  vision/roadmap.md            sequencing plan and phase gates       ← start here
  vision/product-thesis.md     positioning, buyers, non-goals
  adr/                         architecture decision records
  architecture/overview.md     component map, threading, data path
  architecture/                session-state-taxonomy.md = Phase 1 spec
  plans/                       phase-0 plan + measured spike findings
  research/                    the competitive and technical research base
crates/                        Rust workspace (see ADR 0001)
tests/conformance/             wire-protocol conformance harness (run against
                               direct PostgreSQL first - it is the control)
spikes/                        the throwaway experiments behind the ADR revisions
benches/                       hard-case benchmark suite (not yet built)
tools/                         PostgreSQL version matrix
pgproxy.toml                   example configuration
```

## Decisions so far

| ADR | Decision |
|---|---|
| [0001](docs/adr/0001-language-and-runtime.md) | **Rust**, thread-per-core runtime (confirmed by spike S1); no async runtime, no splice bypass |
| [0002](docs/adr/0002-parser-strategy.md) | `libpg_query` over FFI; three-tier parsing; never parse per `Bind`/`Execute` |
| [0003](docs/adr/0003-session-state-ledger.md) | Explicit per-client session image with a three-class state taxonomy; fail closed on the unclassifiable |
| [0004](docs/adr/0004-licence.md) | Licence — **deliberately deferred** |
| [0005](docs/adr/0005-deliverable-shape.md) | **Standalone binary first**; sidecar/library kept open structurally |

## Status

**M0 reached.** `pgproxy` serves real sessions: it reads the startup packet, routes the client's
database to a configured backend, relays authentication (passthrough — it never needs the password
or the SCRAM verifier), and proxies the session.

All 17 conformance scenarios pass **through** the proxy, not just against direct PostgreSQL:
extended protocol, named and unnamed prepared statements, SQL-level `PREPARE`, `search_path`,
`WITH HOLD` cursors, advisory locks, `LISTEN`/`NOTIFY`, `COPY FROM STDIN`, a 50k-row result set,
and 16 concurrent clients.

```sh
cargo build --workspace
cargo test  --workspace
./target/debug/pgproxy --config pgproxy.toml --check    # validate config only
./tests/conformance/run.sh                              # control run against PostgreSQL 18
PROXY=1 ./tests/conformance/run.sh                      # the same scenarios, through pgproxy
./tests/conformance/scram_interop.sh                    # SCRAM verified against real libpq
```

**Not yet implemented**, and refused rather than faked: TLS (the proxy answers `SSLRequest` with
`N`), cancellation routing (ADR-0007), transaction pooling (W4), the admin console, and the
Session-State Ledger (Phase 1).

## Open questions

The **licence** is deferred (ADR-0004) and only becomes urgent before external contributions. The
**v1 conformance scope** — which drivers and PostgreSQL majors are launch requirements — is still
open; the harness currently covers psycopg3 × PostgreSQL 18, and the M0 milestone calls for a
second driver.

## Building

Requires Rust 1.91+ and a C toolchain (`libpg_query` is built from source).

```sh
cargo build --workspace
cargo test --workspace
```
