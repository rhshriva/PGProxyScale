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
  vision/product-thesis.md     (todo)
  adr/                         architecture decision records
  architecture/overview.md     component map, threading, data path
  plans/                       per-phase implementation plans (todo)
  research/                    the competitive and technical research base
crates/                        Rust workspace (see ADR 0001)
benches/                       hard-case benchmark suite
tests/conformance/             driver × PostgreSQL version conformance matrix
tools/                         docker-compose matrix, driver harnesses
```

## Decisions so far

| ADR | Decision |
|---|---|
| [0001](docs/adr/0001-language-and-runtime.md) | **Rust**, thread-per-core runtime, one C dependency (`libpg_query`) |
| [0002](docs/adr/0002-parser-strategy.md) | `libpg_query` over FFI; three-tier parsing; never parse per `Bind`/`Execute` |
| [0003](docs/adr/0003-session-state-ledger.md) | Explicit per-client session image with a three-class state taxonomy; fail closed on the unclassifiable |

## Open questions

The licence, the first deliverable shape (binary vs sidecar vs embeddable library), and the v1
conformance scope are unresolved — see `docs/vision/roadmap.md` §8.

## Building

Requires Rust 1.91+ and a C toolchain (`libpg_query` is built from source).

```sh
cargo build --workspace
cargo test --workspace
```
