# Product Thesis

> Companion to [`roadmap.md`](roadmap.md) (sequencing) and
> [`../research/00-landscape-and-innovation-map.md`](../research/00-landscape-and-innovation-map.md) (evidence).

## The problem

PostgreSQL connection multiplexing was solved in 2007 and is now free. What remains unsolved is
everything that happens *around* it:

- Transaction pooling breaks session state, so applications either can't use it or quietly break —
  prepared statements, `LISTEN`, advisory locks, temp tables, cursors, `SET`/`search_path`.
- RDS Proxy responds by silently **pinning** sessions, which defeats pooling invisibly and is nearly
  impossible to diagnose from CloudWatch.
- Poolers either forbid, pin, reject or **leak** session state between clients — the last being a
  tenant-isolation bug.
- There is no way to enforce a security policy below the application, which is exactly where
  enforcement has to live (CVE-2026-85620 bypassed an application-layer allowlist with a single
  syntactic trick).
- There is no fairness. One tenant or agent can starve every other, and nobody can attribute cost to
  the principal that caused it.

## Who it is for, in order

1. **Platform teams running multi-tenant Postgres** who need per-tenant isolation, quotas and
   chargeback, and who today hand-compute pool arithmetic and hope.
2. **Teams burned by pooler-induced breakage** — the ones who disabled prepared statements, disabled
   `queryset.iterator()`, or stand up a second session-mode pool just for `LISTEN`.
3. **Anyone exposing Postgres to AI agents**, which is now most people: agents are high-cardinality,
   bursty, untrusted, anonymous and financially unbounded. They are the worst possible workload for
   every pooler that exists.

## What we are building

> A protocol-aware PostgreSQL gateway that makes transaction pooling safe for stateful applications,
> makes policy enforcement impossible to bypass, and attributes every query to the agent or tenant
> that issued it.

Three capabilities, in build order:

1. **Session-State Ledger** — a per-client model of session state that the proxy can replay, dedupe
   and undo, so stateful applications work in transaction mode and schema migrations don't need a drain.
2. **Protocol-enforced policy** — capability-based, deny-by-default SQL policy evaluated on the real
   PostgreSQL parse tree and enforced on the wire, below anything an attacker can influence.
3. **Fairness and attribution** — quotas, admission control and chargeback-grade cost attribution per
   principal.

The first is the adoption wedge: it replaces PgBouncer with something strictly better and requires no
change to customer code. The second is the revenue. The third is what makes it enterprise-sticky.

## What we are explicitly not building

- **Not a faster PgBouncer.** Speed is table stakes, not a product. The interesting claim is
  correctness.
- **Not a sharding system first.** Two funded teams are already fighting there and the correctness
  problem is provably constrained. It comes last, if customers pay for it.
- **Not a caching proxy.** PolyScale is the cautionary tale: a standalone transparent Postgres cache
  is the most absorbable layer in the stack, because exact invalidation is a correctness liability
  and the database vendor can bundle equivalent routing for free. Caching ships as a feature.
- **Not a database.** We keep PostgreSQL. That is the whole point of being a proxy.
- **Not a MySQL proxy.**

## Why this is defensible

- **Correctness is hard.** Session virtualisation and DDL-safe plan invalidation are multi-quarter
  problems a PgBouncer fork cannot shortcut — and both are objectively measurable
  (pinning ratio → 0; migrations with zero `cached plan must not change result type` errors).
- **The policy engine compounds.** Deep parse-tree integration plus a capability model becomes a data
  asset — policy libraries per framework — with real switching costs.
- **Attribution is sticky.** Once every query is priced per principal, the gateway becomes the system
  of record for database spend, which is where budgets, approvals and forecasting live.
- **Trust is scarce.** Five PgBouncer CVEs in two years and a CVSS 9.2 MCP bypass mean demonstrable
  security is itself a differentiator.

## The honest risks

- PgBouncer is free and improving. All paid value must live in policy, operations, attribution and
  agent safety — never in pooling.
- Session virtualisation has genuinely hard corners. The rule is fail closed, never corrupt silently.
- The incumbents' low-concurrency latency advantage is real and must be engineered away, not assumed away.
- The decision that has to be made before public release — the licence — determines whether platforms
  can embed us, and is hard to reverse. See [`../adr/`](../adr/README.md).
