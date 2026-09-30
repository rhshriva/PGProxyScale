# Product thesis

Current positioning, reviewed 2026-09-30. Feature boundaries and evidence are in
[implementation status](../plans/implementation-status.md); remaining work is in
[the roadmap](roadmap.md).

## Audience and value

PGProxyScale is a PostgreSQL gateway for platform teams running multi-tenant
applications, teams dealing with stateful transaction-pooling workloads, and
operators exposing bounded database access to agents.

Its ledger reconstructs supported settings, roles and prepared state while
reporting resources that still require a native backend. Parsed deny-by-default
SQL permissions, trusted role/RLS context, principal quotas and bounded scheduling
provide a shared governance model for wire clients and MCP stdio tools.
Operations expose diagnostics and measured usage rather than hiding backend
ownership or treating client elapsed time as server CPU.

## Product boundaries

Full state migration is unfinished: temp relations, session locks and LISTEN
subscriptions retain affinity. Cursor virtualization is opt-in and restricted.
Policy denies protected columns rather than masking results; OAuth/token exchange
and independent security acceptance remain open.

Wire accounting measures principal rows, bytes, elapsed exchanges and errors.
Separate server counters measure cumulative database/role/queryid usage; they do
not establish exclusive tenant CPU/WAL allocation for shared backend roles.
Endpoint failover requires external PostgreSQL promotion/fencing. Restricted
caching validates snapshots with database work; performance benefit must be measured.

## Adoption and release

Ship a standalone binary with a documented configuration and reproducible
compatibility tests. Evaluate each application's drivers, session resources,
roles, RLS and deployment topology; universal drop-in compatibility is not claimed.
Production certification requires independent security, real-provider, deployed
fencing and dedicated performance/soak evidence. Licence selection remains open.

Sharding, operator/embedding packaging and plugins are future decisions. The
product's value is correctness, governance and visibility with explicit limits;
competitive claims require current, versioned primary-source research and a
matching workload benchmark.
