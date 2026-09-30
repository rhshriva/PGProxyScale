# Governance acceptance fixture

`pgproxy.toml` is an isolated test configuration. Its public test password is
`pgproxy-test-password`; both frontend SCRAM identities use that password. It
expects the conformance PostgreSQL container on port 55439 and a proxy on 6446.
The proxy authenticates both identities as its configured backend service user,
then switches to the unprivileged `pgproxy_rls_reader` role before restoring
prepared statements. The injected tenant setting selects the appropriate rows.

Run `drivers/rls_fairness_check.py --setup-only` against the direct backend to
create the isolated test roles and FORCE RLS table, launch the proxy with this
configuration, then run that driver without `--setup-only`. It verifies prepared
backend handoffs, query quota shedding, another tenant's latency during a noisy
query, and an idle transaction's principal capacity limit.

Run `drivers/mcp_rls_check.py --binary /absolute/path/to/pgproxy --config
/absolute/path/to/pgproxy.toml` to verify the same identities and row isolation
through MCP stdio, including protected-column/schema filtering and the tenant's
1.5-second statement timeout. The stdio launcher is trusted local configuration;
the client cannot select its principal through a tool argument.

The scheduler's `per_principal` setting caps both active session/transaction
leases and pending requests per principal. Its total maximum is bounded by this
route's backend pool size. Active transactions retain their scheduler lease until
idle ReadyForQuery. Additional pipelined commands share that session lease.

The capabilities intentionally implement a conservative SQL subset: qualified
relations, literal projections, basic column projections, explicitly approved
functions, and ordinary transaction control. Operators, casts, CTEs, arbitrary
utility commands and dynamic SQL are denied. `set_config` cannot be granted, as
it could change trusted role, tenant or timeout context. Custom approved functions
are trusted database code and require operator review. Protected columns are
denied rather than transformed or masked.

MCP constant-result caching accepts only immutable literal projections. Every
cache hit still checks policy and consumes the agent's query budget. Exact SQL
and the complete principal are part of the key.

`relation-cache.toml` adds an isolated MCP relation-cache acceptance fixture.
Run `drivers/relation_cache_check.py --binary /absolute/path/to/pgproxy --config
/absolute/path/to/relation-cache.toml`. The driver creates its own service role
and tables in the existing `pgproxy-area-tests` conformance container, and proves
actual cache hits, external committed/uncommitted writers, rollback, DDL,
TRUNCATE, permission revocation, failed authentication, and exact measured MCP
usage including cache hits and errors. It emits an EOF usage report in `/tmp`.

Relation caching is restricted to simple projections from one permanent ordinary
heap table with supported integer/text/boolean/UUID output types. Views, RLS,
partitions/inheritance, functions, expressions, custom/output-sensitive types and
replicas bypass caching. Each request opens a fresh backend and validates actual
service identity, cluster incarnation, relation identity and PostgreSQL MVCC
snapshot under an ACCESS SHARE lock in a read-only repeatable-read transaction.
That lock is acquired before the first transaction snapshot, protecting against
TRUNCATE and table-rewrite hazards. Every stamp change clears cached entries;
this deliberately conservative database-wide invalidation also observes writers
outside the proxy. Authentication, connection, permission and transaction failures
clear the cache and never return stale results. Catalog/control-probe permission
failures before the transaction bypass caching. The fixture grants `pg_monitor`
to its dedicated service role for cluster identity validation.

This synchronous validation still connects and queries metadata on cache hits;
it avoids executing the cached relation projection, without promising a measured
latency improvement. It is not logical-decoding or dependency-selective caching.
# Protected-column regression

`protected-columns.toml` is a disposable-test route for PostgreSQL on port 55447,
database `conformance`, with public test credentials. Prepare only in an isolated
fixture:

```sql
CREATE TABLE public.pgproxy_masked_review (id integer, secret text);
INSERT INTO public.pgproxy_masked_review VALUES (42, 'private-review-value');
```

Start the proxy with that config and run
`python3 tests/conformance/drivers/protected_columns_check.py --port 6478`.
The driver checks explicit protected columns, wildcards, whole-row composites,
quoted aliases and renamed relation columns through both SQL protocols, plus
permitted qualified column reads. All 16 exchanges must pass. Relation-column
renaming and ambiguous names matching relation aliases are conservatively refused
when protected columns are configured; authorization does not perform catalog
resolution. Function capabilities and server-side views still require operator
review of what they expose.

## Measured server cost

The operator CLI supports `--server-cost-database`, `--server-cost-user` and
`--server-cost-report` together. It connects to the configured route through the
normal credential adapter, failover and physical connection limit, and exports
an explicitly requested snapshot. It requires `pg_read_all_stats` privileges
(`pg_monitor` or superuser also suffice) and the `pg_stat_statements` extension.
No extra monitoring query is inserted into application requests.

The exported measurements are **cumulative database/role/query aggregates**.
The identity includes cluster system identifier, postmaster start, server major,
database OID, role OID, PostgreSQL query ID and top-level status. SQL text and bind
values are excluded. The collector reports actual WAL generation, individual
shared/local/temp buffer counters, calls, rows and server elapsed execution time.
Decimal WAL counters retain their exact PostgreSQL numeric representation. These
are all executions under that database role, including outside writers; the
collector never claims an exclusive tenant allocation. PostgreSQL query IDs are
distinct from the proxy parser fingerprints.

When the `pg_stat_kcache` extension (2.2 or later) is installed and preloaded, its raw function
is joined on the complete database/role/query/top-level tuple to export measured
execution user and system CPU seconds. Planning CPU is not included. JSON double
precision is preserved during collection and export. Missing CPU instrumentation
produces explicit unavailable CPU values, never an elapsed-time estimate;
insufficient instrumentation permissions fail collection. Nested statements are
excluded to avoid summing both parent and nested work. Parallel worker CPU may
not be included by the extension. The underlying counters are live observations,
not an atomic cross-extension snapshot. Reset timestamps and eviction counts are
reported for global pg_stat_statements resets; per-entry `statistics_since`
identifies targeted resets on PostgreSQL 17 and later (null on older versions).
CPU extension resets are independent and have
no exported reset epoch; no inferred deltas or billing claims are made across
discontinuities.

`drivers/server_cost_check.py` runs seven live checks against a PostgreSQL fixture
with `pg_stat_statements` preloaded. `--require-cpu` additionally requires
`pg_stat_kcache` installed and preloaded, and compares exported CPU counters
exactly with that extension. The driver verifies direct WAL/buffer reconciliation,
shared-role outside writers, CPU availability, monitoring grants and denial,
global/targeted resets and extension removal.

The counter and identity definitions follow the primary
[PostgreSQL pg_stat_statements documentation](https://www.postgresql.org/docs/current/pgstatstatements.html).
The CPU measurement fields and instrumentation caveats follow the
[pg_stat_kcache maintained repository](https://github.com/powa-team/pg_stat_kcache)
and its [raw-function declaration](https://github.com/powa-team/pg_stat_kcache/blob/master/pg_stat_kcache--2.1.3--2.2.0.sql).

Build the native executable, then run `bash tests/conformance/server-cost/run.sh`
to execute 35 cost checks across PostgreSQL 14–18 in disposable containers.
The runner removes its own container and anonymous data volume, uses port 55448
by default and accepts `PGPROXY_COST_BACKEND_PORT` for an alternate local port.
For measured CPU verification, build an isolated fixture image with
`docker build -t pgproxy-server-cost-kcache:fixture tests/conformance/server-cost`,
then run the same runner with `PGPROXY_COST_VERSIONS=17`,
`PGPROXY_COST_POSTGRES_IMAGE=pgproxy-server-cost-kcache:fixture` and
`PGPROXY_COST_REQUIRE_CPU=1`. This exercises actual extension rusage counters;
it does not install packages on the host.
