# Managed PostgreSQL Data-Access Layers — Research Notes

Scope: RDS Proxy, Aurora (incl. Limitless, DSQL), Hyperdrive, plus brief GCP/Azure pooling.

## Comparison

| | Pooling mode | Prepared stmts | Pinning | Auth | Cache | Pricing |
|---|---|---|---|---|---|---|
| **RDS Proxy** | Multiplexing (implicit txn-level) | Supported; `Parse`/`Bind` pins | Yes — core constraint; **no PG pinning filters** | Client IAM; proxy→DB IAM or Secrets Manager | None | $0.015/vCPU-hour per instance |
| **Aurora native** | None (client = backend) | Native | n/a | IAM DB auth, Secrets Manager | None | Instance hours |
| **Aurora Limitless** | Sharded routing, not pooling | Shard-local | n/a | No IAM DB auth / Secrets Manager | None | 16–6144 ACU/shard group |
| **Aurora DSQL** | Connectionless HTTPS | Limited | n/a | IAM only | None | Per-request |
| **Hyperdrive** | **Transaction** | Named PS only in `postgres.js`/`node-postgres` | `RESET` on return; `SET` scoped to txn/query | Stored origin credentials | Reads, `max_age` TTL, **no write invalidation** | Included in Workers Paid; no egress |
| **Cloud SQL MCP** | Transaction (PgBouncer) | PgBouncer semantics | PgBouncer | IAM via Auth Proxy | None | Free |
| **Azure PgBouncer** | Transaction | `max_prepared_statements`, default 0 = off | PgBouncer | Entra ID | None | Free |

## 1. AWS RDS Proxy

**Architecture.** A managed proxy fleet inside your VPC between clients and one RDS/Aurora
instance. It maintains a warm connection pool, queues/throttles clients when the pool is
exhausted, and sheds load rather than overwhelming the DB. It also hides failover by reconnecting
to the new primary while preserving client connections
([docs](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/rds-proxy.html)).

**Pooling mode.** Connection multiplexing, not strict transaction mode — the proxy reuses a
backend whenever session state permits. **Pinning** is the mechanism that defeats multiplexing:
when a session becomes stateful, that backend is bound to the client until the state clears.
Documented/likely causes: any statement >16 KB (explicitly documented), prepared-statement
`Parse`/`Bind`, `SET`/session variables, `SET ROLE`, explicit `BEGIN`…`COMMIT`, temp tables,
advisory locks, `LISTEN`, cursors, and long-running transactions. Notably **PostgreSQL has no
session pinning filters** (MySQL does), so you cannot configure the proxy to ignore known-safe
statements. `SET` in the proxy *initialization query* is the documented workaround
([limitations](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/rds-proxy.html)).

**Detection.** There is no "pinned" metric. Operators infer it by comparing
`ClientConnections` against `DatabaseConnections` over time (a growing gap means multiplexing is
failing), plus `DatabaseConnectionsBorrowLatency` and client-visible latency
([monitoring](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/rds-proxy.monitoring.html),
[pinning KB](https://repost.aws/knowledge-center/rds-proxy-connection-pinning-issues)).

**Auth.** Clients must authenticate with IAM (or Secrets-Manager-derived credentials presented
via IAM); the proxy fetches DB credentials from Secrets Manager. Up to 200 secrets per proxy.

**Limits.** 20 proxies/account; 1 target instance per proxy; VPC-only (never public); no
`dedicated` tenancy VPC; no custom DNS with SSL hostname validation; PostgreSQL: no
`CancelRequest` (Ctrl+C in psql doesn't cancel), no streaming replication, protocol v3.0 only,
no direct SSL negotiation; `lastval()` unreliable.

**Pricing.** $0.015 per vCPU-hour per registered instance, plus instance hours ([pricing](https://aws.amazon.com/rds/proxy/pricing/)).

## 2. Amazon Aurora

**Writer/reader endpoints** are DNS names: the cluster (writer) endpoint follows failover; the
reader endpoint load-balances across replicas; custom endpoints pin subsets. Only the writer
endpoint supports writes; reader-endpoint queries can hit a lagging replica
([endpoints](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/Aurora.Endpoints.html)).
**Fast failover** promotes a replica and repoints DNS, typically in tens of seconds; existing TCP
connections break, so apps must retry. RDS Proxy exists precisely to hide this.

**Serverless v2** scales capacity in ACU increments per instance with no reconnect semantics —
from the client it behaves like a provisioned instance, so it does **not** solve connection
churn.

**Limitless Database** is genuine **sharding**, not pooling: a DB shard group of routers + shards
behind one endpoint, transparent routing, distributed transactions. Hard limits: one shard group
per cluster and five per Region; 16–6144 ACU; **no shard merge**; cannot update shard keys; no
serializable isolation; **RDS Proxy, read replicas, custom endpoints, Secrets Manager, Global
Database and the RDS Data API are all unsupported**; Aurora I/O-Optimized storage required
([limits](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/limitless-reqs-limits.html)).

**RDS Data API** replaces the wire protocol with signed HTTPS calls — no connections to pool, but
also no session affinity, no cross-call prepared statements, and per-request latency.

**Aurora DSQL** is the "what if there were no connections at all" answer: a PostgreSQL-16-compatible,
active-active serverless distributed database with IAM-only auth and an HTTPS endpoint, so there
is no connection pool or failover to manage
([DSQL](https://docs.aws.amazon.com/aurora-dsql/latest/userguide/what-is-aurora-dsql.html)).
It replaces connection management, not PgBouncer.

## 3. Cloudflare Hyperdrive

**Architecture.** (1) Edge connection setup terminates the Postgres handshake at the Cloudflare
location nearest the Worker; (2) a regional origin pool holds warm backend connections near your
database; (3) read-query results are cached. Pool is transaction mode; connections are `RESET`
when returned, so `SET` only lasts a transaction or a single multi-statement query — apps must
re-issue `SET` per transaction ([how it works](https://developers.cloudflare.com/hyperdrive/concepts/how-hyperdrive-works/)).

**Prepared statements.** Only *named* prepared statements in `postgres.js` and `node-postgres`
are supported; other drivers may be unsupported or slower — this forces driver/ORM changes.

**Caching.** Read-only queries cached for `max_age`; **writes never invalidate the cache**.
Read-after-write consistency requires a second, cache-disabled configuration. 50 MB max cached
response; 60 s max query duration.

**Limits.** 10 (Free) / 25 (Paid) configs; ~20 / ~100 origin connections; 15 s connect timeout;
10 min idle timeout; 50 MB cache cap. The docs admit a distributed pool may overshoot the cap
(availability over strict enforcement)
([limits](https://developers.cloudflare.com/hyperdrive/platform/limits/)).

**Pricing.** Pooling and caching are included in the Workers Paid plan with no additional
charges and no data-transfer/egress fees; cached and uncached queries count alike
([pricing](https://github.com/cloudflare/cloudflare-docs/blob/production/src/content/docs/hyperdrive/platform/pricing.mdx)).
Free plan exists with tighter limits.

## 4. Other hyperscaler pooling (brief)

- **Cloud SQL "Managed Connection Pooling"** — built-in PgBouncer, transaction mode, enabled by
  flags, no separate proxy, no extra charge
  ([docs](https://cloud.google.com/sql/docs/postgres/managed-connection-pooling)).
- **AlloyDB** — managed connection pooling (PgBouncer-based) plus the AlloyDB Auth Proxy /
  connectors for IAM + TLS; the connectors are for auth, **not** pooling, which is a common
  confusion ([connectors discussion](https://discuss.google.dev/t/alloydb-auth-proxy-with-connection-pooling/248662),
  [managed pooling](https://cloud.google.com/alloydb/docs/configure-managed-connection-pooling)).
- **Azure Database for PostgreSQL flexible server** — built-in PgBouncer 1.25.2 on port 6432,
  transaction mode by default, Entra ID supported, free. Documented limits: **no Burstable tier**;
  prepared statements need `max_prepared_statements` above 0 and only protocol-level PS work
  (libpq `PQprepare`, not `PREPARE … AS`); restarts on scale/failover drop all connections;
  single-threaded PgBouncer is a scaling bottleneck
  ([docs](https://learn.microsoft.com/en-us/azure/postgresql/connectivity/concepts-pgbouncer)).

## What managed vendors deliberately do NOT solve

1. **Pinning visibility and control.** No vendor exposes a live "pinned session" signal or a
   policy engine to route pinned work; RDS Proxy won't even let PostgreSQL users define pinning
   filters. You discover it from a metric gap after latency degrades.
2. **Safe caching with invalidation.** Hyperdrive caches reads and does nothing on writes — it
   pushes read-after-write correctness back to the application.
3. **Portable prepared-statement semantics.** RDS Proxy pins, Azure needs a non-default parameter
   and protocol-level PS, Hyperdrive supports only two drivers.
4. **Cross-vendor unity.** AWS ships RDS Proxy + Limitless + DSQL, GCP ships PgBouncer-based MCP,
   Azure ships single-threaded PgBouncer. Nothing is multi-cloud or driver-transparent.
5. **Honest limits and coverage.** RDS Proxy cannot exceed the instance backend cap and is
   VPC-only, can't front read replicas or Limitless; Hyperdrive admits it may overshoot its
   published cap; Azure PgBouncer excludes Burstable. A proxy that *classifies* statements,
   reports pinning in real time, and invalidates caches on write has no managed equivalent today.
