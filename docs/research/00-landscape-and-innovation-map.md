# PostgreSQL Proxy & Pooler Landscape — Deep Research and Innovation Map

**Date:** 2026-09-16
**Scope:** every meaningful PostgreSQL wire-protocol proxy, pooler, router and managed data-access layer, plus the practitioner pain points and the technical frontier.
**Purpose:** decide where a new product can be *categorically* better rather than incrementally faster.

**Companion files (raw research, full citations):**

| File | Contents |
|---|---|
| [`01-pooler-comparison.md`](01-pooler-comparison.md) | Full 10-column technical matrix for all self-hostable poolers + per-product failure modes |
| [`02-pgdog-doorman-agroal-proxysql.md`](02-pgdog-doorman-agroal-proxysql.md) | Deep dive: PgDog, pg_doorman, pgagroal, ProxySQL-PG, plus Neon/Crunchy/RDS Proxy notes |
| [`03-odyssey-pgpool-supavisor.md`](03-odyssey-pgpool-supavisor.md) | Odyssey vs pgpool-II vs Supavisor detail |
| [`04-cloud-aws-cloudflare.md`](04-cloud-aws-cloudflare.md) | AWS RDS Proxy, Aurora/Limitless/DSQL, Cloudflare Hyperdrive, GCP/Azure |
| [`05-cloud-serverless-vendors.md`](05-cloud-serverless-vendors.md) | Neon, Supabase, Prisma Accelerate, serverless drivers, PolyScale post-mortem |
| [`06-sharding-routing-transactions.md`](06-sharding-routing-transactions.md) | Sharding (Citus/PgDog/PgCat/ShardingSphere), RW splitting, HA, distributed transactions, multi-tenancy |
| [`07-failover-and-ha.md`](07-failover-and-ha.md) | Failover/HA deep dive: Patroni, VIP/DNS, pg_auto_failover, ProxySQL, split-brain |
| [`08-practitioner-pain-points.md`](08-practitioner-pain-points.md) | 12 pain themes with real user quotes and permalinks |
| [`09-innovation-frontier.md`](09-innovation-frontier.md) | Wire protocol, parsing, caching, transports, auth, observability, Rust perf, emerging projects |
| [`10-agents-and-observability.md`](10-agents-and-observability.md) | MCP servers, agent identity and delegation, vector workloads, observability, overload control |
| [`11-distributed-newsql.md`](11-distributed-newsql.md) | CockroachDB, YugabyteDB, Spock/pgEdge — the "replace Postgres" alternatives |

> This document is the master synthesis. For the decisions taken from it, see
> [`../vision/roadmap.md`](../vision/roadmap.md) and [`../adr/`](../adr/).

---

## 0. Executive summary

**The category is being disrupted at the wrong layer.** Every serious competitor is optimising connection multiplexing — a 2007 problem that PgBouncer solved, for free, well enough. Meanwhile the actual failures in production are about **semantics, policy, fairness and attribution**, and none of those are solved by anyone.

Six findings drive the recommendation:

1. **The incumbents are structurally capped.** PgBouncer is single-threaded and flat at ~36k TPS regardless of client count; multi-core requires running N processes behind `so_reuseport` with a `[peers]` cancel-forwarding protocol — which itself silently breaks query cancellation when misconfigured. It has shipped five CVEs in 2025–2026, including an unauthenticated remote crash via a malformed SCRAM packet and arbitrary SQL execution during authentication.

2. **The newest entrants are fighting over sharding, not correctness.** PgDog has a $5.5M seed, ~3 people, weekly releases, and admits parts of its sharding are experimental — including 2PC that is "eventually consistent… a very high chance of being atomic," not a guarantee, with crash recovery documented as impossible to reason about. Multigres ("Vitess for Postgres") is being built at Supabase by the Vitess co-creator and currently pays 3–8× the latency of peers at low concurrency for its architectural richness. Both are beatable, but not head-on.

3. **Every single top practitioner pain point is a symptom of one missing primitive.** Prepared statements breaking under transaction pooling, RDS Proxy's invisible pinning, `search_path` leaking across tenants, advisory locks dying, `DISCARD ALL` overhead, `LISTEN` requiring a bypass pool, and per-tenant unfairness are *all* the absence of a **per-client session-state ledger** the pooler can see, dedupe, reuse and undo. The second missing primitive is **per-client observability** on top of it. This was reached independently by the pain-point research and by the internals research.

4. **The security boundary has publicly failed at the application layer.** CVE-2026-85620 (CVSS 9.2) bypassed Postgres MCP Pro's "restricted mode" with `SELECT * FROM pg_read_file('/etc/passwd')` — `FuncCall` nodes were checked, `RangeFunction` nodes were not. The architectural conclusion is exactly a proxy thesis: *application-layer allowlists are not a security boundary*. A wire-protocol proxy is the correct enforcement point, and nobody ships one.

5. **The market has moved to agents.** Supabase raised $500M at a $10.5B valuation on agentic infrastructure, reporting >60% of new databases are created by AI agents; MCP has 97M monthly SDK downloads and 28% of the Fortune 500 running servers in production, while 50% of MCP builders name security/access control as their top challenge. Agents are high-cardinality, bursty, untrusted, anonymous and financially unbounded — precisely the workload no existing pooler was designed for.

6. **Managed vendors deliberately do not solve the hard parts.** RDS Proxy has *no session pinning filters at all* on PostgreSQL (MySQL does), pins on any statement >16 KB, has no `CancelRequest`, is VPC-only, caps at 20 proxies/account and can't front read replicas or Aurora Limitless. Hyperdrive's cache **never invalidates on writes** and only supports named prepared statements in two specific drivers. Aurora Limitless is real sharding, not pooling, and explicitly excludes RDS Proxy, read replicas, Secrets Manager and the Data API.

**Recommendation in one line:** build a **protocol-aware PostgreSQL gateway** whose differentiators are (a) session-state virtualisation so transaction pooling stops breaking stateful apps, (b) a bypass-proof SQL policy engine enforced on the wire, and (c) per-principal fairness, quotas and cost attribution — sold first into the agent/MCP and multi-tenant SaaS use cases. Do **not** lead with sharding.

---

## 1. The landscape, in four layers

| Layer | Function | Players | Status |
|---|---|---|---|
| **L1 — Wire-protocol pooler** | Multiplex client connections onto fewer server connections | PgBouncer, pg_doorman, Odyssey, PgCat, PgDog, Supavisor, pgagroal, ProxySQL | Commoditised. Free and good enough on the happy path. |
| **L2 — Routing / sharding** | Parse SQL, route to shard/replica, aggregate | PgDog, SPQR, Citus, Multigres, ShardingSphere, PgCat (experimental) | Contested by two funded teams. Hardest correctness problem. |
| **L3 — Managed data-access edge** | Pooling + auth + caching as a service | RDS Proxy, Hyperdrive, Neon, Supabase, Prisma Accelerate, Cloud SQL/Azure built-in PgBouncer | Locked to clouds; deliberately shallow. |
| **L4 — Application-layer gateways** | Agent/MCP servers, ORM proxies | postgres-mcp, Prisma, Drizzle, Hasura | **Security model just publicly collapsed.** |

### 1.1 Open-source pooler matrix (condensed)

| | Concurrency | Modes | Prepared stmts in txn mode | Session state in txn mode | Auth | Routing/HA/sharding | Observability | Health |
|---|---|---|---|---|---|---|---|---|
| **PgBouncer** | C/libevent, **single-threaded** | session, txn, statement | Opt-in (default 200 since 1.24); `PGBOUNCER_{id}` rewrite; **SQL-level `PREPARE` untracked**; DDL → `cached plan must not change result type` | `SET`/`LISTEN`/`WITH HOLD`/session advisory locks/`PREPARE` **all ✗** | md5, scram, cert, hba, ldap, pam; **no IAM/OAuth** | None built in; DNS/HAProxy; no sharding; replication passthrough 1.23+ | `SHOW *` text console only | 4.4k★, 1.25.2 May 2026, 5 CVEs 2025–26, no corporate owner |
| **PgDog** | Rust/Tokio, multi-threaded | txn (default), session, statement | Yes; global cache + rename; **anonymous `Parse` NOT cached**; `EXECUTE` broadcasts to all shards | GUC tracked+replayed; **advisory locks PIN**; LISTEN/NOTIFY opt-in, **at-most-once** | SCRAM/MD5 + `rds_iam`, azure workload identity, vault; no LDAP/OAuth | LB, RW split, failover, **sharding (partly experimental)** | Admin DB, OpenMetrics, OTEL, async reload | 5.5k★, weekly, **AGPL + paid EE**, $5.5M seed, ~3 people |
| **pg_doorman** | Rust, multi-threaded, one shared pool | txn, session (**no statement**) | Yes **incl. anonymous `Parse`** → `DOORMAN_<N>`, synthesises `ParseComplete`; ~800 MB worst-case plan memory | `SET` outside txn ✗, cross-txn advisory locks ✗, `LISTEN` only inside txn | MD5, SCRAM passthrough, PAM, hba, JWT; **no LDAP/cert/channel binding** | Patroni fallback only; **no sharding** | Prometheus + HDR histograms, admin DB, web UI | 273★, 12 forks, slower cadence, MIT, Ozon Tech |
| **Odyssey** | C, Machinarium coroutines, multi-threaded | session, txn | `pool_reserve_prepared_statement` — **still broken in the field** (`prepared statement "…" does not exist`, open since 2022) | `maintain_params` replay; `pool_pin_on_listen` experimental | Broad: scram, cert, PAM, LDAP, IAM proxy, password passthrough | `balancing` (leastconn, az_aware), lag guard; no sharding; zero-downtime restart | Rich console + exporter | 3.6k★, v1.5.2 Sep 2026, Yandex |
| **pgpool-II** | C, multi-process prefork (`num_init_children` default **32**) | **session-level only — no txn pooling** | Session cache only; parser sees only first statement on a multi-statement line | Routes `LISTEN`/cursors/`LOCK`/`COPY FROM` to primary | Via `pool_hba.conf`; no IAM/OAuth | Watchdog quorum + VIP, statement-level LB, replication modes | `pcp_*` CLI | 442★, 4.7.2 Jun 2026, SRA OSS |
| **Supavisor** | Elixir/BEAM cluster, one owner node per tenant | txn, session, native | Gated behind **default-off** flag; no `max_prepared_statements` knob | Session mode is the stateful path | JWT, tenant records, auth_query | Replicas via API, no query-level RW split; HA via cluster nodes + DNS poll | Prometheus w/ tenant tags | 2.3k★, v2.9.13 Sep 2026, Supabase |
| **pgagroal** | C17, shared memory + io_uring | performance/session/txn pipelines | **Unsupported in txn pipeline**; optional `DEALLOCATE ALL` only | **No `DISCARD ALL`** → `SET`, temp tables, cursors **leak between clients** | hba, auth_query, vault; no LDAP/IAM/OAuth | failover script only; **no LB/sharding** | Prometheus, Grafana, web console | 772★, 2.1.0 Apr 2026, Red Hat heritage |
| **PgCat** | Rust/Tokio | session, txn (**no statement**) | Contradicts its own README; default-off cache; **unreliable in practice** | `SET`/advisory locks ✗; **`LISTEN` unimplemented** | **MD5 client auth only**; no SCRAM/cert | `sqlparser` RW split; sharding **experimental, hash-only** | Prometheus + Grafana | 4.0k★, **last release Nov 2024 — stalled** |

Also checked and excluded: Neon's pooled endpoint is PgBouncer in txn mode; Crunchy Bridge ships managed PgBouncer (`max_prepared_statements` 250); Cloudflare's multi-tenant `cf-pgbouncer` fork was archived June 2026; pg_shardman is abandoned (2017) and is an extension, not a proxy; Heimdall Data is closed-source; KubeDB just provisions upstream poolers.

### 1.2 The performance reality (Feb 2026, 16 vCPU EPYC, PG 17.8, localhost, SELECT-only)

| Client conns | Direct PG | PgBouncer | PgDog | SPQR | Multigres |
|---|---|---|---|---|---|
| 4 | 66,252 | 37,453 | 30,828 | 25,105 | 8,261 |
| 16 | 266,410 | 36,416 | 76,850 | 47,969 | 17,853 |
| 64 | 241,199 | 35,879 | 76,789 | 80,247 | 25,979 |
| Latency overhead @4 | — | +0.047 ms | +0.070 ms | +0.099 ms | +0.424 ms |

Source: [PostgresAI benchmark #72](https://gitlab.com/postgres-ai/postgresql-consulting/tests-and-benchmarks/-/work_items/72).

Four conclusions that shape strategy:

- **PgBouncer is flat forever.** ~36k TPS at 4 clients and at 64. One core, pegged. ClickHouse measured the same ceiling and the workaround: 87k TPS on a single instance (regressing to 77k under load) vs **~336k TPS with a 16-process `so_reuseport` + peering fleet** — a 4× win that operators must assemble by hand.
- **Every proxy is expensive at low concurrency.** PgBouncer adds 78% latency at 4 clients. Nobody has made a proxy that is near-free. PgDog's own pgbench run shows the same shape: libevent beats Tokio at 1–10 connections; Tokio wins only past ~50.
- **Architectural richness currently costs latency.** Multigres is 3–8× slower than peers at c4 because of etcd + pgctld + multipooler + multigateway. Inverting that trade-off (rich features at zero overhead) is an open goal.
- **Nobody benchmarks the hard cases.** Every public benchmark is single-statement `SELECT`. Prepared statements, pinning, DDL, `LISTEN`, failover and agent-style N+1 are unmeasured — so a credible hard-case benchmark suite is itself a strategic asset.

---

## 2. Wire-protocol poolers: what each one actually breaks

**PgBouncer (the baseline).** Documented, self-admitted limits: single-threaded; `cached plan must not change result type` on DDL with the fix being *"run `RECONNECT` on the admin console after the migration"*; SQL-level `PREPARE`/`EXECUTE`/`DEALLOCATE` forwarded untracked; `server_reset_query` deliberately not run in transaction mode; `track_extra_parameters` can only track GUCs Postgres chooses to report; SCRAM secrets unusable for backend login against managed clouds that block `pg_authid`; `so_reuseport` breaks `CancelRequest` without `[peers]` peering; multi-host lists have *"no mechanisms to skip unreachable hosts"*; and it hands out server connections to a dead primary until first use fails, ignoring `server_check_query` errors.

**The state-of-the-art gaps, ranked by how exploitable they are:**

1. **Anonymous/unnamed `Parse` caching is pg_doorman-only.** This is the driver-default path: PgDog explicitly does not cache unnamed statements, and neither does pgagroal or ProxySQL. Everything else caches only *named* statements, which many drivers never use.
2. **`LISTEN`/`NOTIFY` in transaction mode without pinning is PgDog-only** — opt-in, off by default, and **at-most-once** (notifications dropped on connection break). Usually the answer is a second, session-mode pool and an architecture that routes around the pooler: the pg_trickle guide has its background worker *and* its HA relay connect directly to Postgres.
3. **No pooler routes session advisory locks by lock key.** Implementations either **pin** (PgDog, RDS Proxy), **reject** (pg_doorman) or **silently leak** (pgagroal). Advisory-lock migration runners (Alembic) deadlock when many pods start through a transaction-mode pooler.
4. **No product implements read-your-writes.** Routing is `^SELECT` heuristics plus a transaction-state check. Lag sampling is stale by design (ProxySQL defaults `monitor_read_only_interval` to 1500 ms). The only answer today is session pinning after a write, which destroys the pooling benefit.
5. **Replication passthrough is missing** from PgDog, pg_doorman and pgagroal (PgBouncer added it in 1.23).
6. **`DISCARD ALL` on every connection return is a per-transaction round trip** that two independent production repos have filed performance bugs to remove, and Odyssey has an issue asking to *intercept and ignore* client-sent `DISCARD ALL`.
7. **Observability is a pseudo-database.** Heap wrote an entire engineering post because `SHOW POOLS` is cryptic and *"there was even some mismatch between how different people on our team understood the same metrics."* Behind an ELB you lose client IP visibility entirely. No per-client, per-tenant query attribution exists anywhere.
8. **Zero-downtime lifecycle is scripted, not designed.** GitLab's July 2025 incident: PgBouncer nodes left paused after a switchover playbook timed out → ~15 minutes of failing requests. `shutdown wait_for_clients` deletes the admin socket, so you cannot even introspect who is still connected.

---

## 3. Managed and cloud layers: deliberately shallow

**AWS RDS Proxy.** Connection multiplexing, *not* strict transaction mode. **PostgreSQL has no session pinning filters at all** (MySQL does). It pins on prepared-statement `Parse`/`Bind`, `SET`, `SET ROLE`, explicit transactions, temp tables, advisory locks, `LISTEN`, and **any statement over 16 KB**. There is **no "pinned" CloudWatch metric** — operators must infer it from the `ClientConnections` vs `DatabaseConnections` gap. Clients must authenticate with IAM; the proxy reaches the DB via IAM or Secrets Manager. Pricing is **$0.015 per vCPU-hour per registered instance** on top of instance hours (~$175/mo for 16 vCPU) — versus ~$15/mo for a self-managed PgBouncer. Limits: 20 proxies/account, one target instance each, VPC-only, no read-replica targeting, **no `CancelRequest` on PostgreSQL** (Ctrl+C cannot cancel a query), no streaming replication, protocol v3.0 only. AWS's own troubleshooting guidance for prepared-statement-heavy workloads concedes the fix is "PgBouncer in transaction mode."

**Cloudflare Hyperdrive.** Edge handshake termination + regional origin pool + read cache, in transaction mode. Connections are `RESET` on return, so `SET` lasts only a transaction or a single query. **Only named prepared statements in `postgres.js` and `node-postgres` work** — a driver lock-in. **The cache never invalidates on writes**: read-after-write requires configuring a *second, cache-disabled* Hyperdrive. Limits: 10/25 configs, ~20/~100 origin connections, 60 s max query, 50 MB cache, and the docs admit the distributed pool can overshoot its connection cap.

**Amazon Aurora.** Writer/reader DNS endpoints with fast failover that breaks TCP — which is the entire reason RDS Proxy exists. Serverless v2 scales ACUs but still looks like a normal instance, so it does not fix connection churn. **Aurora Limitless is genuine sharding (routers + shards + distributed transactions), not pooling**, and explicitly excludes RDS Proxy, read replicas, custom endpoints, Secrets Manager and the Data API; 1 shard group per cluster, 5 per region, no shard merge, no shard-key updates, no serializable isolation. **Aurora DSQL** replaces connection management entirely (active-active, IAM-only, HTTPS).

**Neon (Databricks).** Compute/storage split: compute streams WAL to safekeepers with quorum commit, pageservers reconstruct at an LSN, object storage holds immutable history and is never on the query path — which makes branching and replica creation metadata operations. Its proxy does what PgBouncer cannot: route connections to the correct branch/compute, **wake scale-to-zero compute**, and terminate WebSocket/HTTP for the serverless driver. Neon also ships a separate PgBouncer endpoint. Its round-trip accounting is the best artifact in the space: a naive path costs **9 round trips to first result**, cut to 4 via TLS 1.3, pipelining `SSLRequest` with the Client Hello, replacing SCRAM (~100 ms CPU, unaffordable in a Worker) with TLS-protected password auth, and `TCP_NODELAY` — but this only works against a proxy that parses `SSLRequest` correctly.

**Supabase.** Shared multi-tenant Supavisor on all plans plus dedicated PgBouncer on paid plans; **both apply the same pool-size setting independently**, and total capacity must satisfy direct + Supavisor + PgBouncer backends under `max_connections` with headroom for Auth/Storage/PostgREST. Transaction mode breaks prepared statements; the documented fix is `prepare: false`. The IPv4 add-on is not dual-stack — it swaps AAAA for A.

**Prisma Accelerate.** Global pool (15+ regions) + edge cache (300+ locations) with TTL/SWR strategies. Raw queries can't be cached, the fluent API breaks, heavy/long queries unsupported. **Accelerate retires 2026-12-01**, and Prisma Postgres has pooling but explicitly no caching.

**Serverless drivers** (Neon, Supabase `prepare:false`/Data API, Cloudflare `connect()`, Vercel, PlanetScale, Drizzle HTTP) all solve "no long-lived TCP in edge runtimes" and all break the same things: interactive transactions over HTTP, prepared statements, session state, `LISTEN`/advisory locks, cursors, and predictable latency. PlanetScale's Postgres driver *is* Neon's.

**PolyScale post-mortem.** PolyScale sold managed, SQL-aware Postgres caching; Neon published a deep dive on its architecture and a connect guide, then absorbed the niche. Its shutdown notice now redirects to a domain marketplace. **Lesson: a standalone transparent Postgres caching proxy is the most absorbable layer in the stack** — exact invalidation is a correctness liability, one stale read is an incident, and the database vendor can bundle equivalent routing for free. This is the single most important negative signal in the research and it directly shapes §5.6 and §6.

### What managed vendors deliberately do not solve

- **No live pinning visibility or pinning policy engine** anywhere. Everyone documents pinning as the user's problem.
- **No safe read cache with write invalidation.** Hyperdrive punts correctness to the application.
- **Prepared-statement semantics are non-portable across every layer** (RDS Proxy pins, Hyperdrive needs specific drivers, PgBouncer rewrites names, pg_doorman remaps anonymous parses).
- **Nothing is multi-cloud or driver-transparent.**
- **Coverage holes:** RDS Proxy is VPC-only and cannot front replicas or Limitless; Azure's built-in PgBouncer excludes the Burstable tier and drops all connections on scale/failover; Cloud SQL's managed pooling is just built-in PgBouncer.

---

## 4. Sharding, routing and HA: where "beyond pooling" actually stands

**Sharding.** Citus is an extension, not a proxy — and its **coordinator is the structural bottleneck**; Citus concedes that in write-heavy cases the coordinator saturates, its remedy is a second coordinator through which **DDL cannot run**, and coordinator failover is manual. Cross-schema foreign keys and joins are unsupported. Rebalancing revealed that disk snapshots could be *inconsistent* under 2PC (a transaction committed on some nodes and merely prepared on others), requiring new block/unblock UDFs. PgCat's sharding is hash-only and experimental — a filterless `SELECT` silently fails to fan out. PgDog's is the most ambitious OSS offering but admits its cross-shard query engine is still being built. Notion **rejected both Citus and Vitess** as "opaque" and hand-rolled 480 logical shards on 32 databases with dual-write migration and minutes of downtime. Shopify sharded in 2015 and then had to invent "pods" because one bad shard broke the whole platform.

**Distributed transactions.** PostgreSQL's own docs say `PREPARE TRANSACTION` is *"not intended for use in applications or interactive sessions"*; a 2026 pgsql-hackers report shows a failed `COMMIT PREPARED` leaving locks visible only by restarting the server. Citus made 2PC mandatory for all multi-shard modifications and requires `max_prepared_transactions` raised on every worker; worst case, 2PC recovery gets stuck and blocks new transactions. PgDog's 2PC is "eventually consistent… a very high chance of being atomic," and its crash recovery docs admit *"it would be impossible to determine the state of each transaction on each shard."* Theory agrees this is not fixable by waiting: FLP rules out fully asynchronous consensus under one unannounced failure, and 2PC is inherently blocking. The practical answer is sagas + outbox, with hand-written compensations and lost isolation.

**Read/write splitting.** Crude by construction: parse, look for `SELECT`, check transaction state, route. ProxySQL warns blanket `^SELECT` rules "do not use in production" and prescribes hand-curated digest rules. **No mainstream proxy implements read-your-writes.** The mechanism exists — tag the session with the write LSN and read only replicas that have replayed past it — and PostgreSQL 19 adds a server-side `WAIT FOR` LSN primitive proxies could delegate to. HeliosProxy documents lag-aware routing; nobody else ships it.

**Failover.** Measured reality: ProxySQL unplanned primary SIGKILL → **median 1900 ms** to resume writes (zero errors across 1.76M transactions); planned `OFFLINE_SOFT` switchover → **median 1100 ms with ~200 ms of actual disruption**; Patroni+ProxySQL → 10,000 ms window with zero app errors, while a Patroni+HAProxy baseline **killed pgbench outright on the connection cut**. DNS failover is the sum of independent delays: one measured drill came to **~2–4 minutes user-visible** despite a "60 s TTL," and Route 53 returns the primary record even when all records are unhealthy. Consul's default DNS consistency is `stale` with **no upper bound**, so a partitioned follower can advertise a stale primary. Patroni's async mode can lose everything written in the last `ttl` seconds plus `maximum_lag_on_failover` bytes, on an unrecoverable forked timeline. AWS blue/green **drops connections in both environments** and can surface `AdminShutdown` errors through RDS Proxy.

**Multi-tenancy.** Three models: schema-per-tenant via proxy, database-per-tenant (isolates hardest, explodes connections) and shared tables + tenant column (needs RLS enforced *in the database* — a proxy that rewrites queries but forgets RLS is a cross-tenant leak). Multigres built **max-min fair per-user pools** specifically because raw-demand allocation is gameable: spawn ten copies of a query, claim ten slots. Per-tenant QoS essentially does not exist in OSS — PgBouncer's per-user limits are connection counts only.

---

## 5. Practitioner pain points, ranked by severity × frequency

| # | Pain | Evidence | Score |
|---|---|---|---|
| 1 | **Prepared statements break under transaction pooling** | 12+ independent sources. SQLAlchemy maintainer: *"transaction-level pooling interacting with the prepared statement cache is a long recurring nightmare for us."* pgjdbc maintainer: *"from the client's point of view they have one session and named prepared statements are session objects."* One team shipped a 28-commit patch; another saw a 1000× slowdown forcing `prepareThreshold=0`; Diesel hits `unnamed prepared statement does not exist` when parse/bind straddle transactions. | 5×5 |
| 2 | **RDS Proxy pinning no-ops pooling and is near-undiagnosable** | 10+ sources. Prisma: *"It looks like Prisma sets these whenever it creates a new connection which causes the Proxy to pin all connections until released rendering the proxy useless."* Even **pgAdmin pins**. Only 3 CloudWatch counters exist; a top re:Post question reports conns that never fall and *"haven't pinpointed the cause."* | 5×5 |
| 3 | **No session-state model** — `LISTEN`, advisory locks, temp tables, cursors, `SET`/`search_path` | 10+ sources, including a **cross-tenant `search_path` leak** where `postgres_fdw` leaves `search_path` set and PgBouncer in transaction mode resolves to the wrong schema. Django had to disable `queryset.iterator()` because server-side cursors don't survive pooling. The most-quoted wish: *"a 'please serialize everything… from this session to disk and load it back when necessary'."* | 5×4 |
| 4 | **Observability: no per-client/tenant attribution** | 6+ sources. Heap wrote a deep dive because of metric ambiguity; behind an ELB client IP is invisible; no Prometheus/OTel in several projects. | 4×5 |
| 5 | **Single-threaded CPU ceiling** | 6+ sources, quantified: 87k TPS single instance regressing to 77k, one core at 97% while a 16-vCPU box sits <10% used; 336k TPS with a 16-process fleet. `so_reuseport` + peering is *"not super easy to set up,"* pool limits are **not shared** across processes, and cancel requests silently no-op without peering. | 5×3 |
| 6 | **Zero-downtime reload/restart/failover** | 10+ sources: restart drops idle client connections, login rejected after `RELOAD`, `default_pool_size` not applied on reload, invalid config on `RELOAD` loses the active config, k8s pod-restart connection errors, online reboot broken under systemd. | 4×4 |
| 7 | **Multi-tenant fairness: no quotas, gameable allocation** | 6+ sources. Multigres built fair pools because greedy clients starve others; per-user pool sizing requested since 2017; `max_client_conn` is global with no per-tenant control. | 4×4 |
| 8 | **`DISCARD ALL` per-transaction cost + `server_idle_timeout` killing live clients** | 6+ sources; two production repos filed bugs to remove the reset round trip; Celery crashes when PgBouncer closes idle connections. | 3×4 |
| 9 | **Idle-in-transaction/long transactions exhaust the pool** | 4+ sources; no pooler-level equivalent of `idle_in_transaction_session_timeout` that actually works end to end. | 4×3 |
| 10 | **Migrations/DDL/`pg_dump` need a bypass path** | 4+ sources. Prisma's top-voted issue (59 upvotes): *"you need to use a non pooled connection URL for running Migrations. That is inconvenient."* Advisory-lock migration runners deadlock. | 3×4 |
| 11 | **Serverless connection storms and restart login floods** | 4+ sources; *"connection pools don't work well with Lambda… they came up with another chargeable service, RDS Proxy, to fix the problem created by Lambda."* | 3×3 |
| 12 | **Per-query / per-vCPU pricing seen as punitive** | 6+ sources; *"60k queries? I burn through that in an hour. All it takes is the Google bot and some shitty AI scraper."* | 3×3 |

**The unifying insight**, reached independently by the pain-point and internals research: items 1, 2, 3, 8, 9 and 10 are all one missing primitive — **a per-client session-state ledger** — and items 4 and 7 ride on the second, **per-client observability**.

---

## 6. Areas to innovate

Ranked by (defensibility × willingness-to-pay) ÷ time-to-ship. Each is something no shipping product does well.

### 6.1 Session-state virtualisation — kill pinning instead of documenting it

**Nobody solves this.** Transaction mode forbids state; RDS Proxy silently pins; PgDog pins advisory locks; pg_doorman rejects them; pgagroal leaks them. Every stateful extension and framework routes *around* the pooler.

**Build:** a per-client **session image** the proxy maintains and replays onto whichever server connection is checked out.
- Track what the client **asked for** (parse `SET`, `SET LOCAL`, `SET ROLE`, `search_path`, `PREPARE`, temp-table DDL, `LISTEN`), not what the server reports back — this crosses the wall `track_extra_parameters` cannot.
- Apply the image as **one batched, pipelined restore** on checkout. Never pay a round trip per GUC.
- **Advisory locks as a proxy-level lease manager**: virtualise `pg_advisory_lock` with heartbeats and re-acquisition across server switches, and **route by lock key** so two clients contending on the same key land on the same backend. Nobody does this; it is the exact reason pg_trickle's HA relay bypasses the pooler and why Alembic deadlocks.
- **`LISTEN`/`NOTIFY` fan-out**: maintain a small number of long-lived server listeners at the proxy, fan out to multiplexed clients, and offer **exactly-once** delivery by binding notification delivery to the client's transaction — beating PgDog's opt-in, at-most-once implementation.
- **Temp tables**: per-client schema namespacing where possible; otherwise *minimal* pinning with an eviction-cost model — pin only while the state exists, release the instant it's dropped.
- **Fail loud and correct** when a statement uses state the proxy cannot virtualise. Never hand a client a dirty session. (`pgagroal`'s silent leak is the anti-pattern.)

**Measurable outcome:** pinning ratio → 0; `LISTEN`, advisory locks and temp tables work in transaction mode.

### 6.2 Plan-invalidation protocol — make DDL safe through the pooler

`ERROR: cached plan must not change result type` is a live production failure class, and the documented remedy is dropping connections during deploys.
- Key the prepared-statement cache on `(normalised SQL hash, param type OIDs, relation OID set, rowtype version)`; re-`Parse` transparently when any component changes.
- **DDL is not carried by logical decoding** — the proxy must synthesise its own DDL event stream from (i) the wire stream, which it uniquely sees in full, (ii) server-side `ddl_command_end` event triggers, and (iii) catalog-fingerprint polling as an out-of-band fail-safe.
- Track **anonymous `Parse`** too — the driver-default path that only pg_doorman handles, and do it with correct DDL invalidation and per-tenant partitioning, which pg_doorman lacks.
- Track SQL-level `PREPARE`/`EXECUTE`/`DEALLOCATE`, which PgBouncer forwards blind.

**Outcome: zero-pin, zero-drain schema migrations.** A headline capability no competitor can claim.

### 6.3 A data path that is actually near-free

Every proxy is a latency tax at low concurrency (PgBouncer +78% at 4 clients). PgBouncer is flat at ~36k TPS forever.
- **Bypass/splice mode:** once a session is assigned and no policy requires inspection, hand the bytes off — `splice(2)`/`sendfile` or fd passing to a thread-per-core worker so bulk traffic never touches a shared event loop. Degrade to inspected mode only when state or policy demands it.
- **Thread-per-core** (monoio/glommio-style) with per-core pools, plus `SO_REUSEPORT`, so no cross-core synchronisation and no shared allocator contention on the hot path.
- **`io_uring`** for batched syscalls (which is also PostgreSQL 18's own AIO path); arena allocation; zero-copy message parsing.
- **Parse lazily and once.** PgDog measured protobuf AST conversion dominating its parser and got parse 613→3,357 q/s and deparse 759→7,319 q/s (+25% pgbench) by switching to direct C→Rust FFI. The rule: hash SQL text, parse once per unique statement, never per `Bind`/`Execute`, and skip SQL entirely when routing needs only the `ReadyForQuery` status byte.
- **Cancel routing as a first-class primitive.** `CancelRequest` arrives on a *separate* connection, so it breaks under `SO_REUSEPORT`, and PostgreSQL 18's variable-length cancel keys (to 256 bits) break the fixed 12-byte assumption. Solve it properly instead of via a peering protocol.
- Publish the **hard-case benchmark suite** (prepared statements, DDL, failover, mixed OLTP+analytics, agent N+1). Every public benchmark today is single-statement `SELECT`.

### 6.4 Protocol-enforced policy — the security boundary in the right place

CVE-2026-85620 (CVSS 9.2) let `SELECT * FROM pg_read_file('/etc/passwd')` through a validator that checked `FuncCall` but not `RangeFunction`. The lesson is architectural, and a wire proxy is the correct answer — it sees plaintext SQL with no extra privileges, which eBPF cannot (socket-level tracing sees ciphertext and needs root uprobes inside the server binary).

- Deny-by-default, capability-based policy enforced on **semantics** using the real PostgreSQL grammar (`libpg_query`), covering `FROM`-clause functions, CTEs, `DO` blocks, dynamic SQL, `COPY … FROM PROGRAM`, `lo_import`, `dblink`, `postgres_fdw`.
- Typed capabilities (`read:<table>`, `write:<table>`, `ddl`, `copy`, `filesystem`), config-as-code with dry-run and diff.
- Inject `SET LOCAL role` / RLS context / column masks so enforcement sits below the application. (Prior art exists in fragments: `pg_ddm` does masking plus pooling; `proxy-monster` does lineage-aware masking under Cedar with a tamper-evident audit trail; HeliosProxy has a WASM plugin ABI and a residency router.)
- **Per-principal identity end to end.** PostgreSQL 18 shipped native OAuth (RFC 6750 bearer tokens, OIDC discovery, `scope`, IdP→role mapping, `delegate_ident_mapping`); RFC 8693 token exchange plus MCP's OAuth 2.1 rules permit **per-agent, audience-bound** database credentials. Today agents get long-lived DSNs that leak through MCP client configs and chat history.
- Enforce on the **simple query protocol too** and fail closed on parser uncertainty.
- Audit every decision: principal, policy, fingerprint, rows, cost, trace id.

### 6.5 Fairness, admission control and cost attribution

RDS Proxy has **no per-user pool and no quota**. Multigres is the only project that took fairness seriously (max-min fair per-user pools) because raw-demand allocation is gameable.
- Per-principal token buckets, weighted fair queueing, priority classes (interactive ≫ batch ≫ analytics ≫ migration).
- **Adaptive concurrency limits from Little's Law** on observed latency, with Vegas/Gradient2-style control (Netflix `concurrency-limits`), rather than static `default_pool_size`.
- Google SRE's overload discipline: per-customer quotas, criticality classes (`SHEDDABLE` batch vs `CRITICAL` live), bounded retry budgets, and the recognition that **connection churn itself is load**.
- Typed, retryable shedding errors instead of mysterious timeouts.
- **Chargeback-grade attribution** from a fingerprint→`queryid` map (so it works without `pg_read_all_stats`): per-principal CPU time, rows read, buffers, WAL bytes, result bytes.

### 6.6 Dependency-tracked caching — and an honest reading of the PolyScale lesson

Hyperdrive's cache never invalidates on write. PolyScale tried transparent caching as a standalone business and was absorbed. **The correct conclusion is not "caching is impossible" — it is "caching is only defensible as a feature of something bigger, and only if it is snapshot-correct."**
- Invalidate on real dependencies: parse → resolve relations/columns → apply or invalidate per commit via logical decoding (the `pgcache` model), with the primary key known.
- **Refuse to cache** `volatile` functions (`now()`, `random()`, `nextval()`) and anything whose hit would not be valid at the *reader's* MVCC snapshot, including role/RLS, `search_path` and GUC dependence.
- Never serve a cached read inside a transaction that has already written — read-your-writes enforced at the proxy, not punted to a second endpoint.
- Handle DDL, which logical decoding does not carry (§6.2).
- Fingerprint-normalise agent-generated SQL so semantically identical queries with different literal formatting share entries.

### 6.7 Read-your-writes and lag honesty as a primitive

No mainstream proxy implements it. Track the write LSN per client, admit reads to a replica only when its replay LSN has caught up, offer per-query consistency levels (`strong`/`session`/`eventual`), and delegate to **PostgreSQL 19's `WAIT FOR` LSN** where available. Expose lag as an SLO signal so routing is auditable rather than magical. (HeliosProxy's `max_replica_lag_ms` is the only shipping analogue.)

### 6.8 Failover and lifecycle with zero dropped work

Measured state of the art still leaks ~200 ms of real errors on a *planned* switchover, and DNS failover is realistically 2–4 minutes.
- Participate in failover: quiesce → drain in-flight transactions → promote → resume, with **no client-visible errors during planned switchover**.
- Auto-retry read-only and idempotent transactions; for writes, require a client idempotency key and dedupe at the proxy so exactly-once replay is opt-in and safe.
- Never hand out a connection to a demoted primary (PgBouncer currently does, until first use fails).
- **Live certificate rotation and config hot-swap with no connection recycling.** PgBouncer recycles TLS connections on TLS config change and has repeatedly shipped reload bugs; pg_doorman requires a restart for client-facing certs.
- Publish a **formally specified router** — a TLA⁺-checked transaction-pinning and GUC-replay state machine — as the correctness argument. Nothing in this category has ever had a specification.

### 6.9 Observability and control plane as the product

What a protocol-aware proxy sees that nothing else can: plaintext SQL with no privileges, plus exact per-client attribution.
- Per-principal query attribution, tail-latency histograms, pool-saturation timelines, and "who is holding the pool hostage right now."
- **Protocol-native trace context**: carry trace IDs in a proxy-side index keyed by `(connection, Bind)` rather than appending SQL comments — SQLCommenter changes the query string and **pollutes plan/prepared caches**, making every unique trace ID a new parse.
- Proxy-side plan capture (`auto_explain`-style plan sampling) without touching server configuration.
- Config as code with validation, dry-run, diff, canary, instant rollback — not `SIGHUP`, and never a pseudo-database console as the only interface.
- Native OpenTelemetry + Prometheus.

### 6.10 Safe extensibility — a platform, not a feature list

PgDog ships native Rust plugins; PgCat has a plugin RFC; HeliosProxy already demonstrates a WASM plugin ABI. **Build the plugin surface on WASM (wasmtime)**: stable ABI, hard per-request CPU and memory budgets, no blocking, graceful degradation, per-tenant sandboxing so a customer's policy cannot take down the proxy. This is what turns a pooler into a platform others build on. (Prior art to study and beat: `proxy-monster`'s Cedar-based, lineage-aware masking.)

### 6.11 Agent-native data access — the wedge

>60% of new databases are agent-created; MCP is the integration surface; half of MCP builders say security is their top challenge.
- **Terminate MCP at the proxy** and expose safe tools (`query`, `describe_schema`, `explain`) backed by the **same** policy engine as wire clients. One policy, two protocols. Nobody has this.
- Per-agent identity, scopes, budgets and rate limits; block runaway loops and accidental full-table scans via `statement_timeout`, row ceilings and cost-based admission.
- Permission-filtered, bounded schema context for the model, so it cannot infer tables it has no right to read.
- **Vector-aware admission control**: pgvector's HNSW/IVFFlat scans are memory- and latency-spiky (bounded by `hnsw.max_scan_tuples`), shared ANN indexes let one tenant degrade another's recall, and iterative scans can explode. Classify ANN queries from the plan and queue them separately.
- Semantic caching for repeated LLM-generated SQL.
- Defend against the known agent attack classes: tool poisoning, rug-pull description mutation, cross-server shadowing, indirect prompt injection through data, and text-to-SQL backdoors (ToxicSQL).

### 6.12 Economics, packaging and coverage holes

- Attack RDS Proxy's per-vCPU pricing from below *and* price on per-tenant metering rather than instance size.
- **Embedded/sidecar mode**: a Rust library or per-pod sidecar sharing the same config and policy engine, removing a network hop for Kubernetes and serverless. Nobody offers proxy-grade semantics in-process.
- **Multi-cloud and driver-transparent** — no vendor is either. Work with every driver rather than requiring named prepared statements in two of them.
- **Data-residency routing as a compliance product**: HeliosProxy proves the mechanism (return a clean `ErrorResponse` when no in-region replica exists); nobody ships it with a real policy language.
- **Pool arithmetic as a product**: Supabase's own docs require users to hand-compute direct + Supavisor + PgBouncer backends against `max_connections`. Computing and enforcing that safely, with headroom, is a feature nobody sells.

---

## 7. Recommended product shape

**Do not compete head-on at L1 (raw pooling) or L2 (sharding).** PgBouncer is free and good enough on the happy path; PgDog and Multigres are funded and already fighting over sharding, which is also the hardest correctness problem in the space.

### Positioning

> **A protocol-aware PostgreSQL gateway that makes transaction pooling safe for stateful applications, makes policy enforcement impossible to bypass, and attributes every query to the agent or tenant that issued it.**

Not "a faster PgBouncer." Speed is table stakes — a claim, not a product.

### Build order

1. **Foundation (must be excellent, or nothing else is credible).** Multi-core thread-per-core data path with a bypass fast path; transaction pooling with correct named *and* anonymous prepared-statement handling; cancel routing; parity admin API, Prometheus/OTel; rolling reload and live cert rotation.
2. **Differentiator #1 — session-state virtualisation (§6.1) + plan-invalidation protocol (§6.2).** The "runs everything PgBouncer breaks" story, objectively measurable as pinning ratio → 0 and migrations without draining.
3. **Differentiator #2 — protocol-level policy engine (§6.4) + per-principal fairness and attribution (§6.5).** The paid enterprise value and the strongest wedge into regulated and multi-tenant buyers.
4. **Differentiator #3 — MCP/agent termination (§6.11).** Ride the fastest-growing traffic source with a safety story no incumbent can tell.
5. **Later:** read-your-writes (§6.7), zero-downtime failover (§6.8), snapshot-correct caching (§6.6), WASM plugins (§6.10), and only then sharding — if customers pull hard.

### Moats

- **Correctness.** Session virtualisation and DDL-safe plan invalidation are multi-quarter engineering problems a PgBouncer fork cannot shortcut, and both are *measurable*.
- **The parser and policy engine.** Deep `libpg_query` integration plus a capability model becomes a data asset (policy libraries per ORM/framework) with real switching costs.
- **Attribution data.** Once every query is attributed to a principal with cost, the proxy becomes the system of record for database spend — the natural place to add budgets, approvals and forecasting.
- **Trust artifacts.** In a category with five PgBouncer CVEs in two years and a CVSS 9.2 MCP bypass, publish the security test corpus and a TLA⁺ router specification. Demonstrable correctness is marketing here.

### Risks to respect

- **PolyScale is the cautionary tale.** A standalone transparent caching/routing proxy is the most absorbable layer in the stack; database vendors bundle equivalent routing for free. Caching must be a *feature* of a product whose main value is policy, correctness and attribution — never the product itself.
- PgBouncer is free, ubiquitous and improving. The paid value must live in policy, operations, attribution and agents, **not** in pooling.
- Session-state virtualisation has genuinely hard corners (extension GUCs, `search_path`, `SET ROLE`, RLS interaction, PL/pgSQL dynamic SQL). Fail closed, never corrupt silently.
- Tokio-style work-stealing loses to libevent at low concurrency. The bypass path is what makes the performance claim defensible.
- Sharding is a knife fight against a funded team shipping weekly, and distributed correctness is provably constrained (FLP, blocking 2PC). Do not lead with it.
- Parsing every statement is expensive. Lazy parsing keyed on SQL hash is an architectural requirement, not an optimisation.
- Licensing: PgDog is AGPL-3.0 core with a paid EE. Choose the licence deliberately — it determines whether platforms can embed you.

---

## Appendix A: Key primary sources

**Protocol and PostgreSQL**
- PgBouncer config and self-documented limits: https://www.pgbouncer.org/config.html
- PgBouncer changelog (1.21–1.25.2, five CVEs): https://www.pgbouncer.org/changelog.html
- PgBouncer feature matrix (session features "Never" in txn mode): https://www.pgbouncer.org/features.html
- PostgreSQL wire protocol flow: https://www.postgresql.org/docs/current/protocol-flow.html
- PostgreSQL 18 release notes (protocol 3.2, OAuth, cancel keys): https://www.postgresql.org/docs/18/release-18.html
- PostgreSQL 18 OAuth: https://www.postgresql.org/docs/18/auth-oauth.html
- Logical replication restrictions (no DDL): https://www.postgresql.org/docs/current/logical-replication-restrictions.html
- `PREPARE TRANSACTION` warning: https://www.postgresql.org/docs/current/sql-prepare-transaction.html
- libpg_query: https://github.com/pganalyze/libpg_query

**Competitors**
- PgDog vs PgBouncer benchmark: https://pgdog.dev/blog/pgbouncer-vs-pgdog
- PgDog funding: https://pgdog.dev/blog/our-funding-announcement/
- PgDog 2PC and crash recovery: https://docs.pgdog.dev/features/sharding/2pc/
- pg_doorman (anonymous Parse remapping): https://ozontech.github.io/pg_doorman/tutorials/prepared-statements.html
- Odyssey internals: https://github.com/yandex/odyssey/blob/master/docs/development/internals.md
- Multigres architecture: https://multigres.com/docs/architecture
- Multigres fair per-user pools: https://multigres.com/blog/per-user-pools-that-share-fairly
- CMU talk, Sugu Sougoumarane at Supabase: https://db.cs.cmu.edu/events/pg-vs-world-multigres-sugu-sougoumarane/
- pgagroal pipelines: https://pgagroal.github.io/doc/PIPELINES.html
- ProxySQL extended query protocol: https://www.proxysql.com/documentation/postgresql-extended-query-protocol
- ProxySQL failover primer (measured numbers): https://proxysql.com/blog/proxysql-postgresql-failover-primer/

**Managed / cloud**
- RDS Proxy limits: https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/rds-proxy.html
- RDS Proxy pinning: https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/rds-proxy-pinning.html
- RDS Proxy limitations runbook: https://devopsity.com/runbooks/aws-rds-proxy-configuration-limitations/
- Hyperdrive how it works: https://developers.cloudflare.com/hyperdrive/concepts/how-hyperdrive-works/
- Hyperdrive query caching (no write invalidation): https://developers.cloudflare.com/hyperdrive/concepts/query-caching/
- Neon architecture: https://neon.com/docs/introduction/architecture-overview
- Neon round-trip optimisation: https://neon.com/blog/quicker-serverless-postgres
- Supabase pooling and limits: https://supabase.com/docs/guides/database/connecting-to-postgres/pooling-and-limits
- Prisma Accelerate known limitations: https://www.prisma.io/docs/accelerate/more/known-limitations
- Aurora blue/green switching: https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/blue-green-deployments-switching.html

**Failover / HA**
- Patroni replication modes (async loss bounds, quorum): https://patroni.readthedocs.io/en/latest/replication_modes.html
- Patroni watchdog: https://patroni.readthedocs.io/en/latest/watchdog.html
- Patroni DCS failsafe mode: https://patroni.readthedocs.io/en/latest/dcs_failsafe_mode.html
- pg_auto_failover architecture: https://pg-auto-failover.readthedocs.io/en/main/architecture.html
- GitLab paused-PgBouncer incident: https://gitlab.com/gitlab-com/gl-infra/production/-/work_items/20150
- Route 53 failover pitfalls: https://hidekazu-konishi.com/entry/route_53_health_check_failover_pitfalls.html

**Security**
- CVE-2026-85620 analysis (MCP allowlist bypass): https://forkast.news/postgres-mcp-pro-restricted-mode-bypass-exposes-the-gap-in-ai-database-security/
- MCP security best practices: https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices
- ToxicSQL: https://arxiv.org/abs/2503.05445

**Scaling / performance**
- PostgresAI latency benchmark #72 (Feb 2026): https://gitlab.com/postgres-ai/postgresql-consulting/tests-and-benchmarks/-/work_items/72
- ClickHouse PgBouncer single-thread analysis: https://clickhouse.com/blog/pgbouncer-clickhouse-managed-postgres
- Notion sharding Postgres: https://www.notion.com/blog/sharding-postgres-at-notion
- Shopify pods architecture: https://shopify.engineering/a-pods-architecture-to-allow-shopify-to-scale
- PgDog parser FFI optimisation: https://pgdog.dev/blog/replace-protobuf-with-rust
- Netflix concurrency-limits: https://github.com/Netflix/concurrency-limits
- Google SRE handling overload: https://sre.google/sre-book/handling-overload/
- The Tail at Scale: https://dl.acm.org/doi/10.1145/3046682

**Pain-point evidence** — full permalinked quotes in `pooler-pain-points-research.md`, including pgbouncer issues #695, #653, #1038, #1021, #802, #297, #241, #655, #166, #103, #1495, #1288, #585, #1311, and Prisma #5866 / #6485.
