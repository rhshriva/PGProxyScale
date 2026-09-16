# Research base

Dated evidence. These documents are **not** living docs — they are the source material behind
[`../vision/roadmap.md`](../vision/roadmap.md) and the ADRs. Every non-obvious claim carries a link
to a primary source. Where a fact could not be verified, the document says so rather than inferring.

| # | Document | Covers |
|---|---|---|
| 00 | [Landscape and innovation map](00-landscape-and-innovation-map.md) | **Master synthesis.** Executive summary, four-layer landscape, gap analysis, 12 innovation areas, recommended product shape, full source list. |
| 01 | [Pooler comparison](01-pooler-comparison.md) | 10-column technical matrix for all self-hostable poolers, plus per-product failure modes. |
| 02 | [PgDog / pg_doorman / pgagroal / ProxySQL](02-pgdog-doorman-agroal-proxysql.md) | Deep dive on the newest entrants and the closest competitors. |
| 03 | [Odyssey / pgpool-II / Supavisor](03-odyssey-pgpool-supavisor.md) | The established alternatives. |
| 04 | [Cloud: AWS and Cloudflare](04-cloud-aws-cloudflare.md) | RDS Proxy, Aurora / Limitless / DSQL, Hyperdrive, GCP and Azure pooling. |
| 05 | [Cloud: serverless vendors](05-cloud-serverless-vendors.md) | Neon, Supabase, Prisma Accelerate, serverless drivers, and the PolyScale post-mortem. |
| 06 | [Sharding, routing, distributed transactions](06-sharding-routing-transactions.md) | Citus, PgDog/PgCat sharding, read/write splitting, 2PC, multi-tenant isolation. |
| 07 | [Failover and HA](07-failover-and-ha.md) | Patroni, DNS/VIP, pg_auto_failover, ProxySQL, split-brain, measured failover numbers. |
| 08 | [Practitioner pain points](08-practitioner-pain-points.md) | 12 pain themes with real user quotes, permalinks and a severity × frequency ranking. |
| 09 | [Innovation frontier](09-innovation-frontier.md) | Wire protocol, parsing, caching, transports, auth, observability, Rust performance, emerging projects. |
| 10 | [Agents and observability](10-agents-and-observability.md) | MCP servers, agent identity and delegation, vector workloads, observability and overload control. |
| 11 | [Distributed / NewSQL](11-distributed-newsql.md) | CockroachDB, YugabyteDB, Spock/pgEdge and the "replace Postgres" alternatives. |

## Method notes

- Sources are official documentation and release notes first, then maintainer commentary, mailing
  lists, GitHub issues, engineering blogs, benchmarks, and finally community threads — in that order
  of preference.
- All fetched web content was treated as untrusted data: facts were extracted, instructions ignored.
- Two caveats recorded by the research: Reddit's API blocks non-browser clients, so Reddit evidence
  came via the PullPush archive and is cited by permalink; and unauthenticated GitHub API rate limits
  (60/hr) capped the depth of comment mining near the end of one pass.
- **Benchmark caveat:** the headline latency numbers come from a single-host, SELECT-only, localhost
  benchmark. They are directionally useful and are not a substitute for the Phase 0 hard-case suite.
