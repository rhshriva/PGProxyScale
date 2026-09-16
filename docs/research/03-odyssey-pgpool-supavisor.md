# PostgreSQL Connection Pooler Competitive Research: Odyssey vs pgpool-II vs Supavisor

*All facts sourced inline; fetched content treated as untrusted data.*

## 1. Language, runtime & concurrency

- **Odyssey (Yandex)** — C, multi-threaded, built on the custom [Machinarium](https://github.com/yandex/odyssey/blob/master/docs/development/internals.md) coroutine engine: each thread is a pthread running a coroutine scheduler over `epoll(7)`; no raw mutexes, synchronization is message-passing. Threads: `system` (router, servers, console, cron) + `worker_pool` of N workers; each worker hosts thousands of client coroutines. `workers 1` is a special optimized single-thread mode. [Architecture](https://yandex.github.io/odyssey/), [internals](https://github.com/yandex/odyssey/blob/master/docs/development/internals.md)
- **pgpool-II** — C, **multi-process**: `num_init_children` preforked processes (default **32**), each owning its own backend connection cache; `process_management_mode` dynamic/static. [Connections doc](https://www.pgpool.net/docs/latest/en/html/runtime-config-connection.html)
- **Supavisor (Supabase)** — **Elixir/Erlang on the BEAM**, co-developed with José Valim and Dashbit; each client is an Erlang process. [1M blog](https://supabase.com/blog/supavisor-1-million), [repo](https://github.com/supabase/supavisor)

## 2. Pooling modes

- **Odyssey**: `session` and `transaction` are documented for use; the config table accepts `pool` values `session | transaction | statement`, plus `pool_reserve_prepared_statement` for transaction mode. [pooling.md](https://github.com/yandex/odyssey/blob/master/docs/features/pooling.md), [rules.md](https://github.com/yandex/odyssey/blob/master/docs/configuration/rules.md)
- **pgpool-II**: **session-level only** — reuses a cached connection per (user, database, protocol version) inside a child process (`connection_cache`, `max_pool` default 4). There is no transaction or statement pooling. [Connection pooling doc](https://www.pgpool.net/docs/latest/en/html/runtime-config-connection-pooling.html)
- **Supavisor**: `mode_type` ∈ `transaction | session | native`; `native` proxies as if directly connected and "is typically needed to run migrations." [Pool modes](https://supabase.github.io/supavisor/configuration/pool_modes/)

## 3. Transaction-level prepared statements

- **Odyssey**: supported in transaction pooling via `pool_reserve_prepared_statement yes`; `server_pstmt_cache_size` bounds reserved statements per server (best-effort SIEVE eviction on release); `server_drop_on_cached_plan_error` drops the server on `ERROR 0A000 cached plan must not change result type`; a `pool_discard_query` containing `DEALLOCATE ALL` disallows prepared statements. Default `pool_discard` runs `DISCARD ALL`. [rules.md](https://github.com/yandex/odyssey/blob/master/docs/configuration/rules.md), [pooling.md](https://github.com/yandex/odyssey/blob/master/docs/features/pooling.md)
- **Odyssey failure mode**: [issue #477](https://github.com/yandex/odyssey/issues/477) (opened 2022-11-23, still open, 6 comments) reports `ERROR: prepared statement "2caa56bd" does not exist` with pgjdbc 42.3.1 + YugabyteDB when `pool_reserve_prepared_statement yes` and `pool_smart_discard yes`.
- **pgpool-II**: because pooling is session-scoped, extended-protocol `PREPARE`/`EXECUTE` normally survive, but the parser has hard limits. In the thread ["Prepared statements over pgpool ?"](https://www.pgpool.net/pipermail/pgpool-general/2023-July/008870.html), a user on 4.4.3 gets `FATAL: unable to bind / DETAIL: cannot get parse message "mark_rels_by_way"`; Tatsuo Ishii replies that pgpool-II cannot handle multi-statement queries on one line — only the first `PREPARE` is parsed — ["Currently there's no workaround"](https://www.pgpool.net/pipermail/pgpool-general/2023-July/008884.html). Other restrictions: multi-statement queries are always sent to the primary; extended protocol forces a re-parse on the primary if a parsed SELECT must move there; and SQL type commands cannot be used in extended query mode. [Restrictions](https://www.pgpool.net/docs/latest/en/html/restrictions.html), [load balancing](https://www.pgpool.net/docs/latest/en/html/runtime-config-load-balancing.html)
- **Supavisor**: prepared statements work in session mode; in transaction mode **named** prepared statements require the `named_prepared_statements` flag — `NAMED_PREPARED_STATEMENTS_ENABLED` (default `false`) or per-tenant `feature_flags`. There is **no `max_prepared_statements` parameter** in the docs; the toggle above is the real knob. [FAQ](https://supabase.github.io/supavisor/faq/), [env vars](https://supabase.github.io/supavisor/configuration/env/)

## 4. Session semantics: LISTEN/NOTIFY, locks, cursors, COPY

- **Odyssey**: `pool_pin_on_listen yes` (experimental, default no) pins a client after `LISTEN`. Default discard resets state with `SET SESSION AUTHORIZATION DEFAULT; RESET ALL; CLOSE ALL; UNLISTEN *; SELECT pg_advisory_unlock_all(); DISCARD PLANS; DISCARD SEQUENCES; DISCARD TEMP;`. Also `application_name_add_host`, `maintain_params`, `pool_discard`, `pool_smart_discard`. [rules.md](https://github.com/yandex/odyssey/blob/master/docs/configuration/rules.md)
- **pgpool-II**: `LISTEN/UNLISTEN/NOTIFY`, `DECLARE/FETCH/CLOSE`, `SHOW`, `LOCK`, `COPY FROM` go to the **primary only**; `COPY TO STDOUT` may be balanced. `reset_query_list` default `'ABORT; DISCARD ALL'`. `set_config()` goes to the primary only, so parameter values diverge across standbys (use `SET`). [Load balancing](https://www.pgpool.net/docs/latest/en/html/runtime-config-load-balancing.html), [restrictions](https://www.pgpool.net/docs/latest/en/html/restrictions.html)
- **Supavisor**: session mode is the stateful path; transaction mode reaps idle pool connections after 5 minutes. [Supavisor FAQ](https://supabase.com/docs/guides/troubleshooting/supavisor-faq-YyP5tI)

## 5. Authentication

- **Odyssey**: per-route `none | block | clear_text | md5 | scram-sha-256 | cert`, PAM (`auth_pam_service`), LDAP (`ldap_endpoint`, `ldap_storage_credentials`), `auth_query`, `password_passthrough`, external auth modules, Yandex MDB IAM proxy (`enable_mdb_iamproxy_auth`). [rules.md](https://github.com/yandex/odyssey/blob/master/docs/configuration/rules.md)
- **pgpool-II**: trust, clear text, md5, scram-sha-256, cert, PAM, LDAP, GSSAPI via `pool_hba.conf` + `pool_passwd` (TEXT/md5/AES); `allow_clear_text_frontend_auth`; no IAM/OAuth. [Client authentication](https://www.pgpool.net/docs/latest/en/html/client-authentication.html)
- **Supavisor**: DB credential check against `user` records (`db_user`, `db_password`, `db_user_alias`) or tenant `auth_query` run as the `is_manager` user (`SELECT rolname, rolpassword FROM pg_authid WHERE rolname=$1`); JWT (HS256) secures the management API and metrics. [Authentication](https://supabase.github.io/supavisor/connecting/authentication/), [tenants](https://supabase.github.io/supavisor/configuration/tenants/)

## 6. TLS

- **Odyssey**: storage TLS modes mirror libpq — `disable | allow | prefer | require | verify_ca | verify_full` with `tls_ca_file`, `tls_cert_file`, `tls_key_file`, `tls_protocols`. [storage.md](https://github.com/yandex/odyssey/blob/master/docs/configuration/storage.md)
- **pgpool-II**: one `ssl` switch enables TLS for **both** frontend and backend; `ssl_key`, `ssl_cert`, `ssl_ca_cert`, `ssl_ca_cert_dir`, `ssl_crl_file`, `ssl_ciphers` (default `HIGH:MEDIUM:+3DES:!aNULL`), `ssl_ecdh_curve prime256v1`. [SSL doc](https://www.pgpool.net/docs/latest/en/html/runtime-ssl.html)
- **Supavisor**: tenant `upstream_ssl`, `upstream_verify`, `upstream_tls_ca`, `enforce_ssl`; globals `GLOBAL_UPSTREAM_CA_PATH`, `GLOBAL_DOWNSTREAM_CERT_PATH/KEY`. [Tenants](https://supabase.github.io/supavisor/configuration/tenants/), [env](https://supabase.github.io/supavisor/configuration/env/)

## 7. Read/write splitting & load balancing

- **Odyssey** (`balancing`, since 1.4.1): multiple `host` entries in `storage`; `roundrobin`/`leastconn`, `az_aware`, per-listen `balancing` override, `show_notice_messages`, and `target_session_attrs` (`read-write`, `read-only`, `prefer-standby`, `any`). Pools are **per endpoint** — `pool_size 10` × 3 hosts = 30 connections. [balancing.md](https://github.com/yandex/odyssey/blob/master/docs/features/balancing.md)
- **pgpool-II**: statement-level LB with `load_balance_mode`, `statement_level_load_balance` (default off), `backend_weight`, `write_function_list`/`read_only_function_list`, `primary_routing_query_pattern_list`, `user_/database_/app_name_redirect_preference_list`, `/*REPLICATION*/` hint, and `disable_load_balance_on_write` (`off | transaction | trans_transaction | always | dml_adaptive`). Modes: streaming replication, native replication, snapshot isolation, logical replication, raw. [Load balancing](https://www.pgpool.net/docs/latest/en/html/runtime-config-load-balancing.html)
- **Supavisor**: multi-tenant by design; adding read replicas is a single POST, but only one node holds direct DB connections per tenant (others relay). [1M blog](https://supabase.com/blog/supavisor-1-million), [FAQ](https://supabase.github.io/supavisor/faq/)

## 8. Failover / HA

- **pgpool-II Watchdog**: `use_watchdog`, leader election, `delegate_ip` VIP (`if_up_cmd`/`arping_cmd`), quorum + `failover_require_consensus`, `wd_lifecheck_method` (`heartbeat|query|external`), `wd_escalation_command`; `backend_flag0 = 'DISALLOW_TO_FAILOVER' | 'ALLOW_TO_FAILOVER' | 'ALWAYS_PRIMARY'`. Failover runs user `failover_command`; `auto_failback` re-attaches; `failover_on_backend_shutdown` keys off `57P01`/`57P02`. [Watchdog](https://www.pgpool.net/docs/latest/en/html/runtime-watchdog-config.html), [failover](https://www.pgpool.net/docs/latest/en/html/runtime-config-failover.html), [backend settings](https://www.pgpool.net/docs/latest/en/html/runtime-config-backend-settings.html)
- **Odyssey**: `od_router` owns attach/detach, limits and queueing; cron expires idle servers; per-storage `watchdog` polls `watchdog_lag_query` (returns the replica's replayed-WAL Unix timestamp); `target_session_attrs` + `endpoints_status_poll_interval` route around lag; zero-downtime online restart via SIGUSR2. [internals](https://github.com/yandex/odyssey/blob/master/docs/development/internals.md), [storage.md](https://github.com/yandex/odyssey/blob/master/docs/configuration/storage.md)
- **Supavisor**: cluster of nodes (`CLUSTER_NODES`, `CLUSTER_POSTGRES`, `DNS_POLL`); the first node to see a tenant's connection owns that tenant's pool, guaranteeing DB connections equal `default_pool_size`. [FAQ](https://supabase.github.io/supavisor/faq/), [env](https://supabase.github.io/supavisor/configuration/env/)

## 9. Observability

- **Odyssey console** (`database "console"`, `role "admin"`): `SHOW CLIENTS/SERVERS/SERVER_PREP_STMTS/POOLS/POOLS_EXTENDED/LISTS/STATS/DATABASES/INSTANCE/ERRORS/CONFIG/HOST_UTILIZATION`, plus `RELOAD`, `PAUSE`/`RESUME`, `KILL_CLIENT`. `SHOW POOLS_EXTENDED` adds `cl_queue`, `maxwait`, `maxwait_us`, quantiles; `cl_waiting` = idle between transactions (not pressure), `cl_queue > 0` = pool exhausted; `SHOW CONFIG` exposes a **`changeable`** column. [console.md](https://github.com/yandex/odyssey/blob/master/docs/features/console.md). The Go exporter serves `/metrics` (default `:9876`) with `odyssey_client_pool_queue_route`, `odyssey_lists_used_clients`, `odyssey_database_avg_wait_time_seconds`, `odyssey_errors_total`. [prometheus-metrics.md](https://github.com/yandex/odyssey/blob/master/docs/features/prometheus-metrics.md)
- **pgpool-II**: `SHOW POOL_POOLS` returns exactly `num_init_children * max_pool * number_of_backends` rows with 20 columns (`pool_connected`, `status`, `load_balance_node`, `statement`); plus `SHOW POOL_NODES` and PCP commands `pcp_node_info`, `pcp_proc_info`, `pcp_watchdog_info`, `pcp_pool_status`, `pcp_health_check_stats`, `pcp_detach_node`. [SHOW POOL_POOLS](https://www.pgpool.net/docs/latest/en/html/sql-show-pool-pools.html), [PCP commands](https://www.pgpool.net/docs/latest/en/html/pcp-commands.html)
- **Supavisor**: Prometheus over the Phoenix HTTP server, `PORT` default **4000**, `/metrics` and `/metrics/:external_id`, Bearer JWT; PromEx plugins `OsMon`, `NetStat`, `Tenant`; tenant-tagged checkout queue time, connected clients, query duration/counts, socket network usage. [Metrics](https://supabase.github.io/supavisor/monitoring/metrics/)

## 10. Config hot reload

- **Odyssey**: SIGUSR1 reopens logs, **SIGHUP does versioned config reload** (adds new databases, obsoletes old); console `RELOAD`; `SHOW CONFIG` exposes a `changeable` flag because only part of the global config applies without restart (`workers`, `resolvers`, `coroutine_stack_size` are restart-only). [internals](https://github.com/yandex/odyssey/blob/master/docs/development/internals.md), [console.md](https://github.com/yandex/odyssey/blob/master/docs/features/console.md), [global.md](https://github.com/yandex/odyssey/blob/master/docs/configuration/global.md)
- **pgpool-II**: `pcp_reload_config [-s cluster|local]`; many parameters are "can only be set at server start" (`num_init_children`, `max_pool`, `ssl`, watchdog). [pcp_reload_config](https://www.pgpool.net/docs/latest/en/html/pcp-reload-config.html)
- **Supavisor**: tenant/user config lives in a metadata database (`DATABASE_URL`) and is read at connection time; releases support hot upgrades (`UPGRADE_FROM`, `RELEASE_COOKIE`). [env](https://supabase.github.io/supavisor/configuration/env/)

## 11. Multi-tenancy

Supavisor is explicitly multi-tenant: a **tenant** = one upstream DB, keyed by `external_id` from the username suffix (`postgres.dev_tenant`), TLS SNI (`dev_tenant.supabase.co`), or `options=reference=dev_tenant`; tenant fields include `default_pool_size`, `default_max_clients`, `allow_list`, `sni_hostname`, `require_user`; each `user` has `pool_size`, `max_clients`, `pool_checkout_timeout`, `mode_type`. [tenants](https://supabase.github.io/supavisor/configuration/tenants/), [users](https://supabase.github.io/supavisor/configuration/users/), [overview](https://supabase.github.io/supavisor/connecting/overview/)

## 12. Connection scaling / overhead

- **Supavisor**: 250k concurrent connections on one 16-core ARM node (400 DB connections, 20k QPS); 500k on one 64-core node with no degradation; **1,003,200 connections across two 64-core nodes** at 20k QPS; median query 2 ms, p95 3 ms, p99 23 ms; backing DB 64 vCPU / 256 GB / 400 direct connections. Supabase's FAQ notes session mode cannot reach this (400 clients would hoard the pool) and that `select pg_sleep(60)` workloads would back up. Added latency vs co-located PgBouncer: median 4 ms vs 1 ms. [1M blog](https://supabase.com/blog/supavisor-1-million), [Supavisor FAQ](https://supabase.com/docs/guides/troubleshooting/supavisor-faq-YyP5tI)
- **Odyssey**: scaling knob is `workers` (threads, restart-only); each coroutine reserves `(coroutine_stack_size + 1) * page_size` of **virtual** address space (default 16 pages ≈ 68 KB on 4 KB pages), so RSS is much lower; `cache_coroutine` default 1024; `client_max_routing` auto = `64 * workers`; `server_max_routing` defaults to worker count. [global.md](https://github.com/yandex/odyssey/blob/master/docs/configuration/global.md)
- **pgpool-II**: client concurrency cap is literally `num_init_children` (default 32) — excess clients **block in the kernel listen queue** (unless `reserved_connections ≥ 1`, which yields `Sorry, too many clients already`). Backend connections ≈ `max_pool * num_init_children` and must satisfy `max_pool*num_init_children ≤ max_connections - superuser_reserved_connections` (double it if cancellation must always work). [Connections doc](https://www.pgpool.net/docs/latest/en/html/runtime-config-connection.html)

## 13. Known ceilings & failure modes

- **pgpool-II**: no transaction pooling; multi-statement queries bypass LB and prepared-statement parsing (mailing list above); temp tables in native replication mode are primary-only and cannot be detected when referenced as literals → "not found the table"; `set_config()` divergence; no encoding conversion between client and backend; large objects unsupported outside streaming/snapshot modes; `pg_terminate_backend()` triggers spurious failover in extended protocol; children leak-prone, hence `child_life_time` (default 300 s) and `child_max_connections`. [Restrictions](https://www.pgpool.net/docs/latest/en/html/restrictions.html), [connection pooling](https://www.pgpool.net/docs/latest/en/html/runtime-config-connection-pooling.html)
- **Odyssey**: router is "request-reply" and internally noted as "a potential hot spot"; soft OOM (since 1.5.1) refuses new connections with `FATAL: odyssey: <id>: soft out of memory` when a process/system memory `limit` is crossed; issue #477 prepared-statement race. [internals](https://github.com/yandex/odyssey/blob/master/docs/development/internals.md), [soft-oom.md](https://github.com/yandex/odyssey/blob/master/docs/features/soft-oom.md)
- **Supavisor**: `Max client connections reached`; `{:error, :eaddrnotavail}` / `{:error, :nxdomain}` to the tenant DB; `Connection closed when state was authentication`; `{:error, :worker_not_found}`; `{:error, {:badrpc, {:error, {:erpc, :timeout}}}}` between nodes. [Supabase troubleshooting](https://supabase.com/docs/guides/database/supavisor)

## 14. Project health (as of this research)

| | Odyssey | pgpool-II | Supavisor |
|---|---|---|---|
| Latest release | **v1.5.2**, 2026-09-13 | **4.7.2**, 2026-06-04 (with 4.6.7/4.5.12/4.4.17/4.3.20) | **v2.9.13**, 2026-09-10 |
| Stars / forks / open issues | 3,624 / 211 / 104 | 442 / 102 / 89 (official mirror) | 2,265 / 117 / 51 |
| License | BSD-3-Clause | Custom (Pgpool GDG) | Apache-2.0 |
| Backing | Yandex | Pgpool Global Development Group / SRA OSS | Supabase |
| Cadence | ~1 minor per 1–2 quarters | Parallel patch releases across 5 branches, roughly quarterly | Frequent (v2.9.x patch train) |

Sources: [Odyssey release](https://github.com/yandex/odyssey/releases/tag/v1.5.2), [pgpool news](https://www.pgpool.net/), [pgpool repo](https://github.com/pgpool/pgpool2), [Supavisor release](https://github.com/supabase/supavisor/releases/tag/v2.9.13).

## Bottom line

Odyssey is the closest template (C + coroutines, transaction pooling, prepared-statement reservation, TSA routing, rich console), but its prepared-statement path has a long-open bug and its router is a serialization point. pgpool-II fits worst: multi-process, session-only pooling, a hard `num_init_children` blocking ceiling, and a parser that cannot see multiple statements on one line. Supavisor wins on density (1M on two 64-core nodes) and multi-tenancy, but pays ~3 ms extra latency vs co-located PgBouncer and gates transaction-mode prepared statements behind a default-off flag.
