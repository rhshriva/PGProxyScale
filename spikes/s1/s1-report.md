# Spike S1 — data-path overhead report

- pgbench scale 100, `-S -n`, 10s measured after 5s warmup
- all containers on one Docker bridge network (no host-network variance)
- Rust proxies: release build, 2 worker(s), SO_REUSEPORT, TCP_NODELAY
- PgBouncer: single process, session mode, `default_pool_size=100`
- PostgreSQL 18, `fsync=off`, `synchronous_commit=off`, `shared_buffers=1GB`

| target | conns | TPS | latency avg (ms) |
|---|---|---|---|
| direct | 1 | 16416.870589 | 0.061 |
| direct | 4 | 55541.591304 | 0.072 |
| direct | 16 | 94599.624618 | 0.169 |
| direct | 64 | 118470.380927 | 0.540 |
| pgbouncer-session | 1 | FAILED | - |
| pgbouncer-session | 4 | FAILED | - |
| pgbouncer-session | 16 | FAILED | - |
| pgbouncer-session | 64 | FAILED | - |
| rust-thread | 1 | 9649.300073 | 0.104 |
| rust-thread | 4 | 33415.536437 | 0.120 |
| rust-thread | 16 | 102210.898863 | 0.157 |
| rust-thread | 64 | 151469.869973 | 0.423 |
| rust-tokio | 1 | 9711.537308 | 0.103 |
| rust-tokio | 4 | 34769.488895 | 0.115 |
| rust-tokio | 16 | 80657.904497 | 0.198 |
| rust-tokio | 64 | 81111.793862 | 0.789 |
| rust-splice | 1 | 9097.397342 | 0.110 |
| rust-splice | 4 | 32948.261113 | 0.121 |
| rust-splice | 16 | 96054.098791 | 0.167 |
| rust-splice | 64 | 161287.052973 | 0.397 |
