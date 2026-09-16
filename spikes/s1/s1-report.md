# Spike S1 — data-path overhead report

- pgbench scale 100, `-S -n`, 8s measured after 4s warmup, best of 2 passes
- pgbench in its own container; global warmup before measuring; targets interleaved
- all containers on one Docker bridge network
- Rust proxies: release, 2 worker(s), SO_REUSEPORT, TCP_NODELAY, pure pass-through
- PgBouncer 1.18 single process, session mode, `default_pool_size=100`
- PostgreSQL 18, `fsync=off`, `synchronous_commit=off`, `shared_buffers=1GB`, 16 CPUs

**Raw TPS** (best of 2 passes):

| target | c=1 | c=4 | c=16 | c=64 |
|---|
| direct | 15542.223108 | 51648.874087 | 148597.268268 | 122921.181845 |
| pgbouncer-session | 9485.976294 | 34346.756533 | 70253.349975 | 71182.542606 |
| rust-thread | 9678.075578 | 33049.017315 | 107599.429331 | 215827.176251 |
| rust-tokio | 9562.928125 | 33918.934703 | 91012.877786 | 93625.226633 |
| rust-splice | 9808.037567 | 32517.937964 | 109344.807526 | 217866.925405 |

**Average latency (ms)** — best-of-pass latency for the fastest TPS run:

| target | c=1 | c=4 | c=16 | c=64 |
|---|
| direct | 0.064 | 0.077 | 0.108 | 0.521 |
| pgbouncer-session | 0.105 | 0.116 | 0.228 | 0.899 |
| rust-thread | 0.103 | 0.121 | 0.149 | 0.297 |
| rust-tokio | 0.105 | 0.118 | 0.176 | 0.684 |
| rust-splice | 0.102 | 0.123 | 0.146 | 0.294 |

**Overhead versus direct**, as (direct ÷ proxy) latency ratio at the same concurrency:

| target | c=1 | c=4 | c=16 | c=64 |
|---|
| pgbouncer-session | 1.64x | 1.51x | 2.11x | 1.73x |
| rust-thread | 1.61x | 1.57x | 1.38x | 0.57x |
| rust-tokio | 1.64x | 1.53x | 1.63x | 1.31x |
| rust-splice | 1.59x | 1.60x | 1.35x | 0.56x |

Raw per-pass data: `s1-report.md.raw.tsv`.
