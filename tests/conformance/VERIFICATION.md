# Compatibility and fuzz verification

Build the native proxy with `cargo build -p pgproxy-cli`, then run:

```
tests/conformance/native-matrix.sh
tests/conformance/backend-tls/run.sh
```

The native matrix runs all existing psycopg cases against a direct PostgreSQL
control, session passthrough and transaction pooling, followed by asyncpg
concurrent prepared statements, transactions, rollback and pool reset. It defaults
to PostgreSQL 14–18. Override `PGPROXY_MATRIX_VERSIONS` with a space-separated
subset. Docker drivers use host networking on Linux and Docker Desktop's host
alias on macOS; temporary backend ports bind only loopback.

Backend TLS defaults to PostgreSQL 18; set `PGPROXY_TLS_POSTGRES_IMAGE` for each
other major. The backend TLS README documents its coverage and limits.

Both runners use disposable containers and temporary config files. They require
Docker, a built native proxy and free default ports; the backend TLS runner also
requires OpenSSL. Existing user containers are untouched. CI runs the same
scripts separately for PostgreSQL 14–18 in `compatibility.yml`.

The isolated `fuzz/` workspace contains bounded codec and parser FFI entry points.
Use the documented nightly cargo-fuzz commands for instrumented campaigns;
`fuzz.yml` runs a 60-second smoke campaign per target. Compiling or running
uninstrumented mutations does not establish coverage or memory safety. The
vendored C parser is currently built by its own Makefile; Rust sanitizer
instrumentation does not automatically certify every C object is instrumented.

These compatibility tests do not establish bare-metal throughput/latency gates,
long-running failover soak or compatibility for all PostgreSQL extensions.

For a reproducible lightweight workload, run the benchmark driver against a
prepared isolated endpoint:

```
python tests/conformance/drivers/benchmark_check.py --host localhost --port 6432 --database conformance_transaction --clients 4 --queries-per-client 1000 --output candidate.json
```

It reports nearest-rank p50/p95/p99 latency and total throughput, including Python,
network and proxy costs. Pass `--baseline reference.json` to enforce explicit
p99 and throughput ratios on matching workload/driver/platform metadata. Establish
the reference on the same hardware under controlled load; default ratios are
configurable workload guards, not the product's production performance promises.

## Verified integration snapshot — 2026-09-30

- macOS and Linux: **290 unit/integration tests** each, strict Clippy across
  all targets, successful workspace/CLI builds. Formatting and diff whitespace passed.
- PostgreSQL **14–18** native proxy: **260 scenarios** (17 direct controls,
  17 session, 17 transaction and one concurrent asyncpg acceptance per major).
- Backend TLS: **40 checks**, eight per PostgreSQL major 14–18, plus **8**
  PostgreSQL 18 checks using an RSA-PSS certificate. This includes mTLS identity,
  bound SCRAM, Unicode normalization, encrypted cancellation and rejection cases.
- Ledger **5/5**, reload **4/4**, physical backend cap **2/2**;
  wire policy **9/9**, MCP **16/16**, RLS/fairness **4/4**, MCP RLS **8/8**.
- Frontend TLS/channel-binding/certificate security **5/5** on the final binary.
- Startup negotiation **3/3**, authenticated operations acceptance, area acceptance
  **7/7** on the final binary (prior optional writable-primary case also passed).
- Both standalone fuzz targets compiled and completed **10,000 uninstrumented
  mutations**. Instrumented long campaigns remain unverified.
- Benchmark harness smoke completed with JSON latency/throughput output. This is
  execution proof for the harness, not production performance certification.

Ledger/reload instructions are in `docs/testing/ledger-semantics.md` and
`docs/testing/reload-and-capacity.md`; operations/policy/MCP semantics are in
`docs/testing/operations-and-governance.md`. All results use disposable local
fixtures. CI definitions are added but a hosted CI run is not implied.

## Verified snapshot — 2026-09-29 Pacific

The native macOS binary passed the complete runner with PostgreSQL 14, 15, 16,
17 and 18: 255 existing psycopg scenarios across direct controls and both pooling
modes, plus five asyncpg acceptance scenarios (260 total). The asyncpg scenario
uses four concurrent frontend connections sharing two backends.

Backend TLS passed eight checks on each major (40 total), plus the same eight
checks using an RSA-PSS SHA384 server certificate on PostgreSQL 18. This includes
trusted CA/hostname validation, bound SCRAM, prepared queries, encrypted
cancellation/recovery, mutual certificate identity and a Unicode SASLprep password.

An isolated ARM64 Linux Rust 1.91 container passed 290 workspace unit/integration
tests, the production workspace build and strict Clippy. The platform test retains
its registered waker until polling ends and has a finite watchdog, fixing a Linux
lifetime race exposed during this verification. These counts describe this code
snapshot; later changes must run the same checks again.

Both fuzz targets compiled and each completed 10,000 uninstrumented local
mutations. These were smoke runs without coverage/sanitizer instrumentation;
nightly instrumented campaigns are configured separately and remain a distinct
verification gate. Benchmark output/reference comparison was smoke-tested against
an isolated PostgreSQL fixture; bare-metal performance targets remain unverified.

## Additional feature integration — 2026-09-29 local

The subsequent parallel implementation snapshot passes **323 workspace unit/integration tests**
on both macOS and Linux, strict all-target Clippy, and optimized release builds. The certification
runner records exact source and binary SHA256 and requires source stability while gates execute.
This snapshot's source hash is `066197ad09cba21248614fee41a09e2438b63515124ea701efc2c5cc074b17e3`.

New live evidence:

- **6 state virtualization cases** plus **5 existing ledger regressions**, including two held cursor
  snapshots on one physical backend, differential scrolling, source-table updates, fallback and roles.
- **5 replicated failover/fault cases**, including reachable demotion with two stale idle connections,
  unpromoted standby rejection, commit preservation and uncertain transaction refusal without replay.
- **5 credential/usage cases** over real SCRAM, including expired physical socket retirement,
  file/broker role rotation, invalid grant rejection, and wire protocol/principal accounting.
- **10 relation-cache/MCP-accounting cases**, covering external DML, active writers, rollback,
  DDL, TRUNCATE, permission/authentication failure and exact byte/row/cache/error reconciliation.
- Internal adversarial review adds **7 credential** and **6 accounting** unit regressions, including
  FIFO refusal, bounded command output, portable process-group cleanup, early protocol errors,
  partial aborted usage and bounded pipeline alignment. Minimal Linux required no procps dependency.

The final durable evidence bundle is `deliverables/verification/`. Read its report for source hashes,
platform, individual results and external gates. The same snapshot also reruns the separate native
PostgreSQL 14–18 and backend TLS matrices; counts appear in the evidence summary.

Production certification remains **false** until an independent security review, actual IAM/Vault
provider validation, deployed promotion/fencing tests, and bare-metal load/soak evidence are supplied.
Server CPU/buffer/WAL cost reconciliation and full state virtualization remain additional roadmap work.
