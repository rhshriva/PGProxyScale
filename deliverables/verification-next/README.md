# Current verification evidence

Frozen source SHA256: `ef878fc5c242ea24dc4c198def25f0b3d3ca456fb94319573dc41dc602ea9175`.

## Local gate rerun — 2026-09-30

`python3 tests/certification/run.py --output deliverables/verification-next/report.json` (without
Docker) passed every gate it can run locally and confirmed source stability:

- `workspace-tests` — **339** unit/integration tests pass (up from 338; the extra test is the new
  closed-cursor regression in `crates/pgproxy-session/src/cursor_protocol.rs`).
- `strict-lint` — `cargo clippy --workspace --all-targets -- -D warnings` clean.
- `release-build` — optimized workspace build succeeds.
- `certification-evidence-tests` — 13 Python evidence contracts pass.
- `source-stability` — start and end source hash identical.

`replicated-failover` and `linux-tests-lint` are recorded as `not-run`: both require Docker, which
was unavailable in this environment. The four external gates below remain
`external-evidence-required`.

This run adds two architecture-decision records (ADR-0006 session-state virtualization boundary,
ADR-0007 shared-role tenant cost attribution) and documents the native suspended-`CLOSE` dependency
risk in `docs/testing/ledger-semantics.md`. Documentation is excluded from source identity, so those
changes do not alter the frozen hash; only the cursor regression test does.

This hash also includes the CI build-tooling fix in `tests/conformance/run.sh`: the slim
`rust:*-slim-bookworm` build container now installs `make`/`gcc` before building `pgproxy-cli`,
because `crates/pgproxy-parser/build.rs` compiles the vendored libpg_query sources with `make`.

`performance/` (collected at the previous source hash) contains six actual direct/proxy smoke workloads, zero errors or dropped measurements, an independent empty-table rollback check, complete bounded latency histograms and the owned release-process provenance. These short local measurements do not satisfy hour-long physical-laboratory certification requirements.

The security logs describe internal development checks, not an independent third-party audit. `prior-baseline/` contains explicitly older logs retained for context; they are not current-source gates.

Production certification remains false. No independently provisioned authority key, signed external audit, actual production fencing report, authorized real AWS/Vault lifecycle evidence, or bare-metal laboratory evidence was supplied. The authenticated ingestion workflow and exact trust assumptions are documented in `tests/certification/EXTERNAL-EVIDENCE.md`. Temporary synthetic unit-test issuers never count as external evidence. Local Docker power fencing does not certify a deployed failover orchestrator.

## Not rerun for this hash (Docker required)

The Linux workspace gate, PostgreSQL 14–18 compatibility, the TLS/mTLS + RSA-PSS matrix, the local
performance smoke and the server-cost/MCP/relation-cache evidence in this directory were collected at
the previous source hash `447283fc2ce7cffaeb76a73b6fb1698a913e9f6b626da94aca17ad9d1948fe74`. At that
hash they passed: 338 isolated Linux tests, 260 compatibility scenarios (one initial PG16 large-result
timeout retained as a failure log), 48 TLS/mTLS + RSA-PSS cases across PostgreSQL 14–18, server-cost
matrix 35, CPU attribution 7, MCP 16 and relation-cache 10. They are retained for context and are not
source-bound gates for the frozen hash above. Regenerate them with Docker before any release claim:

```sh
python3 tests/certification/run.py --live --linux
# plus the tests/conformance/ runners for compatibility, TLS and benchmarks
```

The complete previous snapshot is preserved at `prior-baseline/report-447283-full.json`.
