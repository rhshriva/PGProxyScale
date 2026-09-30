# PGProxyScale verification evidence

The final automated release gates passed for source SHA256 `066197ad09cba21248614fee41a09e2438b63515124ea701efc2c5cc074b17e3`. The hash matched before and after native verification and again after all Linux, compatibility and TLS checks. [Machine-readable report](report.json) records platform, Rust toolchain, binary identities, gate outcomes and log paths.

| Gate | Result |
| --- | --- |
| Native workspace tests | 323 passed |
| Linux workspace tests | 323 passed |
| Native and Linux strict lint | Passed |
| Native and Linux optimized release builds | Passed |
| PostgreSQL 14–18 driver compatibility | 260 scenarios passed |
| PostgreSQL 14–18 TLS/mTLS/channel binding/cancellation/Unicode; PG18 RSA-PSS | 48 checks passed |
| Physical-replica failover and faults | 5 checks passed |
| Credential rotation and usage system checks | 5 checks passed |

The physical-replica fixture rejects user SQL on an unpromoted standby, retires two idle sockets from a reachable demoted primary, routes new work after external promotion, preserves committed data, and rejects an interrupted transaction without replay after recovery. Its PostgreSQL image digest is recorded in [the fault log](replicated-failover.log).

Supplemental integration logs cover virtual state/ledger, relation caching, Unix credential process cleanup and adversarial usage accounting. Those logs were collected during area development; their individual source hashes were not captured. Final source-bound verification is listed in the table above.

**Production certification remains incomplete.** An independent security review, deployment-specific fencing/split-brain validation, real IAM/Vault integration, and bare-metal performance/soak evidence are still required. The proxy does not promote PostgreSQL, fence database servers, or replay uncertain writes. Blocking OS DNS resolution remains outside the socket deadline. Docker acceptance provides no evidence for WAN failures, production load, or encrypted replicated failover as a combined topology.

Run `python3 tests/certification/run.py --live --linux` to generate a new report; use the separate conformance matrix/TLS runners for those acceptance gates. The harness always records `production_certified: false` and rejects source changes during the run.
