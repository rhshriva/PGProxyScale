# Current architecture decisions

This is the maintained summary of the current decisions. Older decision documents
have been consolidated here; their revisions remain available in Git.

| Topic | Current decision or implementation boundary |
|---|---|
| Language/runtime (0001) | Rust; SO_REUSEPORT worker listeners and one OS thread per client connection. Shared pool synchronization exists; per-core pools and io_uring execution are not implemented. |
| Parser (0002) | Vendored libpg_query 18 through bounded, audited FFI; JSON-derived ASTs, parser context, versioned fingerprints and bounded caching. Governed SQL uses full parsing. One grammar is currently built. |
| Session state (0003) | Confirmed per-client state, rollback/savepoints, preparation contexts and safe backend ownership. Replay reconstructible state; retain affinity or refuse unsupported effects. Complete resource migration and comprehensive DDL invalidation remain open. |
| Licence (0004) | Deliberately unresolved. Cargo metadata currently says Apache-2.0 with a TODO; settle the release licence and supporting files before a release claim. |
| Packaging (0005) | Standalone pgproxy binary first. Embedding, sidecar-specific packaging and an operator remain future options. |
| Operations/configuration | Validated service generations and authenticated loopback HTTP controls. Existing sessions retain their generation. Listener/process limits require restart. See the reload guide. |
| Cancellation | Proxy client keys map to current physical backend ownership across reload generations; ownership changes invalidate stale routing. See the current architecture and protocol tests. |

## Unresolved proposals

| Proposal | Status |
|---|---|
| [0006 — State virtualization boundary](0006-session-state-virtualization-boundary.md) | Proposed: define a PostgreSQL-side contract before transparent temp/lock/notification migration |
| [0007 — Shared-role tenant cost attribution](0007-shared-role-tenant-cost-attribution.md) | Proposed: choose distinct backend identities, server-side measurement, or non-exclusive accounting |

These proposals are not recorded approvals. Current affinity and non-exclusive
counter reporting remain the implemented behavior.

## Implementation references

- [Current architecture](../architecture/overview.md)
- [Implementation status](../plans/implementation-status.md)
- [Reload and capacity](../testing/reload-and-capacity.md)
- [Credential and usage semantics](../testing/credentials-and-usage.md)

Any new server dependency, changed user-visible semantics, licence selection or
new plugin ABI needs an explicit decision. Update this summary when a decision is
made; do not treat a target roadmap as proof of implementation or acceptance.
