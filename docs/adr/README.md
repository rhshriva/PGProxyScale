# ADR index

Architecture decision records. Once accepted, an ADR is not edited — supersede it with a new one.

| # | Title | Status |
|---|---|---|
| [0001](0001-language-and-runtime.md) | Implementation language and runtime | Accepted (runtime confirmed by spike S1) |
| [0002](0002-parser-strategy.md) | SQL parsing strategy | Accepted (corrected by spike S3) |
| [0003](0003-session-state-ledger.md) | Session-State Ledger | Accepted (taxonomy delivered by spike S2) |
| [0004](0004-licence.md) | Licence | **Proposed — deliberately deferred** |
| [0005](0005-deliverable-shape.md) | Deliverable shape | Accepted |
| [0006](0006-session-state-virtualization-boundary.md) | Session-state virtualization boundary and the PostgreSQL-side component | **Proposed — decision required** |
| [0007](0007-shared-role-tenant-cost-attribution.md) | Exclusive tenant cost attribution for shared backend roles | **Proposed — decision required** |

Measured outcomes of the spikes that inform these: [`../plans/spike-findings.md`](../plans/spike-findings.md).

## Proposed / not yet written

- **0008 — Admin and configuration surface.** Config-as-code, validation, dry-run, hot reload semantics.
- **0009 — Cancellation and identity.** First-class `CancelRequest` routing; PostgreSQL 18's variable-length cancel keys break the fixed 12-byte assumption that PgBouncer's `[peers]` protocol relies on.
- **0010 — Plugin ABI.** WASM (wasmtime) vs native, and the resource-budget model.

## Template

```markdown
# ADR NNNN — Title

- Status: Proposed | Accepted | Superseded by ADR-XXXX
- Date: YYYY-MM-DD
- Depends on: ADR-XXXX

## Context
## Decision
## Alternatives considered
## Consequences (positive / negative / neutral)
## Open questions
```
