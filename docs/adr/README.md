# ADR index

Architecture decision records. Once accepted, an ADR is not edited — supersede it with a new one.

| # | Title | Status |
|---|---|---|
| [0001](0001-language-and-runtime.md) | Implementation language and runtime | Accepted (runtime confirmed by spike S1) |
| [0002](0002-parser-strategy.md) | SQL parsing strategy | Accepted (corrected by spike S3) |
| [0003](0003-session-state-ledger.md) | Session-State Ledger | Accepted (taxonomy delivered by spike S2) |
| [0004](0004-licence.md) | Licence | **Proposed — deliberately deferred** |

Measured outcomes of the spikes that inform these: [`../plans/spike-findings.md`](../plans/spike-findings.md).

## Proposed / not yet written

- **0005 — Deliverable shape.** Self-hosted binary vs Kubernetes sidecar/operator vs embeddable library.
- **0006 — Admin and configuration surface.** Config-as-code, validation, dry-run, hot reload semantics.
- **0007 — Cancellation and identity.** First-class `CancelRequest` routing; PostgreSQL 18's variable-length cancel keys break the fixed 12-byte assumption that PgBouncer's `[peers]` protocol relies on.
- **0008 — Plugin ABI.** WASM (wasmtime) vs native, and the resource-budget model.

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
