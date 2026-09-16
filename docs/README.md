# Docs index

| Path | What it is |
|---|---|
| [`vision/roadmap.md`](vision/roadmap.md) | **The plan.** Phase order, deliverables, exit gates, risk spikes, non-goals. Start here. |
| [`vision/product-thesis.md`](vision/product-thesis.md) | Positioning, buyers, non-goals, honest risks. |
| [`adr/`](adr/README.md) | Architecture decision records — what we decided and what we rejected. |
| [`architecture/overview.md`](architecture/overview.md) | Component map, threading model, data-path tiers, crate responsibilities. |
| [`architecture/session-state-taxonomy.md`](architecture/session-state-taxonomy.md) | **Spike S2 output.** The PostgreSQL 14–18 session-state surface and what can be virtualised. This is the Phase 1 specification. |
| [`plans/phase-0-foundations.md`](plans/phase-0-foundations.md) | The Phase 0 workstreams, gates and risk spikes. |
| [`plans/spike-findings.md`](plans/spike-findings.md) | **Measured outcomes of spikes S1–S3**, including results that contradicted our assumptions. |
| [`research/`](research/README.md) | The research base: competitive landscape, pain points, technical frontier. |

## Reading order

1. `vision/roadmap.md` — what we are building and in what order.
2. `adr/0001` → `adr/0003` — language, parsing, and the central architectural decision.
3. `architecture/overview.md` — how the pieces fit.
4. `plans/spike-findings.md` — what the experiments actually showed.
5. `research/00-landscape-and-innovation-map.md` — the full evidence base, if you want the source material.

## Conventions

- **ADRs are immutable once accepted.** Supersede rather than edit; a changed decision gets a new ADR that references the old one.
- **Every phase gate is a measurable claim.** If a phase cannot state one, the phase is not ready.
- **Research documents are dated and cite primary sources.** They are evidence, not living docs.
