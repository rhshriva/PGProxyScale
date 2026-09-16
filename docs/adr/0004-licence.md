# ADR 0004 — Licence

- **Status:** **Proposed — deliberately deferred.** Not blocking development; blocking public release.
- **Date:** 2026-09-16

---

## Context

The licence determines whether other platforms can embed the proxy, whether a hosted competitor can
resell it, and what enterprise legal review will accept. It is one of the few decisions here that is
genuinely hard to reverse — a permissive release cannot be un-released.

The relevant market facts:

- **PgDog** is **AGPL-3.0** for the core with a paid Enterprise Edition. This is the closest
  competitor and the closest comparable business model.
- **PgBouncer** is ISC (permissive) and has no corporate owner. It is free and ubiquitous, which caps
  what anyone can charge for raw pooling.
- **pg_doorman** is MIT, **Odyssey** is BSD-3, **pgagroal** is BSD-3, **Supavisor** is Apache-2.0 —
  the self-hostable pooler space is overwhelmingly permissive.
- **Cloudflare's multi-tenant `cf-pgbouncer` fork was archived in June 2026**, and **Neon absorbed
  PolyScale's niche** — evidence that a valuable hosted layer can be absorbed by a platform vendor.

## The three realistic options

### A. AGPL-3.0 core + paid Enterprise Edition (PgDog's model)

**Protects:** the hosted-competitor case, because a modified AGPL service must publish its source.
Directly monetises the enterprise features (policy, SSO, audit, support).

**Costs:** blocks most embedding. Many enterprises prohibit AGPL in their dependency tree outright.
A platform vendor that wants to embed the proxy inside their own product will not do so under AGPL,
which is precisely the segment our research identifies as unserved.

### B. Apache-2.0

**Protects:** nothing directly. Maximises adoption, embedding, and contribution.

**Costs:** no licence moat at all. Value must come entirely from the enterprise control plane,
policy content, support and the data asset (attribution). This is a bet that the moat is
*operational* rather than *legal* — which the research supports: the durable moats identified are
correctness, the policy engine, and attribution data, not the binary.

### C. BSL / source-available with a change date

**Protects:** against a hosted competitor for N years, then converts to open source.

**Costs:** procurement friction — it is neither a recognised open-source licence nor a clean
commercial one, and some enterprises treat it as the worst of both.

## Decision criteria (to be applied when deciding)

1. **Does the primary buyer need to embed the proxy?** If the sidecar/embedded-library packaging
   (roadmap §8, open question 2) is the v1 deliverable, AGPL is close to disqualifying.
2. **Is the differentiator copyable?** Session-state virtualisation and the DDL-safe plan
   invalidation protocol are hard, but visible once shipped. The policy engine and attribution data
   are the compounding assets.
3. **Who is the first design partner?** A platform vendor argues for permissive; a regulated
   enterprise buying a standalone gateway argues for AGPL+EE or BSL.
4. **Is a hosted offering planned?** If we host, AGPL protects the hosted case; if we only ship
   software, it mostly protects nothing.

## Current position

**Deferred by decision.** The workspace tracks this as `TODO(ADR-0004)` in `Cargo.toml`. Nothing in
Phase 0 or Phase 1 depends on the answer; the decision must be made before the first public release
or any external contribution, because retroactively changing a licence requires the consent of every
copyright holder.

## Consequences of deferring

- **Acceptable:** all work is internal, so no rights are granted to anyone.
- **Risk:** if external contributors are accepted before the decision, relicensing later becomes
  impractical. **Anyone contributing before ADR-0004 is accepted must sign a CLA or DCO that permits
  relicensing.** This is the one action item the deferral creates.
