---
# browserid-ng-wid3
title: Phase 2 — Broker issuance security (D2 controls)
status: completed
type: task
priority: high
created_at: 2026-07-17T23:05:30Z
updated_at: 2026-07-18T19:40:37Z
parent: browserid-ng-oup3
blocked_by:
    - browserid-ng-54jz
---

The load-bearing controls. routes/agent.rs::mint self-mode branch enforcing the subject capability (refuse self-cert unless constraint grants it); new plain-cert-for-self branch in cert.rs issue_certificate (delegator email verified+owned, issuer==domain); P_cert revocation status ref consulted at mint/endorsement (logout-everywhere); quota/EmailType separation (self cert != agent identity); keep mint cookie-free (no cookie fallback); well_known.rs discovery advertisement. Fail-closed on unknown constraint axes. See docs/plans/2026-07-18-model-a-browser-first-agent-migration-plan.md §2, D2.

## Summary
/provision/mint branches on subject. self-mode issues a plain login cert for the delegator's own verified email (create_with_status), gated by D2 (constraint must grant 'self'), requires jti, forbids name, no agent quota. agent-mode unchanged + now checks constraint grants 'agent'. Subject required (no default). 2 new tests (self-mint plain cert + D2 refusal); 17/17 broker agent green. Deferred: <=10min endorsement window hardening + jti replay cache + discovery advertisement.

## SUPERSEDED (2026-07-18)
Model pivoted to the device-cert design (docs/plans/2026-07-18-device-cert-model-migration-plan.md). This work targeted the earlier user-signed-provisioning-cert model; kept as historical record, replaced by the new device-cert phases. Not reverted (additive, harmless).
