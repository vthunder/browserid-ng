---
# browserid-ng-umme
title: DC Phase 6 — RP verification contract (breaking)
status: completed
type: task
priority: normal
created_at: 2026-07-18T19:40:58Z
updated_at: 2026-07-18T22:22:52Z
parent: browserid-ng-oup3
blocked_by:
    - browserid-ng-1ep4
---

Always-warrant verification: access cert + assertion + warrant joined by (identity,subject,audience), both revocation links checked. Update browserid-rp + JS/Python/Go verifier libs + hosted /verify. See docs/plans/2026-07-18-device-cert-model-migration-plan.md.

## Partial: verify_access_with_dns live + prod-verified (real primary/fallback conformance). TODO: fail-closed foreign status fetch (with P4 registry), jti replay cache.
