---
# browserid-ng-54jz
title: Phase 1 — Core protocol types
status: completed
type: task
priority: normal
created_at: 2026-07-17T23:05:30Z
updated_at: 2026-07-18T19:40:37Z
parent: browserid-ng-oup3
blocked_by:
    - browserid-ng-i32c
---

browserid-core: reframe Constraint (provisioning.rs:97) as a typed capability descriptor + add the signed subject axis (self|agent); add the axis to ProvisioningRequestClaims (~284) as a REQUIRED field (no serde default; reject missing subjects/subject per 2026-07-18 decision) + a mint-self path; surface via VerifiedRequest; self-mode -> Certificate::create_with_status (plain cert, no struct change). Port spike_a_login_via_mint.rs tests. Blocked by Phase 0 naming/shape. See docs/plans/2026-07-18-model-a-browser-first-agent-migration-plan.md §3.

## Summary
Added Subject enum + subjects axis on Constraint (required, fail-on-empty), subject+jti on the request, mint_self() constructor, self_only() constraint, authorizes_subject(). Re-exported Subject. Updated test literals. New subject_axis_constraint_and_request test. Core 61+ green, broker agent_provisioning 15/15 green.

## SUPERSEDED (2026-07-18)
Model pivoted to the device-cert design (docs/plans/2026-07-18-device-cert-model-migration-plan.md). This work targeted the earlier user-signed-provisioning-cert model; kept as historical record, replaced by the new device-cert phases. Not reverted (additive, harmless).
