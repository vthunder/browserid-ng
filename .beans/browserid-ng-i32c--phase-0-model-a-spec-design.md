---
# browserid-ng-i32c
title: Phase 0 — Model A spec & design
status: completed
type: task
priority: high
created_at: 2026-07-17T23:05:30Z
updated_at: 2026-07-18T19:40:37Z
parent: browserid-ng-oup3
---

Write the Model A spec sections (see docs/plans/2026-07-18-model-a-browser-first-agent-migration-plan.md §6 spec): §7 rewrite (browser-as-first-agent bootstrap), §4.1 self-cert shape (D1), §4.3 mint as shared verb (self vs agent mode), Constraint as typed capability descriptor + the new subject axis + fail-closed-on-unknown-axes rule (D2), §6.4 provisioning-credential revocation = logout-everywhere, discovery advertisement, conformance. Close OQ1-OQ4 (replay nonce, bootstrap-credential handoff, credential lifetime/rotation, SBO signing's new home). Source of truth; unblocks all later phases.

## Summary of Changes
Applied the approved subject-axis draft to the normative specs (commit above): agent-provisioning §4.1/§4.3/§4.2/§9 + protocol §3.1/§7/§9 + divergence item 7. Subject vocabulary (self|agent), subjects REQUIRED (no default, fail-closed), self-mode mint = plain RP-unchanged cert, conformance mandates the mint verb for login, iframe retired. OQ1-4 resolved in docs/plans/2026-07-18-phase0-subject-axis-spec-draft.md. Spec README reading-path polish deferred to Phase 6 (docs).

## SUPERSEDED (2026-07-18)
Model pivoted to the device-cert design (docs/plans/2026-07-18-device-cert-model-migration-plan.md). This work targeted the earlier user-signed-provisioning-cert model; kept as historical record, replaced by the new device-cert phases. Not reverted (additive, harmless).
