---
# browserid-ng-1ep4
title: DC Phase 5 — Client broker (keystore + flows)
status: completed
type: task
priority: normal
created_at: 2026-07-18T19:40:58Z
updated_at: 2026-07-18T22:22:52Z
parent: browserid-ng-oup3
blocked_by:
    - browserid-ng-qo3j
---

Device keystore (non-extractable); cold bootstrap via WinChan popup (RP login->email->discovery->device cert); access-cert minting; warrant fetch; RP presentation; agent device-cert pairing (device-grant). Retire hidden-iframe/postMessage/session-cookie mint path. See docs/plans/2026-07-18-device-cert-model-migration-plan.md.

## Done: /dc-login client + demo RP. Real device-cert flow, deployed, prod-verified with conformance (fallback identity).
