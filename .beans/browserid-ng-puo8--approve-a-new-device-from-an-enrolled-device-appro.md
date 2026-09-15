---
# browserid-ng-puo8
title: 'Approve a new device from an enrolled device: approvals API, login-page code screen, native wallet dialog, account-page card'
status: completed
type: feature
priority: high
created_at: 2026-09-15T00:12:20Z
updated_at: 2026-09-15T00:56:37Z
parent: browserid-ng-0vdu
blocked_by:
    - browserid-ng-noqd
---

Registrar: POST /api/v1/approvals (login page opens; code + wait handle), GET /api/v1/approvals (enrolled devices poll), POST /api/v1/approvals/approve {id, code} under a session with Proof; approving enrols the waiting key with enrolled_by=approval; floor: a key enrolled by approval may approve only after its device has proven one identity. Login page: 'Approve from another device' method showing the code, long-poll for the token. Native wallet: poll + native dialog (like approveLogin in main.js), the phone flow. Account page: pending approvals card. e2e: wallet e2e.mjs two-wallet approval; Playwright for the page.

## Summary of Changes

Shipped and deployed 2026-09-15 (commit a9ae7fc; prod schema 45). Approvals API (§5.2.8), login page 'Approve from another device', account page card with code field, native wallet approve-device window polled every 15 s. Tests: registry_api_test, Playwright device-approval.spec (2), wallet e2e steps.
