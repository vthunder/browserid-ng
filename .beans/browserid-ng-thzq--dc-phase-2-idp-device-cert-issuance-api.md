---
# browserid-ng-thzq
title: DC Phase 2 — IdP device-cert issuance API
status: completed
type: task
priority: normal
created_at: 2026-07-18T19:40:58Z
updated_at: 2026-07-18T22:11:06Z
parent: browserid-ng-oup3
blocked_by:
    - browserid-ng-ru87
---

Issue device cert(s) after auth (fallback SMTP / primary interactive), incl batch (user + agent certs in one request) and config certs. IdP-signed. See docs/plans/2026-07-18-device-cert-model-migration-plan.md.

## Done: /device/issue (batch user+config) + /access/mint (fresh key, per-device status). HTTP tests green.
