---
# browserid-ng-kmvm
title: 'fallback_idp: accept client-supplied browser holder'
status: todo
type: task
priority: low
created_at: 2026-07-21T21:02:32Z
updated_at: 2026-07-21T21:02:32Z
parent: browserid-ng-oup3
---

The fallback-IdP /auth/device_cert path still self-assigns the holder server-side. Accept the optional client holder param (validated to the account's browsers namespace) like /device/issue does, so fallback issuance reuses the one-holder-per-browser. See docs/plans/2026-07-21-broker-assigned-holder-deep-dive.md.
