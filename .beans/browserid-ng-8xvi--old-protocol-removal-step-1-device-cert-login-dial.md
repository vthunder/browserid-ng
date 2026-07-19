---
# browserid-ng-8xvi
title: 'Old-protocol removal step 1: device-cert login dialog + fallback-IdP device issuance'
status: in-progress
type: feature
priority: normal
created_at: 2026-07-19T10:13:26Z
updated_at: 2026-07-19T10:33:30Z
parent: browserid-ng-oup3
---

Rewrite browserid-broker/static/{dialog.js,include.js} as the device-cert cold-start login mediator (email -> discovery -> IdP /device_cert (fallback SMTP or primary popup) -> /access/mint -> config-cert-signed warrant -> return 4-object bundle to RP). Convert routes/fallback_idp.rs to issue device certs (keep SMTP verification, drop classic cert_key). Per docs/plans/2026-07-19-old-protocol-removal-inventory.md sections B/C.

- [x] Convert fallback_idp.rs: /auth/device_cert issues device certs (user+config), classic cert_key path removed; fb_email cookie now SameSite=Lax (dialog is same-origin)
- [x] Rewrite dialog.js + dialog.html: discovery-driven device-cert state machine (fallback SMTP inline, keystore fast path, primary popup protocol)
- [x] Rewrite include.js: new promise API browserid.login() -> {presentation, email}; navigator.id removed
- [x] keystore.js: device store (DB v3) for device/config cert records
- [x] Primary popup path (dialog side): discovery 'device-authorization' page + postMessage handshake; sandmill still needs the page (separate repo work)
- [x] Tests: fallback_idp_test rewritten for device flow incl. full presentation verify; workspace green; no new inline scripts (CSP unchanged)
- [ ] Smoke: cold-start login via dialog against browserid.me (deploy gated: converting demos/RP libs first — new include.js drops navigator.id, would break mingo.place until step 6)
- [x] Real-browser (playwright) e2e: cold-start SMTP login + keystore fast-path both verify via /verify-access on local broker
