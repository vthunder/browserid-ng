---
# browserid-ng-8xvi
title: 'Old-protocol removal step 1: device-cert login dialog + fallback-IdP device issuance'
status: in-progress
type: feature
priority: normal
created_at: 2026-07-19T10:13:26Z
updated_at: 2026-07-19T11:08:53Z
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

## Progress (2026-07-19, session 2)

Steps 1-4 of the removal punch-list are DONE and committed (2240ae6, adbc8b0, a5fde9e + guestbook, fe80581):
- [x] Step 1: device-cert login dialog + fallback IdP device issuance (real-browser e2e green)
- [x] Step 2: RP verification — browserid-rp (AccessPresentation + 3-ref status checks), sdk/js -> /verify-access, rp-quickstart + mcp-agent-auth demos, guestbook on device bundle
- [x] Step 3: registrar warrant surface — /warrant/request + /warrant/poll (agent device-cert authed, RFC 8628), consent.html signs device warrants with the CONFIG key, respond/register verify signatures against the presented config cert; config certs at login now cover the +tag namespace
- [x] Step 4: classic protocol REMOVED from core+broker (Certificate/BackedAssertion/classic Warrant/cert_key//verify/FedCM/primary auth/fallback pages). grep clean in .rs. 41 suites green.

REMAINING:
- [ ] Deploy to browserid.me + prod smoke (NOTE: breaks mingo.place login until step 6 — new include.js has no navigator.id)
- [ ] sandmill: device-authorization popup page + CORS/Accept-JSON fix on access_cert mint (~/src/sandmill)
- [ ] account.html + agents.html: strip dead classic sections (identity Activate via cert_key, chain-based agent create); repoint agents UI at /agent-provision device flow
- [ ] sdk/agent + sdk/wallet JS -> device model (wallet gates guestbook signing; guestbook server now expects device presentations)
- [ ] SBO relocation 3b8m -> then delete communication_iframe* + common/js classic stack + winchan dialog-side? (winchan still used by dialog)
- [ ] marketing/ classic snippets
- [ ] Consumers: mingo (idp+web+cli+poster), sbo — finish device migration, bump pins
