---
# browserid-ng-8xvi
title: 'Old-protocol removal step 1: device-cert login dialog + fallback-IdP device issuance'
status: in-progress
type: feature
priority: normal
created_at: 2026-07-19T10:13:26Z
updated_at: 2026-07-19T13:53:33Z
parent: browserid-ng-oup3
---

Rewrite browserid-broker/static/{dialog.js,include.js} as the device-cert cold-start login mediator (email -> discovery -> IdP /device_cert (fallback SMTP or primary popup) -> /access/mint -> config-cert-signed warrant -> return 4-object bundle to RP). Convert routes/fallback_idp.rs to issue device certs (keep SMTP verification, drop classic cert_key). Per docs/plans/2026-07-19-old-protocol-removal-inventory.md sections B/C.

- [x] Convert fallback_idp.rs: /auth/device_cert issues device certs (user+config), classic cert_key path removed; fb_email cookie now SameSite=Lax (dialog is same-origin)
- [x] Rewrite dialog.js + dialog.html: discovery-driven device-cert state machine (fallback SMTP inline, keystore fast path, primary popup protocol)
- [x] Rewrite include.js: new promise API browserid.login() -> {presentation, email}; navigator.id removed
- [x] keystore.js: device store (DB v3) for device/config cert records
- [x] Primary popup path (dialog side): discovery 'device-authorization' page + postMessage handshake; sandmill still needs the page (separate repo work)
- [x] Tests: fallback_idp_test rewritten for device flow incl. full presentation verify; workspace green; no new inline scripts (CSP unchanged)
- [x] DEPLOYED to browserid.me (c187c47) + prod smoke green: admin-seed account -> /device/issue (+* glob confirmed) -> /access/mint -> warrant+assertion -> /verify-access okay. Classic /verify is 404 in prod. NOTE: mingo.place login is broken until its migration (include.js has no navigator.id — expected cutover breakage).
- [x] Real-browser (playwright) e2e: cold-start SMTP login + keystore fast-path both verify via /verify-access on local broker

## Progress (2026-07-19, session 2)

Steps 1-4 of the removal punch-list are DONE and committed (2240ae6, adbc8b0, a5fde9e + guestbook, fe80581):
- [x] Step 1: device-cert login dialog + fallback IdP device issuance (real-browser e2e green)
- [x] Step 2: RP verification — browserid-rp (AccessPresentation + 3-ref status checks), sdk/js -> /verify-access, rp-quickstart + mcp-agent-auth demos, guestbook on device bundle
- [x] Step 3: registrar warrant surface — /warrant/request + /warrant/poll (agent device-cert authed, RFC 8628), consent.html signs device warrants with the CONFIG key, respond/register verify signatures against the presented config cert; config certs at login now cover the +tag namespace
- [x] Step 4: classic protocol REMOVED from core+broker (Certificate/BackedAssertion/classic Warrant/cert_key//verify/FedCM/primary auth/fallback pages). grep clean in .rs. 41 suites green.

REMAINING:
- [x] Deploy to browserid.me + prod smoke (mingo.place login broken until step 6 as expected)
- [x] sandmill (2a0f7af, deployed): /browserid/device-authorize popup (fragment params -> sessionStorage across the /login round-trip -> first-party device_cert -> postMessage to opener), discovery advertises it, CORS on the headless access_cert mint, force.json on the API routes, config cert +* glob. VERIFIED live: discovery + page 200 + preflight 204 + broker address_info surfaces device_auth/access_mint for danmills@sandmill.org. Remaining: a HUMAN click-through of https://browserid.me/broker-demo with danmills@sandmill.org (needs the real sandmill password).
- [ ] account.html + agents.html: strip dead classic sections (identity Activate via cert_key, chain-based agent create); repoint agents UI at /agent-provision device flow
- [ ] sdk/agent + sdk/wallet JS -> device model (wallet gates guestbook signing; guestbook server now expects device presentations)
- [ ] SBO relocation 3b8m -> then delete communication_iframe* + common/js classic stack + winchan dialog-side? (winchan still used by dialog)
- [ ] marketing/ classic snippets
- [ ] Consumers: mingo (idp+web+cli+poster), sbo — finish device migration, bump pins

## Session 2 outcome
Steps 1-4 of the removal + deploys are done. browserid.me and sandmill.org both run the device-cert model in production; the classic protocol is gone from the Rust workspace. Try it: https://browserid.me/broker-demo (any no-primary email = SMTP fallback; danmills@sandmill.org = primary popup).

Next work (in order): (1) human click-through of the sandmill primary path; (2) mingo migration (idp/web/cli/poster) + sbo, pin bump — restores mingo.place login; (3) sdk/agent + sdk/wallet JS -> device model (guestbook signing depends on it); (4) SBO relocation 3b8m then delete communication_iframe + common/js classic stack; (5) account.html/agents.html dead-section cleanup; (6) marketing snippets.

## Correction (session 3): dialog UX restored
The step-1 rewrite over-reached: it replaced the account-based dialog UX (session chooser over ALL account identities, password auth, account creation, reset) with an SMTP-code-per-login flow. Restored the ORIGINAL dialog state machine (ported from 2240ae6^) with device-cert internals only: /device/issue instead of cert_key, 4-object presentation instead of cert~assertion, device-authorization popup instead of the provisioning iframe. transition_no_password now always uses the reset-code flow (/wsapi/set_password is gone). The dialog-driven SMTP fallback surface (/auth/send|verify|device_cert) remains server-side for conformance/external mediators but the dialog no longer uses it. e2e: create-account cold start + session chooser both green in a real browser.

## Correction (session 3b): RP API restored + primary chooser memory
- include.js is the ORIGINAL navigator.id implementation again (recovered from git), ported: onlogin delivers the presentation; FedCM lanes removed; browserid.login() kept as a promise wrapper. mingo.place's watch() calls work again (its backend still needs the /verify -> /verify-access migration).
- NEW /wsapi/auth_with_presentation (device-model auth_with_assertion, same link/transfer semantics). The dialog's primary flow does the classic dual-presentation dance so primary identities join a broker account and the chooser remembers them.
- Deployed + verified live on browserid.me.
