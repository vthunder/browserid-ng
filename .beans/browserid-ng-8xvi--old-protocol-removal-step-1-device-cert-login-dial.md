---
# browserid-ng-8xvi
title: 'Old-protocol removal step 1: device-cert login dialog + fallback-IdP device issuance'
status: completed
type: feature
priority: normal
created_at: 2026-07-19T10:13:26Z
updated_at: 2026-08-26T23:09:19Z
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
- [x] account.html + agents.html: strip dead classic sections (ad282d6, d632e36; standalone authorize.html replaced the old agents UI)
- [x] sdk/agent + sdk/wallet JS -> device model (DeviceAgent in sdk/agent, agent 0.5.x published; guestbook verifies device presentations, 567b969)
- [x] SBO relocation 3b8m -> communication_iframe* + classic common/js stack deleted (d9a6baf); winchan deliberately retained for the dialog
- [x] marketing/ classic snippets (developers.md on device-model /verify; fedcm-demo on the restored presentation-based navigator.id)
- [x] Consumers: mingo (idp+web+cli+poster), sbo — migrated and deployed (mingo 154cd7f, sbo 55314e9/ac48868); only sbo-cli identity-command rebuild remains, tracked separately

## Session 2 outcome
Steps 1-4 of the removal + deploys are done. browserid.me and sandmill.org both run the device-cert model in production; the classic protocol is gone from the Rust workspace. Try it: https://browserid.me/broker-demo (any no-primary email = SMTP fallback; danmills@sandmill.org = primary popup).

Next work (in order): (1) human click-through of the sandmill primary path; (2) mingo migration (idp/web/cli/poster) + sbo, pin bump — restores mingo.place login; (3) sdk/agent + sdk/wallet JS -> device model (guestbook signing depends on it); (4) SBO relocation 3b8m then delete communication_iframe + common/js classic stack; (5) account.html/agents.html dead-section cleanup; (6) marketing snippets.

## Correction (session 3): dialog UX restored
The step-1 rewrite over-reached: it replaced the account-based dialog UX (session chooser over ALL account identities, password auth, account creation, reset) with an SMTP-code-per-login flow. Restored the ORIGINAL dialog state machine (ported from 2240ae6^) with device-cert internals only: /device/issue instead of cert_key, 4-object presentation instead of cert~assertion, device-authorization popup instead of the provisioning iframe. transition_no_password now always uses the reset-code flow (/wsapi/set_password is gone). The dialog-driven SMTP fallback surface (/auth/send|verify|device_cert) remains server-side for conformance/external mediators but the dialog no longer uses it. e2e: create-account cold start + session chooser both green in a real browser.

## Correction (session 3b): RP API restored + primary chooser memory
- include.js is the ORIGINAL navigator.id implementation again (recovered from git), ported: onlogin delivers the presentation; FedCM lanes removed; browserid.login() kept as a promise wrapper. mingo.place's watch() calls work again (its backend still needs the /verify -> /verify-access migration).
- NEW /wsapi/auth_with_presentation (device-model auth_with_assertion, same link/transfer semantics). The dialog's primary flow does the classic dual-presentation dance so primary identities join a broker account and the chooser remembers them.
- Deployed + verified live on browserid.me.

## Assessment notes (session 3c)
- FedCM: removed because /fedcm/assertion minted classic cert~assertion server-side (dual-impl). Re-spike on device certs is feasible (server mints a full presentation server-side; same server-custody trade-off the classic lane had). Pending user decision.
- mingo WIP (~/src/mingo, uncommitted): KEEP. mingo-idp/src/device.rs (device_cert + access/mint, mirrors sandmill), discovery advert, device_cert_e2e conformance test vs real DeviceAgent SDK, mingo-app/src/device_login.rs (mint+present half, storage). Blockers: mingo's classic modules (agent.rs, poster.rs, verify.rs, routes.rs cert_key) don't compile against post-cutover browserid-ng main — pin bump requires stripping mingo's classic surface; well_known can use the new typed SupportDocument fields; mingo needs a device-authorization popup page; device_login can now wire to /warrant/request+poll.

## mingo site migration (session 3d) — deployed from ~/src/mingo branch device-migration
mingo-idp+web ported (see mingo commit): from-presentation session, device-authorize popup, typed discovery, classic surface removed, poster stubbed 503, pinned to browserid-ng 36b49c4. CLI/poster follow-ups in a new bean.

## mingo.place LIVE on the device model (session 3d)
Deployed (mingo 154cd7f). Verified live: discovery advertises device-cert/access-cert/device-authorization; /device-authorize 200; /session/from-presentation fail-closed; poster reports disabled cleanly; classic /cert_key gone; mint CORS open for the dialog; broker address_info for @mingo.place surfaces device_auth+access_mint; SPA boots error-free and sign-in opens the browserid dialog (playwright). Remaining human check: full login click-through + handle claim.

## sbo verifier migrated (session 4) — branch device-migration (ac48868)
verify_device_attribution is the sole attribution path (4-object presentation, DNSSEC-rooted, envelope key == access-cert key). Classic Auth-Cert/Warrant verification removed; shared DNSSEC substrate kept. sbo-daemon validate.rs + authorize.rs + sbo-capture rewired; pinned to browserid-ng b2e4f82. Workspace green (354 pass, 2 ignored live). sbo-cli identity commands stubbed pending a device-cert CLI rebuild (follow-up, tracked in the mingo-follow-ups bean scope).

## Summary of Changes

The device-cert login mediator shipped: dialog.js/include.js rewritten (then re-ported to the original account-based UX and navigator.id API on device internals), fallback_idp issues device+config certs, and the classic protocol was removed from the Rust workspace — all deployed to browserid.me with real-browser e2e green. Every follow-on removal item has since landed: account/agents classic UI purged, sdk/agent+wallet on the device model, the hidden iframe and classic common/js stack deleted (3b8m), marketing rewritten against the device-model /verify, and mingo + sbo fully migrated and deployed. FedCM was later re-introduced natively on the device model. (Closed by audit 2026-08-27.)
