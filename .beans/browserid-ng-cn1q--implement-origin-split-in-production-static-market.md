---
# browserid-ng-cn1q
title: 'Implement origin split in production: static marketing site on www, broker stays auth/issuer on apex'
status: completed
type: feature
priority: high
created_at: 2026-07-13T09:03:46Z
updated_at: 2026-07-13T10:15:23Z
blocked_by:
    - browserid-ng-omxf
---

Implementing the split validated by the spike (browserid-ng-93z2).

Topology (decided 2026-07-13): auth/issuer stays on apex browserid.me (broker UNCHANGED, no cert/DNSSEC/credential migration); marketing = separate STATIC site on www.browserid.me (not the broker binary). Guestbook page moves to www (read-only display, agent-signed via MCP); feed JSON + POST sign API stay on broker; audience guestbook_audience stays browserid.me/guestbook — unchanged.

## Status: code complete, verified locally; awaiting production DNS/dokku cutover

## Done
- [x] Static marketing site: marketing/{index.html,guestbook.html,config.js,README.md}. Landing copied from broker static; guestbook is client-rendered (fetches ${authOrigin}/guestbook/feed cross-origin). Auth links (Sign in -> /account) resolve to authOrigin via config.js + data-auth-href rewrite.
- [x] Broker: MARKETING_URL env (config threaded via AppState.marketing_url in state.rs + main.rs). When set, GET / and GET /guestbook 308-redirect to the marketing site (routes/mod.rs, routes/guestbook.rs::page now returns Response). Unset -> broker serves them as before (local/dev/e2e unaffected).
- [x] Feed JSON (/guestbook/feed) + POST sign (/guestbook) stay on the auth origin; CORS already allow_origin(Any) so cross-origin feed fetch works.
- [x] e2e: e2e-tests/tests/marketing-split.spec.ts (5 tests, all green): marketing guestbook renders broker feed cross-origin with audience unchanged; graceful error when feed unreachable; Sign-in link points at auth origin; broker 308-redirects / and /guestbook when MARKETING_URL set (spawns a 2nd broker with the env); feed+sign API not redirected. No regressions across cross-origin/dialog/sign-in/include specs (25/25).
- [x] Deploy runbook: marketing/README.md (new www dokku app, DNS/TLS, config:set id MARKETING_URL=...).

## Deferred (follow-ups, intentionally NOT bundled)
- [ ] CSP tightening on the auth origin (script-src 'self' + inline-script hashes, connect-src 'self'). Kept separate: a strict script-src/connect-src risks breaking the primary-IdP cross-origin provisioning iframe flow and needs its own careful pass with the e2e suite as the safety net. Filed as follow-up.
- [ ] Move the demo RPs (/broker-demo, /fallback-demo) to the marketing site (currently still on the broker; they point include.js at the broker origin, which is correct). Optional.
- [ ] Production cutover (DNS www.browserid.me, new dokku app, TLS, config:set MARKETING_URL) — requires host access; runbook in marketing/README.md.

## Notes
- Analytics (browserid-ng-omxf) is now unblocked: the www origin carries no keystore/cookies/wsapi, so locked-down posthog-js there is contained.
- Phase 2 (analytics on auth/app pages like /account, dialog) is still viable incrementally on the auth origin via server-side events + first-party locked-down JS under strict CSP — see the CSP follow-up.
- Pre-existing e2e breakage (guestbook provisioning UI, #pv-handles hidden by the prefix-chip commit) filed separately; not caused by this work.


## Production deploy state (2026-07-13)

Deployed via dokku@sandmill.org (host 198.199.110.160, shared 24G disk):

- [x] `www` dokku app created; domain www.browserid.me; builder pinned to dockerfile; static nginx site deployed (marketing/Dockerfile + nginx.conf). Container healthy. Verified via Host header: /, /guestbook, /config.js all serve correctly; config.js authOrigin=https://browserid.me.
- [x] New broker (with MARKETING_URL support) deployed to `id` from branch origin-split (commit 7373d2d) -> id main. Build ~9min, disk held (6.3G free min). Container healthy. Behavior UNCHANGED because MARKETING_URL is unset: apex still serves landing + guestbook (200), issuer well-known unchanged, feed API 200 with CORS *.
- [ ] **BLOCKED ON USER**: add DNS A record `www.browserid.me -> 198.199.110.160` at Namecheap (browserid.me NS = registrar-servers.com; no wildcard; not manageable via ssh).
- [ ] After DNS resolves: `ssh dokku@sandmill.org letsencrypt:enable www` (TLS for www.browserid.me).
- [ ] Final flip: `ssh dokku@sandmill.org config:set id MARKETING_URL=https://www.browserid.me` -> apex GET / and GET /guestbook 308-redirect to www; auth cluster + feed/sign API stay on apex.

Local branch: origin-split (commit 7373d2d). NOT merged to main / NOT pushed to GitHub origin yet (dokku id remote has it as main). CSP tightening deferred (browserid-ng-kt5y).


## LIVE IN PRODUCTION (2026-07-13)

Cutover complete and verified:
- DNS www.browserid.me -> 198.199.110.160 (added by Dan, propagated).
- letsencrypt:enable www -> TLS live (ssl_verify=0, HSTS on).
- config:set id MARKETING_URL=https://www.browserid.me -> flip on (container restarted).

Verified from the public internet:
- GET https://browserid.me/ -> 308 -> https://www.browserid.me/ (landing).
- GET https://browserid.me/guestbook -> 308 -> https://www.browserid.me/guestbook.
- www guestbook renders the live feed cross-origin (2 entries) — audience unchanged.
- Auth cluster intact on apex: /account, /.well-known/browserid, /dialog/dialog.html, /include.js all 200.
- Feed JSON stays on apex (200); POST /guestbook still verifies (junk -> 401).

The marketing origin (www.browserid.me) now carries no keystore/cookies/wsapi — analytics can go there safely (browserid-ng-omxf unblocked).
