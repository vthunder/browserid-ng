---
# browserid-ng-cn1q
title: 'Implement origin split in production: static marketing site on www, broker stays auth/issuer on apex'
status: in-progress
type: feature
priority: high
created_at: 2026-07-13T09:03:46Z
updated_at: 2026-07-13T09:16:26Z
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
