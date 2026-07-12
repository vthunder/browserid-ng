---
# browserid-ng-7kxt
title: '@browserid/wallet (npx) + hosted guestbook demo'
status: in-progress
type: feature
priority: high
created_at: 2026-07-12T16:08:10Z
updated_at: 2026-07-12T16:23:24Z
---

Zero-checkout demo + the canonical install path for browserid agent support.

## @browserid/wallet (npx MCP server) — the main install
The general-purpose browserid wallet MCP server, run via 'npx -y @browserid/wallet' (bin + shebang). Built on @browserid/agent + @browserid/verify. Persists identity/credential to ~/.browserid/. Tools:
- identity, provision (paired flow), authorize(aud,scopes), get_assertion(aud) — the general wallet.
- sign_guestbook(message), read_guestbook() — the demo tools (talk to the hosted guestbook).
Install = one line in the MCP config: { command: 'npx', args: ['-y','@browserid/wallet'] }. Then a prompt.

## Hosted guestbook service (browserid.me)
- POST /guestbook { assertion, message } -> verify (audience https://browserid.me/guestbook, require agent presentation + 'sign' scope) -> record {message, agent, parent, scopes, at}. Sanitize + rate-limit.
- GET /guestbook -> public HTML page listing entries with attribution (agent, acting for parent). The shareable payoff.
- GET /guestbook/feed -> JSON for read_guestbook.
- Store: in-memory ring (v1; note persistence follow-up).

## Deliverables
- broker guestbook route + page (deploy to browserid.me, test).
- sdk/wallet package (publish-ready; user runs npm publish for @browserid/verify, @browserid/agent, @browserid/wallet).
- Docs: the one-line install + prompt.

Enabled by the JS agent SDK + paired provisioning (no Rust, no downloaded credential).

## Built + deployed (2026-07-12)
- Guestbook service (browserid-broker/src/routes/guestbook.rs): POST /guestbook (verify agent assertion, require 'sign' scope), GET /guestbook (public HTML page), GET /guestbook/feed (JSON). In-process ring. DEPLOYED to browserid.me + smoke-tested (page renders, feed works, bad assertion -> 401). FallbackFetcher localhost dev-bypass lets it be e2e-tested locally.
- @browserid/wallet (sdk/wallet): npx MCP server, ~/.browserid persistence, tools provision/identity/authorize/get_assertion/sign_guestbook/read_guestbook. Smoke-tested (tools register, read_guestbook hits live guestbook, identity->provision). Publish-ready.
- E2E: guestbook.spec.ts drives the full stack locally (provision->warrant->sign->public feed/page). Full suite 94 passed.
- README: one-line install + demo prompt featured.

## Remaining (user)
- npm publish @browserid/verify, @browserid/agent, @browserid/wallet (owns the @browserid org).
- Then the one-line 'npx @browserid/wallet' install works for anyone.
Follow-ups: guestbook persistence across deploys (currently in-memory ring); typed user_code /link UI.
