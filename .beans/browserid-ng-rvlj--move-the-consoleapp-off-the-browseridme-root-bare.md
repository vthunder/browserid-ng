---
# browserid-ng-rvlj
title: Move the console/app off the browserid.me root; bare domain becomes the marketing site
status: todo
type: feature
created_at: 2026-08-27T11:33:13Z
updated_at: 2026-08-27T11:33:13Z
---

## Motivation

Today the broker console/app lives at the `browserid.me` root and the marketing site at `www.browserid.me`, with a root→www redirect on selected paths. Clients — especially agents — reasonably assume the bare domain and www are the same site, so when they guess a path directly on the root domain (e.g. `browserid.me/pricing`) they hit a broker 404 instead of marketing content. The fix: treat the bare domain as the marketing site and move the console to a subdomain (e.g. `app.browserid.me` or `console.browserid.me`).

## Critical design decision (settle this before any code)

`browserid.me` is not just a web app origin — it is an **identity origin**:

- Passkey/WebAuthn RP ID is bound to the origin; moving it silently orphans users' passkeys.
- Assertions/certs carry the issuer origin; verifiers and warrant chains reference it.
- The `_browserid` DNS TXT root of trust and tenant delegation (`host=idp.browserid.me`) point at this infrastructure.
- Published SDKs (`@browserid-ng/agent`, `mcp-auth`, express/hono/js) default to `https://browserid.me` as broker origin — already shipped to npm.
- Sibling hosts exist and must keep working: `idp.browserid.me`, `agents.browserid.me`, `bsky.browserid.me`, `mcp-demo.browserid.me`.

So the plan must choose: **(a) split the human console UI off to a subdomain while protocol endpoints (issuance, verify, MCP, .well-known, OAuth AS) stay on the bare domain**, with marketing served for everything else on root; or **(b) move the whole broker origin** (much larger: passkey re-enrollment, SDK default churn, DNS changes, credential re-issuance). Option (a) is almost certainly the right shape — agents guessing marketing paths and agents hitting protocol endpoints can coexist on root if the routing is explicit — but write the decision down with reasoning before starting.

## Plan checklist

- [ ] Inventory the root-domain surface: enumerate every route the broker serves on `browserid.me` and classify each as console-UI / protocol-endpoint / redirect (broker has ~31 self-referencing host mentions in `browserid-broker/src` as a starting point)
- [ ] Decide the split (option a vs b above) and the console subdomain name; record the decision here
- [ ] Map session/cookie implications: console on a subdomain vs cookies scoped to the bare domain (login flows, dialog.js, postMessage origins)
- [ ] Check WebAuthn RP ID scope: RP ID `browserid.me` covers subdomains, so passkeys should survive a console-on-subdomain move — verify, don't assume
- [ ] Plan redirects: old console URLs on root → new subdomain (permanent), and root serves marketing for everything not a protocol endpoint; kill or invert the current root→www redirect (decide www's fate: redirect www→root?)
- [ ] Audit external references: OAuth client redirect URIs, PostHog config, email templates/links, docs, published SDK READMEs, marketing-site links, sandmill-infra dokku vhost config
- [ ] Update e2e/Playwright tests and CSP/inline-script-hash guards for any moved pages
- [ ] Staged rollout plan: serve console on both origins during transition, then flip root paths to marketing, monitor 404s/analytics before removing old paths
- [ ] Verify agents' guessed-path experience end-to-end (bare-domain path guesses land on marketing or a helpful 404 with pointers)

## Notes

- `browserid-ng-93z2` (origin-split spike: what breaks when moving key-custody/IdP surface to a separate origin) is completed and should be re-read first — it likely already answers several of the questions above.
- Infra changes go through sandmill-infra (run bin/audit-host.sh first).
