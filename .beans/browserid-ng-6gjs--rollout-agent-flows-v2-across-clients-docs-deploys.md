---
# browserid-ng-6gjs
title: 'Rollout: agent flows v2 across clients + docs + deploys'
status: completed
type: task
priority: normal
created_at: 2026-07-26T18:57:41Z
updated_at: 2026-07-26T19:30:32Z
---

Follow-on to eywc/t1jp: update every consumer to the new protocol (grantor pin incl. 'self', message field, two-stage approval, poll reasons), refresh documentation/readmes, and deploy everything for live testing.

- [x] browserid-ng: browserid-rp — no change needed (verification-only; warrant/presentation shapes unchanged)
- [x] browserid-ng: sdk/wallet MCP — authorize gains a message input, denial reasons recorded+surfaced; marketing sample refreshed; mcp-agent-auth example left on the legacy Agent API (works unchanged; tnwb tracks its drift)
- [x] browserid-ng: sdk/agent README gains a device-model/v2 section (grantor pin, message, grantsDenied, denial reasons); wallet README tweak; spec was updated in eywc
- [x] browserid-ng: committed (c14489b + ac7b93e incl. rust-SDK grants_denied), pushed; deploy-broker CI green twice; live CSP serves the new account.html hash
- [x] mingo: revs → ac7b93e; login passes message + surfaces grants_denied; poster sends message; shipped together with the pre-existing 22hu grantor/grantee parse WIP (bean completed); 69 tests green; commit 1a20b32 pushed; dokku deploy in flight
- [x] sbo: NO changes needed — depends only on browserid-core at an older pinned rev, no agent SDK, no /warrant calls; provision-agent CLI is a stub. No deploy.
- [x] browserid-bsky: setup --for accepts 'self' (pins as-itself — the returning-human 409 fix), messages on both requests, grantsDenied handled without saving half a setup, guide + README updated to 'agree the shape, then pin it'; deps → ac7b93e; 36 tests green; acd14a2 pushed (auto-deploys bridge)
- [x] verify deployed broker serves the new pages (CSP hash present in live header; /account + /consent serve the I/P flow strings; mingo.place, bsky.browserid.me, www.browserid.me all 200 on the new deploys)

## Summary of Changes

All consumers updated and deployed:
- browserid-ng: broker deployed twice via CI (c14489b, ac7b93e — the second adds Provisioned.grants_denied to the rust SDK); www redeployed via the marketing subtree split (71cdbf0); browserid-rp needed nothing; wallet MCP gained message + denial-reason surfacing; sdk/agent README documents the v2 fields.
- mingo (1a20b32, deployed to mingo.place): revs bumped, login message + grants_denied handling, poster message; shipped with the pre-existing 22hu grantor/grantee parse fix.
- sbo: unaffected (browserid-core-only, older pinned rev) — no change, no deploy.
- browserid-bsky (acd14a2, bridge CI deployed): setup --for self pins as-itself (the returning-human 409 fix), messages, grantsDenied handling, guide/README updated.

Not done (flagged): npm publish of @browserid-ng/agent 0.3.0 + @browserid-ng/bsky pin bump — local dev uses the symlinked SDK; publishing is manual and left to Dan.
