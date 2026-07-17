---
# browserid-ng-3nsg
title: Agent provisioning fails for external PRIMARY-IdP delegators (e.g. danmills@sandmill.org)
status: todo
type: bug
priority: high
created_at: 2026-07-17T13:01:56Z
updated_at: 2026-07-17T14:31:15Z
parent: browserid-ng-mr2n
---

`mingo login` as danmills@sandmill.org fails at the agent-identity mint: "IdP rejected the request (404)". Root cause corrected (live-probed 2026-07-17):

## Not a wrong-URL bug — a capability gap
- `dig TXT _browserid.sandmill.org` publishes sandmill.org's OWN Ed25519 key; `https://sandmill.org/.well-known/browserid` (200) advertises `authentication:/browserid/auth`, `provisioning:/browserid/provision`. So sandmill.org is a SELF-HOSTED CLASSIC primary IdP — it is NOT delegated to browserid.me (my initial "delegated domain, target the provider" diagnosis was wrong).
- But sandmill.org implements CLASSIC INTERACTIVE provisioning only: `/browserid/provision` GET 200/POST 405, while `/provision/mint`, `/wsapi/session_context`, `/agents` all 404. It is not a browserid-broker and has NO agent delegation-chain mint.
- The agent mint targets the delegator's home IdP = U_cert issuer = sandmill.org (the browser roots a PRIMARY's U_cert at its own IdP). So AgentIdentity::provision POSTs sandmill.org/provision/mint → 404.
- browserid.me can't substitute as-is: broker mint (browserid-broker/src/routes/agent.rs:85 verify_as_target_idp) requires `verified.issuer == state.domain` AND verifies the U_cert against the broker's OWN key. sandmill.org's U_cert (issuer=sandmill.org, signed by sandmill.org's key) fails both → a client fallback to browserid.me gets 400, not success.

CONCLUSION: there is NO agent-mint endpoint anywhere for a sandmill.org-rooted delegator. mingo.place works only because it is a self-hosted browserid-broker (issuer-domain == IdP host == implements /provision/mint).

## Shipped (client-side, no deploy): fail-fast UX — mingo commit c88d23e
`mingo login` now catches the mint failure and, when the home IdP != broker, replaces the cryptic 404 with an actionable explanation of the primary-IdP gap + options, and persists the browser-approved credential so the delegation isn't wasted. mingo.place/self-hosted path unaffected. Tests pass.

## The real fix (browserid.me broker feature + redeploy — NOT built)
Make browserid.me host agent identities for external PRIMARY-IdP delegators it has authenticated: in browserid-broker mint, verify the delegator's U_cert against the issuer's DNS-discovered `_browserid` key (the broker already has DNS discovery / fallback_fetcher) instead of assuming its own key; relax `verified.issuer == state.domain` to accept a discoverable primary the broker has an account link for; mint the agent as `<name>@browserid.me` with parent = the external primary (danmills@sandmill.org). This is exactly the mingo-poster shape (agent@provider, parent=external primary) and is the same territory as cross-issuer agent warrants (browserid-ng-yhcx). Needs a browserid.me redeploy (live infra).

## Impact on the mingo admin migration (mingo-3mhi)
The email-rooted-admin plan's ergonomic path (`mingo login` -> warrant as: danmills@sandmill.org -> admin) is blocked until this lands. The dual-admin state is already live and safe; verifying danmills + the cutover need danmills to make an attributed write, which needs EITHER this broker feature OR a classic-cert-signing path (also needs tooling) OR reconsidering the admin identity (a browserid.me-rooted identity works today).

## Relates
browserid-ng-wmgb (CLI-auth), browserid-ng-yhcx (cross-issuer warrants), mingo-3mhi (admin migration).
