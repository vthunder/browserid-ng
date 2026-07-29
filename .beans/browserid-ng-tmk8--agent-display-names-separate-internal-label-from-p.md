---
# browserid-ng-tmk8
title: 'Agent display names: separate internal label from public byline'
status: in-progress
type: feature
priority: normal
created_at: 2026-07-29T18:04:46Z
updated_at: 2026-07-29T19:00:16Z
---

Live guestbook demo (bean browserid-ng-kp0a) surfaced a naming-consent gap: the display name set when pairing a device/agent at browserid.me/account was published verbatim as the public guestbook byline ('Claude.ai (web)'). The human experienced that name as an internal management label (like naming an SSH key), not a public persona. Current feed names ('Dan's Claude Code', 'Claude.ai (web)') read as infrastructure vocabulary leaking into a public space.

Options discussed:
1. Keep pairing names internal-only; services must always obtain a public name explicitly.
2. Keep one name but relabel pairing UI as 'public display name — shown wherever this agent acts'.
3. Dual names: internal label (device management, revocation UI) + optional public byline (persona); fallback behavior when byline unset TBD.

Recommendation: option 3 — the two roles genuinely differ (a good management label describes the channel; a good byline is a persona), and option 2 forces one string to do both jobs badly.

Touches: pairing/approval UI copy, broker account schema, guestbook default-name logic, wallet sign_guestbook description ('the display name your human confirmed when pairing'). Decision needed before implementation.

## Investigation (2026-07-29) — where the name actually lives

NOT in any certificate. Cert claims are {typ, iss, iat, exp, purpose/identity, holder, public-key, status} only. The name is broker-side DB state, and there are already TWO fields:

- **holder label** (set_holder_label; store/models.rs) — the Devices & services list entry. Internal-only today: never served to RPs or agents.
- **identity display_name** (set_email_display_name; email record) — used on later permission cards (shown to the owning human) AND published by the guestbook as the byline (guestbook.rs:286-303 fallback chain: per-post name → display_name → email local-part).

The conflation happens at pairing approval (browserid-registrar/src/agent_provision.rs:1414-1444): the ONE display_name the human types is written to BOTH fields. The approval UI never says the name will be public.

Agent exposure today: agents cannot read either field pre-publication — no API returns them, they are not in certs or presentations. The agent learns the byline only from the guestbook sign RESPONSE (post-hoc, already public). So the private-even-from-agents property basically holds today; the leak is the guestbook fallback chain publishing an internally-consented string.

## Decided design (Dan, 2026-07-29)

Add a public display name distinct from the internal label:

1. New per-identity field `public_name` (email record). Set in the pairing approval UI as a SEPARATE optional field labeled as public ("shown wherever this agent acts publicly"), editable later at browserid.me/account.
2. Guestbook fallback chain becomes: per-post name → public_name → email local-part. **display_name is removed from the chain** — existing values were consented as labels, not bylines; no grandfathering.
3. holder label stays internal-only (account UI); display_name stays for permission cards (shown only to the owning human) — or is folded into the holder label later.
4. Invariant to keep: unpublished names are never served to agents/RPs via any API; the sign response may echo the byline it just published (already public).

Touches: browserid-broker store (schema + migration: add public_name), guestbook.rs fallback, agent_provision.rs approval flow + UI copy, account page edit UI, wallet-service sign_guestbook description ("the display name your human confirmed when pairing" → public_name semantics).

## Scope additions (Dan, 2026-07-29)

- Remove per-post `name` from BOTH MCP surfaces (wallet sign_guestbook, guestbook-mcp) AND stop honoring it in the guestbook HTTP API (keep accepting the field for old-wallet compat, ignore the value — beware the a9u4-style 422 on unknown/missing fields). Byline is always the human-configured public name: per-post agent-chosen bylines are gone by design (the name next to the checkmark must be human-set).
- Wallet `identity` tool reports the agent's public display name. Data path: new UNAUTHENTICATED broker endpoint GET /api/public-name?identity=<email> -> {identity, public_name} with local-part fallback (public-by-intent, so an open lookup is consistent; returns the same fallback for unknown identities so it leaks no registration info).

- [x] Broker: schema + store (public_name on email records) — migrate_v21, both stores, trait + deref
- [x] Broker: guestbook fallback -> public_name -> local-part; per-post name accepted-but-ignored (compat)
- [x] Broker: GET /public-name endpoint (bare-path convention; no registration oracle)
- [x] Registrar: approval flow accepts separate public_name (host hook + glue); approval UI has a second explicitly-public field, internal name marked private
- [x] Account page: Agent names card (list + prompt-edit via /wsapi/set_public_name; list_emails grew public_names)
- [x] wallet-service AND sdk/wallet local twin: drop name param; identity tool fetches /public-name (fail-soft)
- [x] guestbook-mcp: drop name param
- [ ] Tests across all of the above (broker agent_flows_v2 extended + CSP hash bumped; node suites green; full workspace run in progress)
