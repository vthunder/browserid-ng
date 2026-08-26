---
# browserid-ng-qgpv
title: 'Explore: signed agent attribution for plain HTTP (open alternative to Web Bot Auth)'
status: todo
type: task
priority: normal
created_at: 2026-08-26T23:21:35Z
updated_at: 2026-08-26T23:33:39Z
---

## Idea

Borrowed authority currently works where a site runs mcp-auth — but most of what agents do is ordinary HTTP. Explore an HTTP-level attribution scheme: any agent request can carry a signature (likely RFC 9421 HTTP Message Signatures) bound to the agent's device cert + warrant, verifiable by anyone via the same DNS trust root. No registry, no blessed-crawler list.

Sites get per-agent rate limits, blocklists, and attribution ("consequences need an address", principle 5) without a CAPTCHA arms race; agents get "acting as myself works everywhere" beyond MCP (principle 5: honesty cheaper than masquerade).

## Why timely

Cloudflare's Web Bot Auth / signed-agents direction is standardizing exactly a registry-of-blessed-parties model right now — a gatekeeper design (principle 2's antithesis) likely to win by default if no open alternative exists. Same wedge logic as MCP — a new lane with no entrenched incumbent — but at web scale, and time-sensitive.

## Open questions

- How much of the presentation travels per-request vs. cached per-origin (a 4-object presentation per fetch is heavy; maybe first-contact handshake + short-lived session binding)?
- Replay + scope semantics for a signed request (audience = origin? path patterns from the warrant?)
- Verification cost story for CDNs/origins — reuse the hosted /verify? per-origin verifier middleware?
- Relationship to the IETF web-bot-auth draft: interop where possible (same signature envelope, different key-discovery/trust root) vs. clean-sheet.
- Policy surface: how a site *declares* it wants attributed-agent traffic (headers? .well-known? robots.txt successor?).

## First steps

- [ ] Read the web-bot-auth / HTTP Message Signatures drafts; write a comparison + design sketch (docs/plans/)
- [ ] Prototype: fetch-wrapper in sdk/agent that signs requests + a tiny express/hono verifying middleware
- [ ] Demo: a site that rate-limits anonymous bots hard but welcomes attributed agents

## Design sketch (2026-08-27 discussion)

**Envelope:** RFC 9421 HTTP Message Signatures — the agent signs covered components (@method, @authority, @target-uri, content-digest, created/expires + nonce) with its access-cert key on every request. Same envelope web-bot-auth uses, so a verifier can support both; the fork is trust/key discovery.

**Trust:** web-bot-auth points the keyid at an operator-owned key directory URL and gets trust from a registry of known operators. Ours: the keyid identifies a cached identity chain (device cert + access cert) whose trust resolves from the agent's email-shaped name via the DNSSEC _browserid root — the name declares its issuer, no registry anywhere.

**Two tiers, cleanly separated:**
- Tier 1 — attribution (the new thing): device+access certs only, no site-specific warrant. Proves *who is acting and on whose behalf* (agent identity + grantor; the s8lv agent marker slots in here). This replaces "User-Agent string + IP" and is what rate limits, blocklists, and analytics key on. No consent ceremony needed per site — attribution is not authorization.
- Tier 2 — authorization: the existing full warrant presentation, for sites that want delegated authority (writes). Unchanged from mcp-auth semantics, just carried over plain HTTP.

**Wire efficiency:** chain travels once — first contact (or on a 401/403 challenge) carries the full chain in a header/body; after that the per-request cost is one Signature/Signature-Input pair, with the verifier caching the chain by keyid (DNS + cert TTLs bound the cache). Stateless-friendly: any node that hasn't seen the keyid challenges, agent re-sends the chain.

**Site policy surface:** a response challenge (WWW-Authenticate-style or Accept-Signature) invites attributed retry; a .well-known policy doc (robots.txt successor shape) declares crawl/action policy for attributed vs anonymous agents — e.g. "attributed agents get 10 rps, anonymous get 0.1".

**Verification cost:** one EdDSA verify per request + cacheable chain verify per keyid. Middleware drops into the existing sdk/express, sdk/hono, sdk/fastify packages; hosted /verify covers sites that won't run crypto.

**Replay/consequences:** created/expires + nonce with a short window; signature binds method+URI so replay ≈ idempotent re-fetch. Consequences attach to the stable agent name (block/limit the agent, not the human); Tier 2 revocation rides the existing warrant status refs.

**Adversarial framing (why sites bother):** they can't force honest agents into existence, but they can make honesty the cheap lane — attributed traffic gets real rate limits and capabilities, anonymous automation gets the existing bot-management wall. Same "honesty cheaper than masquerade" bet as principle 5.

**2026-08-27 (Dan):** parked — interesting but on par with the other explorations, not above them. Lowered from high to normal.
