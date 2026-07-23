---
# browserid-ng-o92d
title: Fallback-IdP abuse vectors — audit + guardrails
status: todo
type: task
priority: high
created_at: 2026-07-11T20:37:12Z
updated_at: 2026-07-23T11:02:41Z
---

The fallback IdP exposes public, unauthenticated endpoints (/auth/send emails a code to any address; /auth/verify; /cert_key). Audit the abuse surface and put guardrails in place. Registration/API keys are NOT the answer (the broker holds RP attribution from mediation; keys were an Auth0-shaped mistake) — the fix is rate limiting + template hygiene.

## What's already good
- **Fixed email template** (a verification code, no attacker-controllable content) → not useful as a spam/phishing CONTENT relay. This defuses the worst vector.
- Codes are short-lived (15 min), single-use, and deleted on verify.
- Certs are short (24h); the email cookie is signed by the broker key.

## The vector to guard (this bean implements)
- **Mailbombing / quota burn via `/auth/send`.** It's directly reachable (not only via the broker), so an attacker can flood a victim's inbox with benign-but-annoying code emails, or burn the Resend quota/sender reputation. The broker only sees *mediated* traffic, so this needs limits AT the fallback.
- Guardrail: per-recipient-email rate limit (cap sends per address per window) + a global cap. In-memory counters (single-instance fallback), pruned per call. [DONE below]

## Broader audit (this bean tracks)
- [x] Per-recipient (5/hr) + global (300/hr) rate limit on /auth/send (mailbomb/quota-burn). In-memory, pruned per call. Tested.
- [x] Code brute-force: /auth/verify burns the code after 5 wrong attempts (per email). Tested. (Could still lengthen codes later.)
- [ ] Cert issuance flooding: /cert_key is cookie-gated (needs a verified email cookie), so bounded by successful /auth. OK, but confirm one cookie can't mint unbounded certs for unrelated pubkeys (it's scoped to its email — fine; just document).
- [ ] Cookie forgery: signed by the broker Ed25519 key; confirm verify is constant-time-ish and the token can't be replayed cross-domain (it's origin-cookie-scoped). 
- [ ] Open-redirect / return_to on /auth: authentication_api.js takes return_to from URL — ensure it can't be pointed at an attacker origin to leak anything (the popup posts to opener; the assertion is audience-bound so low value, but audit).
- [ ] Email enumeration: /auth/send behavior shouldn't reveal whether an address exists anywhere (it doesn't — it verifies control, not existence). OK.
- [ ] Resend deliverability: new sender fallback@id.sandmill.org — SPF/DKIM/DMARC hygiene so codes don't land in spam or get the domain flagged.

## Related
Surfaced in the monetization/abuse discussion for apgv (browserid-ng-apgv). The broker-side attribution + agent-governance-is-the-revenue framing means the fallback stays free/open, so abuse control (not billing) is the real reason for these limits.
