---
# browserid-ng-pz0f
title: JIT consent flow — warrants requested via RP challenge, approved at the registrar
status: in-progress
type: feature
priority: high
created_at: 2026-07-10T15:24:22Z
updated_at: 2026-07-10T17:23:54Z
parent: browserid-ng-gsnm
blocked_by:
    - browserid-ng-5zdh
---

Nobody should ever type an audience string. The RP names its own audience authoritatively in the §5.2 `WWW-Authenticate` challenge; warrants get **requested, not configured**. Canonical design: `docs/plans/2026-07-10-agent-identity-v3-and-gtm-plan.md` (§4).

## Flow

1. Agent contacts RP → challenge with `audience=` + (spec addition) requested scopes.
2. Agent can't sign a warrant — it raises a **consent request** at the user's registrar (device-authorization-grant shape, RFC 8628): link/notification to the user.
3. Consent page (served by the registrar, where the identity key lives per §4.6 typed-signing) shows "**researcher** wants to act for you at **mingo.place** with **post, read**" — audience/scopes prefilled from the challenge. Approve → key signs warrant → agent picks it up (poll/callback).

## Properties

- Solves the id.mingo.place-vs-mingo.place problem: the party that defines the audience supplies it (same move OAuth made with prefilled consent).
- Warrants become **just-in-time**: no upfront audience enumeration, no speculative over-granting. Still user-signed at authorization time; agent can request, never self-issue or widen (delegation-time-only scoping stands).
- Policy knobs: deny, "always ask", per-agent standing preferences.
- Imported risk = consent fatigue / look-alike prompts: consent surface must show verified origin prominently, deliberate approve action.
- RPs publishing §5.4 metadata get richer consent screens (display name) as polish.
- MVP fallback: manual audience entry in registrar UI. aud is exact-origin only in v3 (no wildcards).

### Todo
- [x] Spec v0.4: scope param on WWW-Authenticate challenge; consent-request + pickup endpoints (RFC 8628 shape) — agent spec §6, §7.2
- [x] Registrar: consent request storage (store v6 migration, delete-on-delivery), /warrant/request + /warrant/poll, consent page at /consent[/code] with client-side warrant signing + stale-cert refresh. (Notification = verification_uri surfaced by the agent; broker-push notification not implemented.)
- [x] browserid-agent: request_warrant / poll_warrant / obtain_warrant (RFC 8628 loop), auto add_warrant on approval; agent_cli example for prod smoke tests
- [ ] Anti-phishing review of consent surface

## Implementation notes (2026-07-10)

Full flow shipped and covered by consent_flow_test.rs (approval roundtrip incl. single-delivery semantics, denial, registry gate). Poll rate limiting (5s/429), 900s request expiry, ≥128-bit codes, audience/scope data deleted on delivery per §6.4. Remaining: anti-phishing review of the consent surface.

**Prod-validated 2026-07-10**: full flow exercised against live browserid.me — provision (typed cert, parent=vthunder@gmail.com) → /warrant/request → consent approval at /consent → poll pickup → warrant-backed assertion verified at /verify with agent{parent} attribution. Negative checks passed live: warrant-less presentation rejected, wrong-audience replay rejected, request row (audience data) deleted on delivery.
