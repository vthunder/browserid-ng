---
# browserid-ng-pz0f
title: JIT consent flow — warrants requested via RP challenge, approved at the registrar
status: todo
type: feature
priority: high
created_at: 2026-07-10T15:24:22Z
updated_at: 2026-07-10T15:24:22Z
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
- [ ] Spec v0.4: scope param on WWW-Authenticate challenge; consent-request + pickup endpoints (RFC 8628 shape)
- [ ] Registrar: consent request storage, notification/link, consent page + typed-signing warrant issuance
- [ ] browserid-agent: challenge parse → consent request → poll → warrant store
- [ ] Anti-phishing review of consent surface
