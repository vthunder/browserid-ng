---
# browserid-ng-8t8h
title: Replaceable fallback IdP — RP declares its accepted fallback IdPs
status: completed
type: feature
priority: high
created_at: 2026-07-11T13:00:32Z
updated_at: 2026-07-11T13:38:47Z
---

The higher-leverage half of login-path decentralization (from vthunder discussion, 2026-07-11). Lets an RP adopt browserid **without being forced to trust browserid.me as an identity authority** — the objection that keeps RPs out. Pure protocol/implementation; no browser-platform bet, no dependency on key custody or storage behavior. Do this before the broker-choice work.

## Model

Separate the two roles browserid.me fuses today: **mediator** (runs the dialog) vs **fallback IdP** (vouches for emails whose domain has no primary). Make the fallback IdP an RP-chosen trust decision:

- The RP declares the set of **fallback IdPs it accepts**.
- For an email with no primary, the broker routes verification to an accepted fallback; the issued cert carries that fallback's issuer.
- The **RP's verifier enforces**: reject any assertion whose fallback issuer isn't in the accepted set. (This is the real security boundary — see below.)
- Cross-RP cert reuse is gated: reuse a cached fallback cert only at RPs that accept its issuer, else re-verify via one they do accept (cached per (email, issuer) pair).
- Primaries are unaffected: a domain's primary is DNSSEC-authoritative and always accepted; the accepted-fallbacks set governs only the no-primary path.

## Where the RP declares it — DECIDED: argument, not well-known

The accepted-fallbacks list is passed as an **argument** to the polyfill at invocation (FedCM-shaped: FedCM's `navigator.credentials.get({identity:{providers:[...]}})` is the same shape), NOT discovered at `RP/.well-known/browserid`.

Rationale:
- **FedCM-congruent** — the browser will eventually consume exactly this argument, so the polyfill → native path is a swap, not a rewrite.
- **No RP-hosted well-known** → lower adoption friction (the whole point is RP adoption).
- It's **request-time policy** (can vary per page/context), naturally a parameter like OAuth scope.
- It's only a **hint to the broker** anyway — the RP's server-side verifier is the enforcement point — so it needs no tamper-resistance/authority a well-known might imply.

A `.well-known` could be added later as an *optional* discovery channel (for a browser or a non-JS consumer that wants the policy without RP-provided JS), but not in v1.

## Enforcement is server-side (load-bearing)

The argument is advisory for the broker (so it doesn't verify via a fallback the RP will reject). The authoritative check is the RP backend at `/verify`: the assertion's fallback issuer MUST be in the RP's accepted set. `browserid-rp`'s `Verifier` already has `trust_issuer(domain, key)` — the enforcement primitive exists. The RP derives both the client argument and the server accepted-set from one config so they can't drift.

## Default / migration

No argument → default to `{browserid.me}` (today's behavior, backward compatible). An RP that wants to exclude browserid.me passes an explicit list without it. Explicit argument → use it verbatim.

## v1 scope honesty

Only one fallback IdP (browserid.me) is deployed today, so v1's concrete effect is "an RP can *decline* browserid.me's fallback (and then only primary logins work there)" plus the plumbing — accepted-set argument, verifier enforcement, cert-issuer carriage (certs already carry the issuer), reuse gating — that lets *anyone* stand up a second fallback later without further protocol change. The full multi-fallback value needs a second fallback service to exist.

## Related

Sibling of the broker-choice bean [[polyfill-selectable-broker-endpoint-user-chosen-broker-for-the-login-path]] (0efn), which is the platform-gated half. Both descend from the s75b role-decomposition discussion (browserid-ng-s75b). North star for both: FedCM.
