---
# browserid-ng-yhcx
title: Cross-issuer agent warrants (third-party service delegation)
status: todo
type: feature
priority: normal
created_at: 2026-07-14T18:41:57Z
updated_at: 2026-07-14T18:56:34Z
---

Foundational protocol change enabling a user (ANY email) to warrant a
third-party service agent they don't own — e.g. mingo-poster@mingo.place.
Blocks mingo-3f3i (delegated mobile posting).

## Why (design settled with Dan)
Today warrants require the delegator and agent to share ONE IdP issuer
(browserid-core warrant.rs:189 + sbo-core attribution.rs ForeignParentIssuer;
single DNSSEC proof reused for both certs). This was an optimization for
"your own derived agent", not a security requirement. Relaxing it lets a
user's own-IdP-signed key authorize any agent identity.

## Changes
1. sbo-core (on-chain verify) — THE FOUNDATION:
   - [x] Drop ForeignParentIssuer; delegator parent-cert now fully attributed
         under the delegator's own issuer key (window + cert-window + signature
         + authority). (sbo feat/cross-issuer-warrants)
   - [x] verify_attribution_with_warrant sources the delegator key: same-issuer
         reuses the agent proof; cross-issuer needs a second proof (inline OR
         daemon-resolved on-chain /sys/dnssec/<delegator-issuer>).
   - [x] Tests: cross-issuer happy path + delegator-authority (rogue-IdP)
         rejection + wrong-key rejection; all same-issuer tests still pass;
         89 daemon tests pass.
   - [x] Specs (Authorization + Attribution) document cross-issuer + dual proof
         sourcing.
2. Daemon (sbo-daemon validate.rs):
   - [x] Daemon resolves the delegator issuer's on-chain /sys/dnssec proof and
         passes it (warrant_delegator_issuer helper).
3. Registrar consent (browserid-registrar): third-party warrant-request entry
   point — see mingo-3f3i (skip provisioning-cert gate, arbitrary agent
   identity, route to delegator's registrar, carry a delegator hint). May also
   need to relax warrant validation in respond() to STORE a cross-issuer
   warrant.
4. (Optional/among assertions) browserid-core warrant.rs::verify_for is the
   ASSERTION path (RP login), independent of on-chain; relax only if needed.

## Note: single-parent binding is NOT changed
mingo mints a per-user mingo-poster cert (agent.parent=<user>) in-process with
its own IdP key. The parent claim is inert without the user's warrant, so no
user authorization is needed to mint it. Certs cheap; refresh before 24h exp.
