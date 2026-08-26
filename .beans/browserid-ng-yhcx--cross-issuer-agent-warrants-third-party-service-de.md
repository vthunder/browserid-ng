---
# browserid-ng-yhcx
title: Cross-issuer agent warrants (third-party service delegation)
status: scrapped
type: feature
priority: normal
created_at: 2026-07-14T18:41:57Z
updated_at: 2026-08-26T23:09:36Z
blocking:
    - browserid-ng-gnu2
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

## Work log (2026-07-14)

Registrar-side implementation underway (items 3–4 of the plan; see mingo-3f3i 'Registrar consent — implementation plan'):
- [x] browserid-core: delegator claim + warrant_external() + ExternalWarrantRequest (agent_cert~R) verify + tests (incl. parent==delegator binding, so a mismatched request can't yield a dead warrant)
- [x] registrar /warrant/request external branch (2-part vs 3-part bundle dispatch) + IssuerKeyResolver discovery hook + per-delegator pending cap (5) + redirect-tied listing (?code= deep link only) + broker sqlite migration v11 (external flag) + integration tests
- [x] account.html 'external services' UI (granted warrants, revocable) + consent.html external wording/deep-link fetch
- [ ] mingo backend signer + mingo-web redirect (tracked in mingo-3f3i)


## Review pass (2026-07-14): 6-finder code review + fixes

Ran a high-effort multi-agent review of the whole external-warrant diff. Strong cross-finder consensus on three real issues, all fixed + tested:

- **[FIXED] Consent-page spoofing**: `ExternalWarrantRequest::verify` didn't bind the agent cert's email-domain to its issuer (unlike assertion.rs:336). A foreign IdP could certify `mingo-poster@mingo.place` under its own key and the consent page would attribute the ask to a service it doesn't control. Now enforces `agent-email-domain == iss`; test `external_request_spoofed_agent_domain_rejected`.
- **[FIXED] Own-agent deep-link regression**: the new `?code=` filter on list_requests returned only the one matching row for ANY shape, so a user with multiple pending OWN-agent requests (all reached via /consent/<code>) would see just one and the siblings silently expired. Filter now hides only externals unless code-matched; own-agent queue always fully listed.
- **[FIXED] Unauthenticated discovery/allocation before gating**: request_external did outbound DNSSEC discovery + status-index allocation before checking the delegator is local or the per-delegator cap. Reordered: refuse non-local-delegator / over-cap requests with zero outbound calls, then discover+verify, then re-confirm the signed claims match what was gated. Residual (monotonic index growth per victim per window; TOCTOU on the count) tracked in browserid-ng-gnu2.

Cleared by finders (not bugs): XSS (all attacker strings escaped), cross-user ?code= leak (store query is user-scoped), issuer-confusion cross-user impersonation (broker-minted certs parent to the requester only), fresh-DB migration path.

Deferred (browserid-ng-gnu2): account.html client-side external heuristic → server flag; discovery rate-limit / deferred allocation.

## Reasons for Scrapping

Superseded, not abandoned. The mechanism this bean specified (warrant_external / ExternalWarrantRequest, agent_cert~R cross-issuer delegation) was built and reviewed (e572cda), then deliberately retired three days later in the device-cert cutover (c136158) along with the legacy delegation chain. The motivating use case — a user authorizing a third-party service like mingo posting — shipped via a different mechanism: as-you holder services (ykjk/3b8m, live e2e confirmed) and warrant-v2 foreign grantees (7a9960f delegated foreign-grantee approval card, ba68022 external grantee recorded as a service). What survives in device-model form is the registrar's external-request plumbing (consent.rs external flag, deep-link-only listing, delegator routing); literal cross-issuer agent identities (bare agent names on a primary domain needing reverse name-registry lookup) remain unsupported today by design choice — if that becomes needed, open a fresh bean against the device model. (Audit 2026-08-27.)
