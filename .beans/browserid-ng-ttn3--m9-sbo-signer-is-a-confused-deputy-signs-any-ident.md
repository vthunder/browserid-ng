---
# browserid-ng-ttn3
title: '[M9] SBO signer is a confused deputy (signs any identity/audience, unlimited)'
status: completed
type: bug
priority: normal
created_at: 2026-07-28T23:54:23Z
updated_at: 2026-08-25T19:16:55Z
parent: browserid-ng-wre6
---

docs/security-audit-2026-07-29.md (M9). sbo-signer.js:186 gates only on a per-origin boolean; d.email/d.audience opener-supplied + unchecked; popup holds device certs for ALL identities. Granted origin signs as any identity/audience, unlimited.
(Fix tracked via the phased checklist at the bottom of this bean.)

## Re-verification 2026-08-17 — STILL VALID, unchanged in substance

browserid-broker/static/common/js/sbo-signer.js:
- grantedFor(origin) (:47-52): still a bare per-origin boolean from localStorage.siteInfo[origin].sbo_sign_granted. No identity/audience/count in the grant.
- Gate at :186 is exactly `if (!grantedFor(rpOrigin))`. Only addition since audit is a PRESENCE check at :191 (`if (!d.audience)`) — validates non-emptiness, not authorization.
- :198-202 devicePairFor(d.email) → mintPresentation(d.email, d.audience, …): opener-supplied email+audience flow straight into minting a fresh access cert for ANY identity with device certs in that browser.
- :145-151 warrant built client-side with grantor/grantee/audience all from opener input.
- No per-request consent: header comment :14-15 "No user interaction: consent granted once at login"; :118 only logs a counter.
- Grant-writing side unchanged: dialog.js:1977 (read) / :1987 (set sbo_sign_granted=true), origin-keyed boolean only.
- Only pre-existing hardening: e.source !== opener check at :180 (predates audit). No consent-card/warrant work has landed in this file since.

Decision/coordination: scope grant to specific identity+audience + per-request consent. Coordinate with consent-card work in bean browserid-ng-rjmm before implementing.

## Design direction (2026-08-22, discussed with Dan)

Decided against the narrow fix (scoping the stored boolean) in favor of the
general primitive: **signing grants** — 'who may ask my keys to sign what'.
Design note: docs/plans/2026-08-22-signing-grants-design.md (first draft,
pre-review).

Shape: a v2 self-grant warrant (holder-bound, presentable) + a signed
`requester` claim naming the RP origin + a `sign:sbo-envelope` shape scope,
minted ONCE at consent via the standard card/registry/ledger machinery from
rjmm, stored at the custodian. The popup loses the authority to author
warrants entirely — it can only exercise stored records covering
(origin, email, audience, shape). Revocation = registry status bit,
network-wide via the existing sbo-core status-ref contract.

Key insight recorded in the note: the v2 binding slot pins *which instance of
the grantee acts*; this case surfaces the orthogonal axis *which channel may
initiate* — they coincide for OAuth connections, split when the actor is the
user's own custodian. Silent login and agent assertion pulls are future
instances of the same primitive.

- [x] Design note review (Dan) — signed off 2026-08-25 after 5 rounds
(Work items restructured into the phased implementation plan at the bottom of this bean, 2026-08-25.)

## Design update (2026-08-25) — supersedes the record-shape wording above

Review round 5 unified the channel concepts: there is no separate requester
claim. The v2 `binding` claim now holds a SET of channel entries (singular
object = shorthand for one entry, so deployed records are unchanged); the
signing grant's set is {holder, requester}. Entries are conjunctive; each
kind has a defined evaluation per operation (unsatisfiable cells fail that
op) — this table replaces the old 'connection not presentable' / 'requester
not admittable' special-case invariants. Multi-entry sets are
self-grant-only; delegated records keep exactly one holder entry (three
labeled doors in the note §3). Scope modes are inline scope-entry
parameters. The note (docs/plans/2026-08-22-signing-grants-design.md) is the
source of truth; earlier wording in this bean is historical.

## Handoff (2026-08-25): design COMPLETE, next step is an implementation plan

Do this in a fresh session. Read first:
1. docs/plans/2026-08-22-signing-grants-design.md — the design, source of truth (final at commit 95f4f45)
2. docs/warrant-use-cases.md — context: where signing grants sit among the five warrant use cases
3. This bean's unchecked work items (the component-impact table in the note §6 is the implementation surface)

Not part of this bean but adjacent: rjmm carries the 'binding set amendment' note that must fold into the v2 spec PR when it lands; beans eodu/0ijs are deferred language extensions, out of scope.

## Implementation plan (2026-08-25) — docs/plans/2026-08-25-signing-grants-implementation-plan.md

The plan doc is authoritative for details, file:line targets, and the per-phase
checklists; the phases here mirror it. Two survey findings baked into the
ordering: (1) NO SBO caller checks the warrant status refs today (sbo-daemon
drops them — revocation is currently a no-op network-wide), and (2) sbo-core's
scopes_authorize fails closed on unknown scope dimensions, so the daemon must
understand sign:sbo:* BEFORE the broker starts presenting the new records —
phase 2 deploys before phase 3.

- [x] Code survey: broker consent machinery, spec/Rust verification path, mingo/sbo caller side (2026-08-25)
- [x] Implementation plan written (docs/plans/2026-08-25-signing-grants-implementation-plan.md)
- [x] Phase 0 — spec amendment in docs/specs/browserid-ng-protocol.md (commit c8e8964; Dan skimmed, has verbosity/placement quibbles + a break-compat question to revisit — decided to keep singular shorthand for now, revisit after testing). This IS rjmm's binding-set amendment — note it there
- [x] Phase 1 — browserid-core BindingSet/Requester/ScopeEntry/req_origin + full-set evaluation, registrar/broker ripples, tests (commit 73d4625; all 59 workspace test targets green, golden v1 vectors byte-stable). Deferred: cross-language warrant-v2 golden-vector file (wire pinned by unit tests only)
- [x] Phase 2 — SBO side deployed FIRST: sbo cf6df3f (sign:sbo:* scopes, submit-gate revocation checks in new sbo-daemon/src/status.rs — TLS-rooted list verification via the origin's support doc; deliberately submission-time-only so replay stays deterministic); mingo pin + SBO_REV bumped, daemon deployed + verified on da.sandmill.org 2026-08-25
- [x] Phase 3 — broker consent + wallet flip. NOTE deviation from plan: no shared warrant-mint module — dialog.js already carries its own mint/register machinery (buildPresentation), so grantSigningRecords() reuses signJws/apiCall there; consent.html/authorize.html dedup left as optional cleanup. sboSign is {audiences, scopes} (dev lane: ?sbo_request=b64url); card lists per-scope verbs; approve = allocate idx → sign v2 {holder, requester} record → register → store in siteInfo[origin].signing_grants; sbo-signer.js rewritten (stored-record dispatch, fabrication deleted, req_origin stamp, prompt UI in sign.html, sbo:grant-info, typed errors, absent action classifies as post per SBO default); /account rows via registrar requester_origin; legacy booleans wiped at dialog init; CSP hash updated
- [x] Phase 4 — mingo web (mingo b3f0ece): SBO_SIGN_REQUEST declared at consent (post auto, delete prompt); typed-error handling incl. not_granted clearing the ready flag; 120s sign timeout for prompted deletions. grant-info rendering left as a nice-to-have (not wired into UI)
- [x] Phase 5 — e2e-tests/tests/sbo-signing-grants.spec.ts (consent card → stored+registered record → silent post w/ req_origin stamp + stored-warrant-in-presentation assertion → not_granted/scope_not_granted → delete prompt decline+approve → grant-info → revoke bit); full suite green on warm broker (105 pass; connection-sharing flake passes in isolation). Deploys in order: daemon (da.sandmill.org, verified) → broker 73831d8 (browserid.me serves new dialog/signer, verified) → mingo web. Use-cases doc flipped to live. sbo-smoke-test.html updated to the new contract (manual pass pending)
- [x] Dan: interactive testing COMPLETE (2026-08-25) — silent post, prompted delete, and the full revoke→instant-refusal→re-consent→resume loop all verified on prod (wallet now checks revocation per sign, authoritatively)
- [x] Spec editing pass → moved to browserid-ng-lf78 (2026-08-25, Dan's call): a whole-spec editorial pass makes more sense than a ttn3-scoped one; the verbosity/placement quibbles and the break-format decision are carried there

## Summary of Changes (2026-08-25, phases 0-5 shipped)

M9 is closed structurally: the popup can no longer author warrants — the fabrication block is gone and every request must match a stored, consent-minted signing-grant record on (origin, email, audience, action, device holder), with req_origin stamped into each assertion and re-verified in browserid-core. Revocation is now real end to end: /account Revoke flips the registrar bit AND the sbo-daemon checks all three status refs fail-closed at its submit gate (new status.rs; deliberately submission-time-only so replay stays deterministic — previously NO SBO caller checked them at all). Commits: browserid-ng c8e8964 (spec) + 73d4625 (core) + 73831d8 (broker/e2e); sbo cf6df3f; mingo 3d0561a-ish pin bump + b3f0ece (web). Known deferrals recorded in the phase checklist (cross-language v2 vectors, consent.html mint-module dedup, grant-info UI).

## M9 interactive testing fallout (2026-08-25, Dan) — all fixed same-day

Testing surfaced four real issues, none in the signing-grant mechanism itself: (1) hosted-IdP mint CORS regression from the L9 rescope (fixed, cors_surface_test pins it — in v1ia); (2) daemon status gate keyed on support-doc keys → reworked to DNSSEC (sbo 594c2ac), which then led to the full keyless-support-doc sweep across 5 origins; (3) on-chain DNSSEC evidence for browserid.me had lapsed → daemon now live-captures a proof when the chain copy is stale (sbo 4a2b056); (4) Dan's delete routed via the mingo POSTER whose stored bundle carried a long-revoked config cert — the new revocation gate caught genuinely revoked paper in active use; poster now self-disables on revocation + client falls back to the signing grant + the off-switch is honored per-browser (mingo b3f0ece..latest). End state verified by Dan: silent post works, prompted delete works. Remaining: revoke-path test + spec editing pass.

## Closed (2026-08-25)

M9 fully resolved: the signing-grants primitive is designed, specced, built, deployed, and interactively verified end to end (silent post, prompted delete, instant wallet-side revocation, re-consent, resume). The audit finding closed with parent wre6; the remaining editorial work moved to lf78; deferred technical follow-ups (v2 golden vectors, mint-module dedup, grant-info UI, hosted-tenant e2e) are recorded in this bean's phase notes and v1ia.
