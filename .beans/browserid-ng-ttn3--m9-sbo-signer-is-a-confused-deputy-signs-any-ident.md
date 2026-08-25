---
# browserid-ng-ttn3
title: '[M9] SBO signer is a confused deputy (signs any identity/audience, unlimited)'
status: in-progress
type: bug
priority: normal
created_at: 2026-07-28T23:54:23Z
updated_at: 2026-08-25T10:36:14Z
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
- [ ] Phase 0 — spec amendment PR: binding set + kind×op table + requester kind + scope entries/mode + req_origin + invariants 9-14 in docs/specs/browserid-ng-protocol.md (this IS rjmm's pending binding-set amendment — note it there when landed). DRAFTED 2026-08-25, uncommitted, awaiting Dan's review before phases 1+
- [ ] Phase 1 — browserid-core: BindingSet (singular shorthand, unknown-kind reject, self-grant-only multi-entry), Requester kind, ScopeEntry, assertion req_origin, full-set op P/A evaluation; compile-fix registrar/broker match sites; tests + v2 test-vectors
- [ ] Phase 2 — SBO side (deploy FIRST): sbo-core browserid-core bump + sign:sbo:* in scopes_authorize; sbo-daemon status-ref checking fail-closed; mingo rev bump + daemon deploy
- [ ] Phase 3 — broker: shared warrant-mint module, sboSign object param, standard consent card minting+registering+storing the record, sbo-signer.js stored-record dispatch (delete fabrication, req_origin stamp, prompt mode, grant-info, error vocab), /account rows + revoke, wipe sbo_sign_granted booleans
- [ ] Phase 4 — mingo web: declare audiences/scopes at consent, handle not_granted/prompt_declined/scope_not_granted, grant-info rendering
- [ ] Phase 5 — Playwright e2e for the full consent→sign→revoke path (none exists today), smoke test, ordered deploys, M9 closure re-verification, flip use-cases doc to live
