---
# browserid-ng-ttn3
title: '[M9] SBO signer is a confused deputy (signs any identity/audience, unlimited)'
status: in-progress
type: bug
priority: normal
created_at: 2026-07-28T23:54:23Z
updated_at: 2026-08-25T10:11:25Z
parent: browserid-ng-wre6
---

docs/security-audit-2026-07-29.md (M9). sbo-signer.js:186 gates only on a per-origin boolean; d.email/d.audience opener-supplied + unchecked; popup holds device certs for ALL identities. Granted origin signs as any identity/audience, unlimited.
- [ ] Scope grant to a specific identity + audience
- [ ] Require per-request/per-identity consent

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
- [ ] Spec text: requester claim + sign: scopes with inline parameters (mode) + assertion req_origin + wallet invariants 9-14 (incl. unknown-claims-fail-closed)
- [ ] Dialog: standard-card consent variant, sign+register+store record, RP declares audience
- [ ] Popup: stored-record lookup, delete warrant fabrication (sbo-signer.js:147-151)
- [ ] /account rendering + revocation; make the consent copy true
- [ ] mingo: pass audience with sboSign, handle not-covered error
- [ ] Audit SBO callers actually check the warrant status ref

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
