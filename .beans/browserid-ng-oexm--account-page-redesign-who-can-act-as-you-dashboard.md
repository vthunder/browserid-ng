---
# browserid-ng-oexm
title: 'Account page redesign: ''Who can act as you'' dashboard + standalone /authorize'
status: completed
type: feature
priority: normal
created_at: 2026-07-29T23:03:49Z
updated_at: 2026-07-29T23:54:40Z
---

Implement the high-fidelity redesign from the design handoff (~/Account page redesign.zip, extracted README in scratchpad). One mental model: "Who can act as you" — a roster of actors (browsers / agents / outside services) with permissions nested inside, plus a per-site view, an inactive drawer, and the authorization (pv*) flows moved OFF the dashboard to a standalone /authorize route.

Binding vocabulary: UI never shows protocol nouns (warrant→permission; holder/namespace/cert hidden; forget_holder→sign out; etc.) — see the handoff README table.

## Todo

- [x] authorize.html: standalone page hosting the full pv* flow (I0 sign-in gate, I1 check, I2 name, I4 as-you, P permission, foreign, pinmismatch, invalid, denied), 400px centered card on #f5f5f4; approval → redirect to /account with sessionStorage handoff (banner + roster highlight)
- [x] account.html: full rewrite — dashboard (3 actor sections, expandable rows, full-control blanket, shared-permissions disclosure, inactive drawer), rail (addresses + add flow, connected sites, goes well with, account settings incl. change password / sign out everywhere / advanced signer / delete account), sites view, actor detail view (rename, public name edit, per-address trust, grouped grants, danger zone, technical details)
- [x] account.html: ?provision=<code> → client redirect to /authorize?code=<code> (back-compat with printed agent URLs)
- [x] routes/mod.rs: /authorize route_service; guard-test file list + INLINE_SCRIPT_HASHES updated (account.html new hash, authorize.html added); csp_tier test row
- [x] registrar agent_provision.rs: verification_uri(_complete) → {origin}/authorize?code=…
- [x] cargo test (broker + registrar + agent) green (37 binaries, 0 failures; CSP guard re-run against final files)

## Known degradations (deliberate)

- No last-used/recency server support yet (API only has issued_at) — the recency column shows the added-on date, sorting uses issued_at, and the >90-days-unused auto-demotion rule can't run (inactive = revoked-only). Follow-up bean tracks the server work.

## Verification

Screenshot-verified with Playwright + canned wsapi data (scratchpad/shots.cjs): dashboard, expanded browser row (blanket rule), expanded agent row, shared disclosure + inactive drawer, sites view, agent detail, browser detail, post-approval landing (banner + highlighted row), authorize I1/I2, authorize signed-out gate (I0), account signed-out. All match the design handoff.

## Summary of Changes

- **static/authorize.html** (new): standalone authorization page per the design handoff — quiet #f5f5f4 page, one centered 400px card, tiny footer. Hosts the full pv* flow ported from account.html (I0 inline sign-in gate with the waiting-for-approval panel, I1 fingerprint check, I2 name+address, I4 as-you danger card, P permission, foreign-service, pinmismatch, invalid, denied). Approvals stash a handoff in sessionStorage (browserid:authorized) and redirect to /account; deny/cancel ends on the terminal card. Accepts ?code= (canonical) and ?provision= (legacy).
- **static/account.html** (rewritten): "Who can act as you" dashboard — three actor sections (browsers / agents / outside services) derived from holders + device_certs + warrants; expandable rows; full-control blanket rule (trusted addresses collapse redundant grants); shared-permissions disclosure (browsers.* and * matchers); inactive drawer (revoked holders) with Remove-for-good (forget_holder); rail with addresses (+ stage_email/complete_email_addition add flow), connected sites, goes-well-with, account settings (change password, sign out everywhere = revoke all browser certs, advanced manual-warrant signer, delete account). Sites view and actor detail view (inline rename, agent public-name edit, per-address trust table, grouped grants, danger zone = revoke certs + own warrants → Inactive, technical-details disclosure). Post-authorize landing: confirmation banner + highlighted "new" roster row. ?provision= redirects to /authorize.
- **broker routes/mod.rs**: /authorize route; INLINE_SCRIPT_HASHES updated (account) + added (authorize); guard-test file list + csp_tier test row.
- **registrar agent_provision.rs**: verification_uri(_complete) → {origin}/authorize(?code=…).
- **e2e paired-provisioning.spec.ts**: URL assertion → /authorize?code=, bundled-grants test now expects the /account landing + banner.
- Verified by 12 Playwright screenshots against mocked wsapi data (all views match the design) and full cargo test (37 binaries green).

Known deliberate gaps: recency column shows added-on date (last-used tracking = bean browserid-ng-lfpu); inactive notes have no dates; guestbook.spec.ts e2e was already stale before this change (references #pv-handles and pre-subaddressing agent naming) and still needs a rewrite.
