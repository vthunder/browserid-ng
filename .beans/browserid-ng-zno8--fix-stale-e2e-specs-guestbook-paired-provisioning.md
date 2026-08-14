---
# browserid-ng-zno8
title: 'Fix stale e2e specs: guestbook + paired-provisioning drive an outdated /authorize flow'
status: todo
type: bug
priority: normal
created_at: 2026-08-14T17:37:40Z
updated_at: 2026-08-14T19:16:02Z
---

Both specs fail identically on main (verified at commit 5d022b5, pre-warrant-v2-broker changes): guestbook.spec.ts drives the OLD single-stage authorize page (#pv-identity select before any #pv-match step) and paired-provisioning.spec.ts 'no downloaded credential' fails after reaching the Meet screen (agent pickup leg). Reproduced twice on the dirty tree and once on clean HEAD (2 failed / 3 passed each time). Not caused by the warrant-v2 work — the same failures exist without it. Diagnose whether the page flow drifted from the specs (eywc Flow-I refactor?) or the agent pickup broke, and fix spec or page.

Update 2026-08-14: the full-suite run surfaced two MORE pre-existing failures on main, verified identically at the same base commit with a clean tree: marketing-split.spec.ts:147 (v3 nav: Demos page) and transition-no-password-reset.spec.ts:110 (signed-in set-password screen). 4 pre-existing e2e failures total; 101 pass.

## Root causes (2026-08-14, all four verified on clean main)

1. guestbook.spec.ts:42 — STALE SPEC. It drives the pre-Flow-I authorize page (page.selectOption('#pv-identity') immediately). Since the eywc agent-flows-v2 redesign, a paired request renders the fingerprint step (#pv-match) first, so #pv-identity is not interactable and selectOption times out. paired-provisioning.spec was updated for Flow I; guestbook.spec was not. Fix: rewrite its provisioning steps to the Flow-I sequence.

2. paired-provisioning.spec.ts:40 — REAL SDK BUG. Agent.bootstrap's pickup (sdk/agent/src/agent.mjs ~:122) constructs the LEGACY Credential ({secret_key, delegation, broker, idp}) from /agent-provision/poll's completed payload; the broker now delivers the device-cert-model shape, so Credential's constructor throws InvalidCredentialError('credential needs secret_key, delegation, broker, idp'). The sibling test passes because requestProvision (device.mjs) is the device-model path. This is the wallet-less bootstrap product path, broken since delivery moved to the device model. Fix: bootstrap should build the device-model agent from the delivered credential.

3. marketing-split.spec.ts:166 — TRIVIAL STALE EXPECTATION. expect .demorow toHaveCount(6) but the demos page now has 7 rows (a demo was added without updating the spec). One-line fix.

4. transition-no-password-reset.spec.ts:110 — LIKELY REGRESSION of gg5s. The spec pins: a SIGNED-IN user in transition_no_password keeps the direct set-password screen (session = proof of control, no mailed code). dialog.js handleNoPasswordTransition (static/dialog.js:571) now unconditionally calls stage_reset and shows the reset screen — there is no signed-in branch at all, so the gg5s discrimination is gone from the dialog. Signed-out sibling passes. Fix: restore the authenticated branch in handleNoPasswordTransition (or, if the simplification was deliberate, update the spec and retire gg5s's contract explicitly).

(2) and (4) are product bugs, not just stale specs.
