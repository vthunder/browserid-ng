---
# browserid-ng-v8s0
title: '[Audit 2026-11] D1: auth certs mint exact identities only; subaddress rule becomes authorizes_grantor (config certs)'
status: completed
type: bug
priority: high
created_at: 2026-11-02T22:43:19Z
updated_at: 2026-11-03T08:21:23Z
parent: browserid-ng-ag1l
---

Findings: D1 (WS1/WS6/WS3/WS8; sdk/agent client mirror from WS4). Severity: Medium (downgraded from High 2026-11-02: holder-pinned warrants are unaffected; exposure is attribution, the per-agent revocation axis, and the blast radius of a browser-key compromise via *-holder warrants). Decision: Q1 settled (spec §4.6 stands, code moves; option (b) hold for the WS8 PoC, which is now done, so this is unblocked).

Where: browserid-core/src/device.rs:96-111 (identity_matches, subaddress branch, purpose-blind); used by DeviceCert::authorizes_identity at both mints: browserid-broker/src/routes/device.rs:455 (/access/mint) and routes/hosted_idp.rs:536 (/idp/access_cert); mirrored client-side in sdk/agent/src/device.mjs:447-455 (authorizesIdentity).

Change: split the predicate. authorizes_identity keeps the exact and glob branches only; the subaddress rule moves to a separate authorizes_grantor used only by the two config-cert checks (AccessPresentation::verify_at step 5 and RecordBundle::validate step 1b). Invert the auth-purpose expectations in the existing unit test device::tests::base_identity_authorizes_subaddresses. Mirror the split in sdk/agent authorizesIdentity. Re-run the WS8 PoC against /access/mint afterwards.

Acceptance (un-ignore / un-skip):
- browserid-core/tests/audit_2026_11_ws6.rs: d1_authentication_cert_for_base_identity_does_not_authorize_subaddress
- browserid-core/tests/audit_2026_11_ws3_proptest.rs: auth_cert_identity_is_exact
- browserid-core/tests/audit_2026_11_ws8_d1.rs (PoC; flips)
- sdk/agent/audit_2026_11_ws4.test.mjs: "D1 (client mirror): an auth cert for the base identity does not authorize a subaddress"

Reports: ws6 §1.1, ws3 §1.1, ws8 §1.1, ws4 §2 (client mirror note). Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.



## Summary of Changes

- browserid-core/src/device.rs: `identity_matches` is now exact + glob only (the mint-side rule); the §4.6 subaddress widening moved to a new private `identity_matches_as_grantor`.
- `DeviceCert::authorizes_identity` is purpose-aware: an authentication cert covers exactly its identities (no `+tag` widening); an authorization cert delegates to the new public `DeviceCert::authorizes_grantor(grantor)` (requires purpose == authorization; exact / glob / §4.6 subaddress). Purpose-aware rather than the literal 'drop the branch everywhere' split because the audit's own passing WS3 properties pin subaddress coverage through `authorizes_identity` on config certs; the mint gate (auth cert) is exact either way. No existing signature changed, so the broker's two mint call sites need no edit and now mint exact identities only.
- `AccessPresentation::verify_at` (§6.1 step 5) and `RecordBundle::validate` (§6.4 step 1b) call `authorizes_grantor`.
- Unit test `device::tests::base_identity_authorizes_subaddresses` replaced by `subaddressing_is_a_grantor_rule_only` (auth-purpose expectations inverted, purpose matrix on certs).
- Un-ignored: ws6 `d1_authentication_cert_for_base_identity_does_not_authorize_subaddress`, ws3 `auth_cert_identity_is_exact`; WS8 PoC flipped (asserts no widening; the legitimately-minted subaddress presentation still verifies).
- Not done here: sdk/agent `authorizesIdentity` mirror and its ws4 test (outside browserid-core); re-running the PoC against a live /access/mint.
