---
# browserid-ng-xvfp
title: Integration tests for cryptographic assertion validation (dialog → auth_with_assertion)
status: todo
type: task
priority: high
created_at: 2026-07-08T00:11:27Z
updated_at: 2026-07-08T00:11:27Z
---

Close the dialog→endpoint integration gap identified in `docs/test-coverage-audit.md`.
Unit coverage is strong (`browserid-core/tests/verifier_test.rs`,
`browserid-broker/tests/verifier_test.rs`, `conformance_test.rs`), but the specific
integration between assertion *creation* (dialog.js) and assertion *verification*
(`auth_with_assertion` endpoint) is untested — which is exactly why the
audience-mismatch bug (fixed in commit 0974443) slipped through.

## Still-open gaps (verified 2026-07-08)

- `browserid-broker/tests/auth_with_assertion_test.rs` tests only error paths (400/
  422/500); valid-assertion tests are explicitly "deferred to Task 8." None creates a
  real assertion, exercises the audience-mismatch case, or asserts a session is
  created.
- E2E mock IdP uses a fake signature: `e2e-tests/tests/primary-idp.spec.ts` (~L421,
  `const signature = 'mock-signature-for-testing'`) — no crypto validation.
- `silent-assertion.spec.ts` checks callbacks fire + assertion non-empty, but never
  POSTs it to `auth_with_assertion` or verifies the signature end-to-end.

## TODO

- [ ] `auth_with_assertion` happy-path test: create a real (cryptographically valid) assertion, POST it, assert a session is created
- [ ] Regression test for the audience-mismatch bug (commit 0974443)
- [ ] Replace the e2e mock-signature path with a real signed assertion (or add a Rust integration test that covers the crypto path e2e)

(Migrated from beads BID-3; sibling client-flow beads BID-1/BID-2 were verified DONE
and the beads DB was removed.)
