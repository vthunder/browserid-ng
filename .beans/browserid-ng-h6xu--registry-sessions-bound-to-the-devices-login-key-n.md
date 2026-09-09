---
# browserid-ng-h6xu
title: Registry sessions bound to the device's login key (no member set, no per-call cert proofs)
status: completed
type: task
priority: high
created_at: 2026-09-09T17:58:59Z
updated_at: 2026-09-09T19:24:58Z
blocking:
    - browserid-ng-zpbh
---

Spec revision agreed with Dan 2026-09-09: every session is opened with and bound to the device's login key; Proof header always by that key; identity certs are account data only (attach records them; no session refresh); login keys enrolled at accounts/login_page (POST login-keys removed), carry a holder link, lose the status ref; stored_key failures answer login_required {url}; 'member' means identity again. Review draft: docs/plans/2026-09-09-session-key-draft.md. Supersedes the self-proven login-keys change in a069f73.

- [x] Dan reviews the draft (2026-09-09: lookup by cert; two levers, no flag; attach → {recorded}; creation keeps the cert)
- [x] Spec text (§4.2, §4.4, §4.5, §5.2, §7.1)
- [x] Registrar: extractor by login key; enrolment at accounts/login; holder link; login_required on stored_key failure; remove POST login-keys, member re-check, end_sessions_solely_on_cert
- [x] Clients: registry-session.js (dialog + page share the browser's key), wallet/src/registry.js
- [x] Tests: registry_api_test helpers; wallet e2e; account-registry-session spec
- [x] Migration: honour existing login certs' keys; end existing sessions (sqlite v40: holder column; sessions without a key deleted)

## Summary of Changes

A session is bound to the device's login key from the call that opens it (`accounts` or `login`, both carrying `login_key {pubkey, label?, proof}`); the Proof header is always by that key; attach records certs and returns `{recorded}`; POST login-keys is gone; stored_key failures answer `login_required {url}`; login keys carry a holder (set by attach, revoked by holders/forget) and no status ref or cert; `member` means an identity again. Spec §1, §2, §4.2, §4.4, §4.5, §5.2, §5.5, §5.6, §7. Registrar: session.rs (verify_session_call, open), api.rs (ApiUser = session + key), account.rs (brought_key/enroll), holders.rs, store trait; broker store v40 + memory/sqlite/glue. Clients: registry-session.js (dialog and account page share the per-account key), wallet registry.js, keystore healthLocal skips login keys. Verified: cargo test --workspace, 122 Playwright, wallet e2e.
