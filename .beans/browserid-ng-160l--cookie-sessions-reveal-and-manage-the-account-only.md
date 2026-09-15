---
# browserid-ng-160l
title: Cookie sessions reveal and manage the account only once bound to an enrolled login key (session_admit)
status: completed
type: feature
priority: high
created_at: 2026-09-15T16:12:37Z
updated_at: 2026-09-15T16:41:25Z
parent: browserid-ng-0vdu
---

Handoff: docs/plans/2026-09-15-cookie-session-admission-handoff.md. Server-side rule: an issuer cookie session is an identity session (issuer-role work for the identity it proved) until bound to a registry login key enrolled on the account; account-wide cookie endpoints (list_emails, browser_holder, parent_of, set_parent, set_public_name, remove_email, account_cancel, update_password, issuer_revoke_url, session_context.account, address_info owner disclosure, stage_email for new addresses) require admission. New: sessions.login_key_id + proved_emails (schema v47), POST /wsapi/session_admit (Bearer + Proof by the login key), unbind on logout/revoke, 403 not_admitted; dialog binds after Registry.ensure() and reorders the primary flow (registry step before reconcileBrowserHolder); replaces the 2026-09-15 client-side hasLoginKey gate. ~12 test files read the roster under a bare cookie: migrate.

- [x] Schema + models + stores (SqliteStore test)
- [x] session_admit + unbind + not_admitted
- [x] Gate the account-wide endpoints; scope identity-role ones to proved_emails
- [x] Dialog + account page order of operations; remove the client gate
- [x] Spec sentences (fallback-idp §3.2, registry-api §4.3 note)
- [x] Tests: Rust (unadmitted vs admitted), Playwright, migrate roster readers

## Summary of Changes

Server: sessions carry proved_emails + login_key_id (schema v47, old sessions ended); POST /wsapi/session_admit binds a cookie session to the registry login key of the Bearer+Proof call (same account, live key); revoking a key unbinds (registrar glue); 403 not_admitted gates list_emails, parent_of, set_parent, set_public_name, remove_email, account_cancel, update_password, issuer_revoke_url, stage_email for new addresses; device/issue (cookie), stage_email re-verify, address_info state and FedCM are scoped to proved identities when unadmitted; session_context gains admitted + proved_emails. Departures from the handoff (recorded there): browser_holder stays open, session_context.account stays visible, address_info discloses state to the proving session.

Client: Registry.admitSession() (+storedOnly); dialog runs it in the registry step (ensureRegistryAdmission, from buildPresentation), records the parent hint after it, keys the chooser off session_context.admitted (client hasLoginKey gate removed; silent stored-key admission at init); account page admits after keyless/password login and signs out on not_admitted.

Tests: session_admission_test.rs (4), SqliteStore round-trip, create_user now admits (create_user_unadmitted + registry::admit_session helpers); broker suite 367 passed; Playwright 131 passed / 15 skipped. Specs: fallback-idp §3.2, registry-api §4.3.
