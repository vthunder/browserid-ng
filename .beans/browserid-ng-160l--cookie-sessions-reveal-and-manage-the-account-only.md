---
# browserid-ng-160l
title: Cookie sessions reveal and manage the account only once bound to an enrolled login key (session_admit)
status: todo
type: feature
priority: high
created_at: 2026-09-15T16:12:37Z
updated_at: 2026-09-15T16:12:37Z
parent: browserid-ng-0vdu
---

Handoff: docs/plans/2026-09-15-cookie-session-admission-handoff.md. Server-side rule: an issuer cookie session is an identity session (issuer-role work for the identity it proved) until bound to a registry login key enrolled on the account; account-wide cookie endpoints (list_emails, browser_holder, parent_of, set_parent, set_public_name, remove_email, account_cancel, update_password, issuer_revoke_url, session_context.account, address_info owner disclosure, stage_email for new addresses) require admission. New: sessions.login_key_id + proved_emails (schema v47), POST /wsapi/session_admit (Bearer + Proof by the login key), unbind on logout/revoke, 403 not_admitted; dialog binds after Registry.ensure() and reorders the primary flow (registry step before reconcileBrowserHolder); replaces the 2026-09-15 client-side hasLoginKey gate. ~12 test files read the roster under a bare cookie: migrate.

- [ ] Schema + models + stores (SqliteStore test)
- [ ] session_admit + unbind + not_admitted
- [ ] Gate the account-wide endpoints; scope identity-role ones to proved_emails
- [ ] Dialog + account page order of operations; remove the client gate
- [ ] Spec sentences (fallback-idp §3.2, registry-api §4.3 note)
- [ ] Tests: Rust (unadmitted vs admitted), Playwright, migrate roster readers
