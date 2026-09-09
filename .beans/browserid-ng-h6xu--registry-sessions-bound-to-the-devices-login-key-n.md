---
# browserid-ng-h6xu
title: Registry sessions bound to the device's login key (no member set, no per-call cert proofs)
status: in-progress
type: task
priority: high
created_at: 2026-09-09T17:58:59Z
updated_at: 2026-09-09T19:05:05Z
blocking:
    - browserid-ng-zpbh
---

Spec revision agreed with Dan 2026-09-09: every session is opened with and bound to the device's login key; Proof header always by that key; identity certs are account data only (attach records them; no session refresh); login keys enrolled at accounts/login_page (POST login-keys removed), carry a holder link, lose the status ref; stored_key failures answer login_required {url}; 'member' means identity again. Review draft: docs/plans/2026-09-09-session-key-draft.md. Supersedes the self-proven login-keys change in a069f73.

- [x] Dan reviews the draft (2026-09-09: lookup by cert; two levers, no flag; attach → {recorded}; creation keeps the cert)
- [ ] Spec text (§4.2, §4.4, §4.5, §5.2, §7.1)
- [ ] Registrar: extractor by login key; enrolment at accounts/login; holder link; login_required on stored_key failure; remove POST login-keys, member re-check, end_sessions_solely_on_cert
- [ ] Clients: registry-session.js (dialog + page share the browser's key), wallet/src/registry.js
- [ ] Tests: registry_api_test helpers; wallet e2e; account-registry-session spec
- [ ] Migration: honour existing login certs' keys; end existing sessions
