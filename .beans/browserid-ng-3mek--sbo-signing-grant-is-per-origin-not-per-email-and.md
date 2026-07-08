---
# browserid-ng-3mek
title: SBO signing grant is per-origin (not per-email) and can't be revoked
status: todo
type: bug
priority: high
created_at: 2026-07-08T06:13:39Z
updated_at: 2026-07-08T06:13:39Z
parent: browserid-ng-8u60
---

Consent screen says 'sign as alice@… / revoke by signing out', but the stored grant is siteInfo[origin].sbo_sign_granted=true — not bound to email — so a granted origin can sign as ANY resident email (sbo-signer.js:94-104, start.js:199-211). Logout clears logged_in but never the grant, so 'revoke by signing out' has no code path.
- [ ] Bind the grant to the consented email (or change the consent copy)
- [ ] Clear sbo_sign_granted on logout
- [ ] Add a grant management/revocation surface
