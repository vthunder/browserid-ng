---
# browserid-ng-8z5m
title: Warrant UI '(will activate)' identity doesn't trigger IdP login + cert refresh
status: todo
type: bug
priority: normal
created_at: 2026-07-17T14:30:49Z
updated_at: 2026-07-17T14:31:14Z
parent: browserid-ng-mr2n
---

Roadmap item 6 (see the CLI-auth epic). On browserid.me/account, when the user is NOT signed into a primary identity, the warrant UI offers it labeled "(will activate)", but actually authorizing/using it fails with "not authenticated". Expected: selecting a "(will activate)" identity triggers a login to that identity's IdP and a certificate refresh, then proceeds. Current workaround (dan): go to an RP (mingo), log out, log in as the primary identity, then the cert is fresh. Fix the /account warrant flow to drive the IdP login + cert refresh inline.
