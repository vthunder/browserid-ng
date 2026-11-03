---
# browserid-ng-3k53
title: '[Audit 2026-11] D13: hosted wallet keeps status refs, re-checks on refresh, adds revoke/disconnect'
status: completed
type: bug
priority: normal
created_at: 2026-11-02T22:43:20Z
updated_at: 2026-11-03T08:29:48Z
parent: browserid-ng-ag1l
---

Findings: D13. Severity: Low (RP-session semantics; the asset behind the session is a custodied agent key). Decision: Q21 settled 2026-11-02: (a) keep status refs, re-check status on refresh (fail closed), add disconnect; after the Mediums.

Where: wallet-service/src/server.mjs:116-120 (statusRefs dropped at login), src/oauth.mjs:213-227 (30-day refresh re-mints 1 h tokens with no verifier contact); no RFC 7009 revoke, no logout, no per-tenant disconnect; the accounts table stores only email, created_at.

Change under (a): persist statusRefs per account; call checkStatus on refresh and fail closed; add /oauth/revoke and a "disconnect all clients" page or MCP tool.

Acceptance: un-skip wallet-service/test/audit_2026_11_ws4.test.mjs "D13: a tenant can revoke a connection (RFC 7009 /oauth/revoke)"; the two D13 pins keep passing.

Reports: ws4 §1.5. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.


## Summary of Changes

Decision Q21 (a): the hosted wallet keeps the sign-in's status refs, re-checks them fail-closed, and gains revoke / disconnect.

- wallet-service/src/oauth.mjs: the session cookie carries the login's `statusRefs`; `approveAuthorization` copies them into the code and `issueTokenPair` into every access/refresh token (per connection — a stronger binding than per account, since a later login must not relive an older connection). `tokenGrant` is async and takes `{ checkStatus }`: a refresh is granted only on `{ok:true, revoked:false}`; an unreachable verifier refuses (nothing minted, nothing burned); a revoked login refuses and burns the (account, client) family; a pre-D13 row without refs refuses. New `revokeToken` (RFC 7009: token + client_id from the issuing public client ends that connection; unknown/foreign tokens answer 200 without effect), `disconnectAll`, `listConnections`. AS metadata advertises `revocation_endpoint`.
- wallet-service/src/server.mjs: `createWalletService({ verifyLogin, checkStatus })` (default: `@browserid-ng/verify`'s `checkStatus`); `/oauth/approve` and the new `/oauth/disconnect` require a LIVE session (status re-checked, fail-closed: 503 unreachable / 401 revoked); `POST /oauth/revoke`; `GET /account` (sign-in + connection list + "Disconnect all clients"), `GET /oauth/connections`. Audit rows: `oauth.revoke`, `oauth.disconnect_all`.
- wallet-service/src/db.mjs: `status_refs` column on `oauth_codes` and `oauth_tokens`, with an ALTER migration for existing databases. pages.mjs: `accountPage()`. README updated.

Tests (wallet-service/test/audit_2026_11_ws4.test.mjs): un-skipped the RFC 7009 revoke test; the two "pinned" D13 observations ("status refs not retained", "refresh re-mints without verifier contact") necessarily flip under Q21 (a) and now assert the new behaviour (refs ride into tokens; refresh asks the verifier with the login's refs, refuses on unreachable, burns on revoked); added a disconnect-all test. The service takes an injected `checkStatus`, so no test reaches the network. 29 pass / 0 fail / 1 skipped (W4-23, bean gajq).

Not done: no MCP "disconnect" tool — the `/account` page is the human-facing lever (the bean offered either).
