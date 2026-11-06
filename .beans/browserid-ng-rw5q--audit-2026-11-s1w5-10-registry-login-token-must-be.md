---
# browserid-ng-rw5q
title: '[Audit 2026-11] S1/W5-10: registry login token must be bound to an accepted return origin in the minting handler'
status: completed
type: bug
priority: high
created_at: 2026-11-02T22:43:19Z
updated_at: 2026-11-03T08:13:57Z
parent: browserid-ng-ag1l
---

Findings: S1 (spec, accepted 2026-11-01) and W5-10 (code side). Severity: High. Decision: settled (S1 accepted; reg §4.2 amended: the token goes only to an accepted return origin, checked in the handler that mints it).

Where: browserid-broker/src/routes/registry_login.rs:34-78 (mints the login-page token with no return_url / origin binding); delivery is decided by browserid-broker/static/common/js/registry-login.js. WS8 §4 has the phishing walkthrough: an attacker-initiated login-page flow delivers a token minted under the victim's session to an attacker-chosen return target; the token enrols a login key, which is a full account session.

Change (either, per the accepted S1 text; the first is simpler and matches fb §3.1):
- Make the minting handler take return_origin, check it against the accepted return-origin rule (same rule as /device/issue, routes/device.rs:273-277), refuse otherwise, and bind the token to that origin so the page cannot redirect it; or
- bind the token to the opener's login-key public key passed in the opening fragment so only that key can spend it.
Update registry-login.js to send the origin. If a per-origin limiter is added, it inherits W5-6 (XFF bean).

Acceptance (un-ignore): browserid-broker/tests/authz_matrix_test.rs: registry_login_token_minting_checks_the_return_origin. Run the Playwright e2e for the registry login flow before deploying (CI does not run e2e).

Reports: ws1 §2 S1, ws5 §1 (S1) and §2a (W5-10), ws8 §4. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.



## Summary of Changes

- routes/registry_login.rs: `POST /wsapi/registry_login` and `POST /wsapi/registry_login_proofs` take a REQUIRED `return_origin` (plus optional `return_url`) and refuse with `return_origin_not_allowed` (403) unless the origin passes the same accepted-return-origin rule as /device/issue (`state.return_origin_accepted`: loopback, custom scheme, own origin, TRUSTED_WALLET_ORIGINS) and `return_url` is same-origin to it. The check runs before any password work. `registry_login_hints` mints nothing and is unchanged.
- return_origin.rs: new `same_origin(url, origin)` helper (default-port aware, rejects userinfo) with unit tests.
- static/common/js/registry-login.js sends the fragment's return_origin/return_url on both minting calls; static/dialog.js and static/common/js/registry-session.js (same-origin wallet path) send `window.location.origin`.
- Tests: un-ignored `registry_login_token_minting_checks_the_return_origin`; test helpers (tests/common/registry.rs, registry_api_test.rs) send the origin.
- Deploy note: dialog.js and registry-login.js changed; run the Playwright registry-login e2e before deploying (CI does not run e2e).
