---
# browserid-ng-2jfh
title: Consolidate the broker's three device-cert issuance lanes onto one core
status: completed
type: task
priority: normal
created_at: 2026-08-28T19:54:54Z
updated_at: 2026-08-28T22:30:46Z
parent: browserid-ng-9yyk
blocked_by:
    - browserid-ng-d0xb
---

Found during d0xb review (2026-08-28). Three lanes mint device+config cert pairs with divergent semantics: /device/issue (session+csrf, config cert covers [email, local+*@domain]), /auth/device_cert (fb_email+session, exact-address only — 7ww7 blast-radius narrowing for its mailbox-rooted bar), /idp/device_cert (hosted tenants, wildcard). fallback-idp-api-v1 resolves coverage by principle (coverage follows the authentication bar → wildcard at the session bar) and adds the ceremony page as a new consumer. Implement the page on the /device/issue core, migrate the dialog's /auth/device_cert consumer to the same core, retire the exact-only variant. Blocked by d0xb spec finalization.

## Summary of Changes

One issuance core. New fallback ceremony page /device-authorize (static/device-authorize.html + common/js/fb-device-authorize.js) implements the standard fragment/return contract over the broker-session backend and issues via /device/issue (authorize_mint bar, wildcard rule, fresh issuer-assigned holder, UA label). Live-session visits require an explicit consent click (mxcn) and return_url is same-origin-validated (9it0). Discovery: support doc now advertises device-authorization + access-cert (device-cert key dropped; core §3.1 qualified by rjge) and registry.browser.account. Retired the exact-only /auth/send + /auth/verify + /whoami + /auth/device_cert lane and deleted routes/fallback_idp.rs + its test file (its only consumers were tests; registry_api_test now issues via /device/issue). mint_chokepoint guard updated. Playwright spec fallback-device-authorize.spec.ts covers the real ceremony (password, session-consent, cancel, cross-origin refusal, wrong password, uboq stale path). Deployed + prod-verified 2026-08-29.
