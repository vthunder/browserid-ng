---
# browserid-ng-2jfh
title: Consolidate the broker's three device-cert issuance lanes onto one core
status: todo
type: task
created_at: 2026-08-28T19:54:54Z
updated_at: 2026-08-28T19:54:54Z
blocked_by:
    - browserid-ng-d0xb
---

Found during d0xb review (2026-08-28). Three lanes mint device+config cert pairs with divergent semantics: /device/issue (session+csrf, config cert covers [email, local+*@domain]), /auth/device_cert (fb_email+session, exact-address only — 7ww7 blast-radius narrowing for its mailbox-rooted bar), /idp/device_cert (hosted tenants, wildcard). fallback-idp-api-v1 resolves coverage by principle (coverage follows the authentication bar → wildcard at the session bar) and adds the ceremony page as a new consumer. Implement the page on the /device/issue core, migrate the dialog's /auth/device_cert consumer to the same core, retire the exact-only variant. Blocked by d0xb spec finalization.
