---
# browserid-ng-lnas
title: '[M5] mingo ops tooling calls nonexistent endpoints (/admin/provision, /wsapi/admin/cert_key)'
status: todo
type: bug
priority: normal
created_at: 2026-08-07T16:03:44Z
updated_at: 2026-08-07T16:03:44Z
parent: browserid-ng-8g49
---

mingo-app seed.rs:1261/appoint.rs:241/livetest.rs:482,1054 POST {idp}/admin/provision and seed.rs:1302 {broker}/wsapi/admin/cert_key, expecting a classic per-email cert. Neither route exists at HEAD (mingo-idp/src/lib.rs:42-68; no admin/cert_key in broker) and classic format no longer issued. Dead ops tooling; will fail next run. Port to device-cert flow or delete. See audit M5.
