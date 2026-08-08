---
# browserid-ng-o68b
title: '[M2] Support-doc ''mint'' field and /verify route shapes differ from spec'
status: todo
type: bug
priority: normal
created_at: 2026-08-07T16:03:17Z
updated_at: 2026-08-07T16:03:17Z
parent: browserid-ng-8g49
---

spec §3.1 lists REQUIRED 'mint' field; discovery.rs:18-77 has none (published as access-cert) + 5 undocumented fields. Spec §6.1 documents POST /verify with 'assertion' field + cites nonexistent routes/verify.rs; actual is POST /verify-access with 'presentation' (routes/device.rs:335-341). Update §3.1/§6.1. See audit M2.
