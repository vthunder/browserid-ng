---
# browserid-ng-jvcl
title: '[H3] Whole e2e flows quarantined; ugg2 cert-leak security regression test skipped'
status: todo
type: bug
priority: high
created_at: 2026-08-07T16:03:17Z
updated_at: 2026-08-07T16:03:17Z
parent: browserid-ng-8g49
---

e2e-tests: silent-assertion.spec.ts fully test.fixme (8/8); primary-idp.spec.ts skips 13/25 incl line 656 (bean-ugg2 cert-leak-to-malicious-parent regression); cross-origin-rp.spec.ts fixmes the cross-origin section incl the prod origin-split test; guestbook.spec.ts:53 fills nonexistent #pv-handles (UI uses #pv-handle). Tracking bean browserid-ng-78hi understates it. Re-enable/rewrite; ugg2 first. See audit H3.
