---
# browserid-ng-tnwb
title: 35 of 105 e2e tests fail locally on clean main (pre-existing)
status: todo
type: bug
priority: low
created_at: 2026-07-23T22:50:24Z
updated_at: 2026-07-23T22:50:24Z
---

Running the Playwright suite locally on unmodified main (2026-07-24, after installing chromium build v1200): 65 passed / 35 failed / 2 skipped / 3 did not run. Failures cluster in primary-idp.spec (mock IdP postMessage/provisioning flows), silent-assertion.spec (timeouts waiting for onlogin/onmatch), cross-origin-rp.spec, marketing-split.spec (MARKETING_URL redirects), include-api, guestbook, paired-provisioning, accepted-fallbacks. Verified unrelated to the 4lxl status-check change: identical failure sets with and without it. May be local-env drift (fresh chromium headless-shell v1200 / missing env for multi-origin specs) vs CI; triage whether these pass in CI and what env the suite expects locally.
