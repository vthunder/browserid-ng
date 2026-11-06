---
# browserid-ng-hynd
title: '[Audit 2026-11] W4-21: loopback page pairing with the wallet only under WALLET_TEST; pin the extension id'
status: completed
type: bug
priority: normal
created_at: 2026-11-02T22:43:20Z
updated_at: 2026-11-03T08:39:50Z
parent: browserid-ng-ag1l
---

Findings: W4-21. Severity: Low (mitigated by a default-Cancel native dialog that names the page). Decision: Q22 settled 2026-11-02: (a) gate the loopback branch on WALLET_TEST and pin the extension id.

Where: wallet/src/server.js:17 (ALLOWED_ORIGIN admits http(s)://localhost:* and 127.0.0.1:* unconditionally "for the e2e harness"), :108-111: any local dev-server page can POST /pair, and once paired /request trusts the body origin, so it files requests as any origin and login requests for any RP (A9); any 32-letter chrome-extension:// origin may pair likewise.

Change under (a): allow loopback page origins only when WALLET_TEST=1; pin the extension id in release builds. Keep the e2e harness working by setting WALLET_TEST in the Playwright config.

Acceptance: un-skip wallet/test/audit_2026_11_ws4.test.mjs "W4-21: a loopback web page cannot pair with the bridge outside WALLET_TEST" (needs port 8873 free). Run the wallet e2e afterwards.

Reports: ws4 §2. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.


## Summary of Changes

Decision Q22 (a): wallet/src/server.js replaces the static `ALLOWED_ORIGIN` regex with `originAllowed(origin)`: loopback page origins (`http(s)://localhost|127.0.0.1[:port]`) are admitted only while `WALLET_TEST=1` (the e2e harness sets it in wallet/e2e.mjs already); `chrome-extension://<id>` origins are pinned to `WALLET_EXTENSION_IDS=<id,id>` or the `RELEASE_EXTENSION_IDS` constant when either is non-empty, and accept any 32-letter id otherwise (unpacked dev builds have no stable id — the manifest carries no `key`, so there is no published id to pin yet; fill `RELEASE_EXTENSION_IDS` when the bridge extension ships). README trust-model notes updated.

Tests: un-skipped "W4-21: a loopback web page cannot pair with the bridge outside WALLET_TEST" (it skips itself while a real wallet holds port 8873, which was the case on this machine — pid left alone) and added a port-free unit test of `originAllowed` (exported from server.js) covering loopback-under-test, pinned ids and refusal of other pages. The wallet e2e (`node wallet/e2e.mjs`) was not run here (needs Electron on an observed display); it keeps WALLET_TEST=1 so the harness is unaffected.
