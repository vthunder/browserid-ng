---
# browserid-ng-hynd
title: '[Audit 2026-11] W4-21: loopback page pairing with the wallet only under WALLET_TEST; pin the extension id'
status: todo
type: bug
priority: normal
created_at: 2026-11-02T22:43:20Z
updated_at: 2026-11-02T22:43:20Z
parent: browserid-ng-ag1l
---

Findings: W4-21. Severity: Low (mitigated by a default-Cancel native dialog that names the page). Decision: Q22 settled 2026-11-02: (a) gate the loopback branch on WALLET_TEST and pin the extension id.

Where: wallet/src/server.js:17 (ALLOWED_ORIGIN admits http(s)://localhost:* and 127.0.0.1:* unconditionally "for the e2e harness"), :108-111: any local dev-server page can POST /pair, and once paired /request trusts the body origin, so it files requests as any origin and login requests for any RP (A9); any 32-letter chrome-extension:// origin may pair likewise.

Change under (a): allow loopback page origins only when WALLET_TEST=1; pin the extension id in release builds. Keep the e2e harness working by setting WALLET_TEST in the Playwright config.

Acceptance: un-skip wallet/test/audit_2026_11_ws4.test.mjs "W4-21: a loopback web page cannot pair with the bridge outside WALLET_TEST" (needs port 8873 free). Run the wallet e2e afterwards.

Reports: ws4 §2. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.
