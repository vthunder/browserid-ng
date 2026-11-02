---
# browserid-ng-jxhb
title: '[Audit 2026-11] Q13: salt the PostHog distinct id with a deployment secret'
status: todo
type: bug
priority: normal
created_at: 2026-11-02T22:43:21Z
updated_at: 2026-11-02T22:43:21Z
parent: browserid-ng-ag1l
---

Findings: WS7 §5 PostHog observation (no finding id in the report). Severity: Low. Decision: Q13 settled 2026-11-02: (a) salt with a server secret; closes the rainbow-table argument.

Where: browserid-broker/src/analytics.rs:114: distinct_id = u_<sha256(email)[:12]>, unsalted, so anyone with PostHog access and an email guess can confirm membership. Everything else about the analytics wiring was verified PII-safe (no raw email, code, IP or RP origin; client side pinned bundle, first-party proxy, redactor).

Change: derive the id with HMAC-SHA256 under a per-deployment secret (new env var, add to id.env.age); accept that historical ids do not join. If W7-10/W7-11 adopts the hashed id for logs, use the same salted function.

Acceptance: unit test that the id changes with the secret and is stable for one secret.

Reports: ws7 §5. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.
