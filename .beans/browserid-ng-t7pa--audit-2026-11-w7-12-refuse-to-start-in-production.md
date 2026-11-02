---
# browserid-ng-t7pa
title: '[Audit 2026-11] W7-12: refuse to start in production without SMTP (console sender logs codes)'
status: todo
type: bug
priority: high
created_at: 2026-11-02T22:43:19Z
updated_at: 2026-11-02T22:43:19Z
parent: browserid-ng-ag1l
---

Findings: W7-12. Severity: Medium (conditional on a misconfiguration, but silent). Decision: none needed.

Where: browserid-broker/src/email/console.rs:24-42: when SMTP_HOST is unset the broker silently falls back to the console sender and prints every verification and reset code with the address at info level and on stdout, which lands in the dokku log.

Change: in production (BROKER_ENV=production or DOMAIN != localhost) refuse to start without SMTP configuration unless EMAIL_SENDER=console is set explicitly. Add a startup test for the refusal.

Reports: ws7 §5. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.
