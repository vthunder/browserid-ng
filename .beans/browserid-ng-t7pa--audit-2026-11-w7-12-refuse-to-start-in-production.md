---
# browserid-ng-t7pa
title: '[Audit 2026-11] W7-12: refuse to start in production without SMTP (console sender logs codes)'
status: completed
type: bug
priority: high
created_at: 2026-11-02T22:43:19Z
updated_at: 2026-11-03T08:32:04Z
parent: browserid-ng-ag1l
---

Findings: W7-12. Severity: Medium (conditional on a misconfiguration, but silent). Decision: none needed.

Where: browserid-broker/src/email/console.rs:24-42: when SMTP_HOST is unset the broker silently falls back to the console sender and prints every verification and reset code with the address at info level and on stdout, which lands in the dokku log.

Change: in production (BROKER_ENV=production or DOMAIN != localhost) refuse to start without SMTP configuration unless EMAIL_SENDER=console is set explicitly. Add a startup test for the refusal.

Reports: ws7 §5. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.



## Summary of Changes

- email/mod.rs: `choose_sender(domain, smtp_configured, EMAIL_SENDER, disable_smtp) -> Result<SenderChoice, String>` with `is_production_domain` (any `BROKER_DOMAIN` host that is not localhost/127.x/::1). SMTP wins when configured; the console sender is allowed only on a loopback domain, under `DISABLE_SMTP` (the e2e switch), or with an explicit `EMAIL_SENDER=console`; a production domain without SMTP returns an error naming the four required `SMTP_*` vars. Unit tests cover all branches (the startup refusal test).
- main.rs: uses it and bails before binding; the console path logs at warn ("codes are printed to stdout (dev only)") instead of info.
- lib.rs re-exports `choose_sender`/`SenderChoice`. README configuration table: `SMTP_*` and the new `EMAIL_SENDER` rows.
- New env var: `EMAIL_SENDER` (unset by default; `console` = opt in to the stdout sender on a non-loopback domain, dev only). No other behaviour change for correctly configured deployments.
