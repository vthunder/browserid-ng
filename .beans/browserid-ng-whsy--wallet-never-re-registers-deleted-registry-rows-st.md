---
# browserid-ng-whsy
title: 'Wallet never re-registers: deleted registry rows stay gone; revoked certs not surfaced'
status: todo
type: task
priority: normal
created_at: 2026-08-29T10:43:40Z
updated_at: 2026-08-29T10:43:46Z
parent: browserid-ng-9yyk
---

Observed by Dan 2026-08-29: after removing all devices on /account (including the mac-mini wallet's), the wallet's row never returns and the account page no longer lists the native wallet; the tray still claims 'signed in as danmills@sandmill.org' even though those certs were revoked at removal. The converged wallet calls devices/register exactly once, at bootstrap (wallet/src/bootstrap.js registerAtRegistry) — there is no self-heal analogue of the dialog's per-login devices/register. Add: (1) periodic/startup re-registration — devices/register is verified + idempotent, so calling it on inbox-watch start (registry.js) is safe and resurrects swept rows exactly like the dialog lane; (2) detect the revoked state (token exchange / mint failures with a revoked bound cert) and surface it in the tray ('identity revoked — set up again') instead of silently claiming a working identity. Note: re-registration of a REVOKED cert correctly refuses — that is the detection signal.
