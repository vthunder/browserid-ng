---
# browserid-ng-afn5
title: '[Audit 2026-11] W7-9 (sandmill-infra): second age recipient and a rotation note'
status: todo
type: task
priority: normal
created_at: 2026-11-02T22:43:21Z
updated_at: 2026-11-02T22:43:21Z
parent: browserid-ng-ag1l
---

Belongs in sandmill-infra, not this repo. Findings: W7-9. Severity: Low. Decision: Q12 settled 2026-11-02: (a) add a second age recipient (recovery key kept offline) and a dated rotation note.

What: every secrets/*.env.age file on both hosts and the host backups are encrypted to one age recipient (public half at ~/backups/sandmill/age-recipient.pub; private half in the password manager and on the mac mini backup path). Losing it loses recoverability; leaking it exposes everything at once; no rotation story is written down.

Change: re-encrypt with age -r <existing> -r <offline recovery key>; write keys/README.md rotation note (who holds what, how to rotate, when last rotated). The broker root key is not in id.env.age (it lives on the storage mount and in the age-encrypted host backup), so test that backup restore path too.

Reports: docs/security-audit-2026-11-ws7-supply-chain.md §4. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.
