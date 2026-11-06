---
# browserid-ng-u3q7
title: '[Audit 2026-11] W7-8 (sandmill-infra): chown storage mounts to the container uid; read-only fs and no-new-privileges docker-options'
status: todo
type: task
priority: high
created_at: 2026-11-02T22:43:20Z
updated_at: 2026-11-02T22:43:20Z
parent: browserid-ng-ag1l
---

Belongs in sandmill-infra, not this repo. Findings: W7-8 host half. Decision: Q9 settled 2026-11-02: (a).

What: before the broker image switches to USER broker (uid 10001), chown the identity host's storage mount for the id app to 10001 (dokku storage:ensure-directory --chown <uid>, or by hand), and the same for each Node/Python app's mounts if any. Add --read-only --tmpfs /tmp --security-opt no-new-privileges to apps/identity/id.conf docker-options once the image is verified to need no writable paths beyond /data and /tmp. Run bin/audit-host.sh before touching the host (memory: infra lives in sandmill-infra; audit first).

Pairs with the W7-8 Dockerfile bean in this repo; that bean's broker deploy must follow this step.

Reports: docs/security-audit-2026-11-ws7-supply-chain.md §3 and §7. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.
