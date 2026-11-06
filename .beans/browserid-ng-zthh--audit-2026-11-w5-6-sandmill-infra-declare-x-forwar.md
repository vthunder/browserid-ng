---
# browserid-ng-zthh
title: '[Audit 2026-11] W5-6 (sandmill-infra): declare x-forwarded-for-value $remote_addr and assert it in audit-host.sh'
status: todo
type: task
priority: normal
created_at: 2026-11-02T22:43:20Z
updated_at: 2026-11-02T22:43:20Z
parent: browserid-ng-ag1l
---

Belongs in sandmill-infra, not this repo. Findings: W5-6 infra half (Q7, settled 2026-11-02: both). Status todo.

What: dokku's shipped nginx template (0.38.31) overwrites X-Forwarded-For with $remote_addr by default, so the broker's throttles see the connection address today, but nothing in sandmill-infra declares or checks it, and one dokku nginx:set id x-forwarded-for-value '$http_x_forwarded_for' (the documented "behind another proxy" recipe) silently reintroduces the hole. If the host is ever put behind Cloudflare or a load balancer every client shares one bucket.

Change: pin nginx:set id x-forwarded-for-value '$remote_addr' in apps/identity/id.conf (and the equivalent for the wallet-service app on its host); have bin/audit-host.sh assert dokku nginx:report <app> --nginx-computed-x-forwarded-for-value equals $remote_addr. Run bin/audit-host.sh before touching either host.

Pairs with the broker/wallet-service XFF bean in this repo (take the proxy's hop, trusted-proxy count), which is what removes the dependency on this setting.

Reports: docs/security-audit-2026-11-ws7-supply-chain.md §6. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.
