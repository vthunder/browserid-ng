---
# browserid-ng-gajq
title: '[Audit 2026-11] W5-6/W4-23: client IP from the proxy''s X-Forwarded-For hop (trusted-proxy count) in broker and wallet-service'
status: todo
type: bug
priority: normal
created_at: 2026-11-02T22:43:19Z
updated_at: 2026-11-02T22:43:19Z
parent: browserid-ng-ag1l
---

Findings: W5-6 (broker) and W4-23 (wallet-service). Severity: Low after verification (WS7 confirmed dokku's shipped nginx template overwrites X-Forwarded-For with $remote_addr, so the first hop is the connection address on the identity host today); the broker fix is still wanted so the throttles never depend on proxy config. Decision: Q7 settled 2026-11-02: both (infra declares and audits the value; broker takes the proxy's hop).

Where: browserid-broker/src/routes/auth.rs:47-61 (client_ip: first X-Forwarded-For hop, X-Real-IP fallback that the proxy never sets) used by rate_limit.rs, registry_login.rs and the code_guard callers; wallet-service/src/server.mjs:76-77 (clientIp: first XFF hop for every limiter and the audit-log ip).

Change: take the last hop (the hop the fronting proxy appended) or a configured trusted-proxy count (TRUSTED_PROXIES=1 default behind dokku; 0 for direct), in both the broker and wallet-service. Document the setting. The D8 and W5-2 limiter beans depend on this.

Acceptance: wallet-service/test/audit_2026_11_ws4.test.mjs: un-skip "W4-23: a client cannot spend another address's login budget, nor reset its own, via X-Forwarded-For". Broker: add a unit test for client_ip with a spoofed first hop.

Infra half (declare x-forwarded-for-value and assert it in audit-host.sh) is a separate task bean in sandmill-infra.

Reports: ws5 §2 (W5-6), ws4 §2 (W4-23), ws7 §6. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.
