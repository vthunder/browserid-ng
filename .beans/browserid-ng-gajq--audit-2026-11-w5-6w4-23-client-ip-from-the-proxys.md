---
# browserid-ng-gajq
title: '[Audit 2026-11] W5-6/W4-23: client IP from the proxy''s X-Forwarded-For hop (trusted-proxy count) in broker and wallet-service'
status: completed
type: bug
priority: normal
created_at: 2026-11-02T22:43:19Z
updated_at: 2026-11-03T08:17:49Z
parent: browserid-ng-ag1l
---

Findings: W5-6 (broker) and W4-23 (wallet-service). Severity: Low after verification (WS7 confirmed dokku's shipped nginx template overwrites X-Forwarded-For with $remote_addr, so the first hop is the connection address on the identity host today); the broker fix is still wanted so the throttles never depend on proxy config. Decision: Q7 settled 2026-11-02: both (infra declares and audits the value; broker takes the proxy's hop).

Where: browserid-broker/src/routes/auth.rs:47-61 (client_ip: first X-Forwarded-For hop, X-Real-IP fallback that the proxy never sets) used by rate_limit.rs, registry_login.rs and the code_guard callers; wallet-service/src/server.mjs:76-77 (clientIp: first XFF hop for every limiter and the audit-log ip).

Change: take the last hop (the hop the fronting proxy appended) or a configured trusted-proxy count (TRUSTED_PROXIES=1 default behind dokku; 0 for direct), in both the broker and wallet-service. Document the setting. The D8 and W5-2 limiter beans depend on this.

Acceptance: wallet-service/test/audit_2026_11_ws4.test.mjs: un-skip "W4-23: a client cannot spend another address's login budget, nor reset its own, via X-Forwarded-For". Broker: add a unit test for client_ip with a spoofed first hop.

Infra half (declare x-forwarded-for-value and assert it in audit-host.sh) is a separate task bean in sandmill-infra.

Reports: ws5 §2 (W5-6), ws4 §2 (W4-23), ws7 §6. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.


## Summary of Changes (wallet-service half only)

- wallet-service/src/config.mjs: `TRUSTED_PROXIES` from `WALLET_TRUSTED_PROXIES` (default 1 — dokku's nginx; 0 for direct clients). wallet-service/src/server.mjs: `clientIp` takes the hop the TRUSTED_PROXIES-th proxy appended to `X-Forwarded-For` (the Nth from the end), never the client-written first hop; with 0 trusted proxies, or fewer hops than proxies, it is the socket address. Every limiter key and the audit-log `ip` use it. README documents the setting.
- Tests: un-skipped "W4-23: a client cannot spend another address's login budget, nor reset its own, via X-Forwarded-For" in wallet-service/test/audit_2026_11_ws4.test.mjs; the test file sets `WALLET_TRUSTED_PROXIES=0` (it connects directly). 31 pass / 0 fail.

Not in this bean: the broker half (browserid-broker/src/routes/auth.rs client_ip + unit test) belongs to the Rust agents; the infra half is a sandmill-infra task.

## Summary of Changes (broker half)

- routes/auth.rs: `client_ip` no longer trusts the first `X-Forwarded-For` hop nor `X-Real-IP`. New `forwarded_client_ip(headers, trusted)` takes the hop `trusted` from the END of the list (the one the outermost trusted proxy appended); `TRUSTED_PROXIES=0` ignores the header. New outermost middleware `resolve_client_ip` works the address out once per request (trusted hop, else the connection's peer address via `ConnectInfo`), strips any client-sent copy, and stamps it in `x-browserid-client-ip`, which `client_ip` prefers. Unit tests cover a spoofed first hop, two proxies, direct exposure, X-Real-IP being ignored.
- routes/mod.rs: the middleware is the outermost layer of the whole router; `routes::{set_trusted_proxies, DEFAULT_TRUSTED_PROXIES}` exported.
- main.rs: reads `TRUSTED_PROXIES` (default 1, dokku's nginx; invalid values refuse to start) and serves with `into_make_service_with_connect_info` so the peer address is available.
- README.md configuration table: `TRUSTED_PROXIES` row.
- Every existing throttle (rate_limit.rs, registry_login.rs, signin_code.rs, authenticate_user) inherits the fix through `client_ip`. The wallet-service half (W4-23) is another agent's.
