---
# browserid-ng-tx5r
title: 'Audit WS8: red-team scenario walkthroughs + PoCs (local broker only)'
status: todo
type: task
priority: normal
created_at: 2026-11-01T12:40:56Z
updated_at: 2026-11-01T15:43:06Z
parent: browserid-ng-ag1l
blocked_by:
    - browserid-ng-n6nn
    - browserid-ng-t25u
    - browserid-ng-p5vc
---

Trace end-to-end: evil RP phishing an assertion; evil MCP server escalating a warrant; co-tenant on hosted IdP; stolen session cookie / recovery cannot evict attacker; stale status list defeating revocation; key compromise -> can everything be revoked? Build PoCs for every High+ candidate from WS4-6 against a local :3000 broker. Never against prod.

## From WS1 — PoC targets in order
D1 (browser auth cert mints as user+agent@), D2 (retired/self-minted config cert approves a consent request), D3 (choose another tenant user's holder on /idp/device_cert), D8 (approval-code brute force), D5 (narrowed policy record admits any holder via gate). Local broker only. S1 (login_page token to attacker return_url) is a design finding; a PoC demonstrates the phishing shape.
