---
# browserid-ng-djdz
title: 'Audit WS7: supply chain, build, deploy, secrets'
status: todo
type: task
created_at: 2026-11-01T12:40:56Z
updated_at: 2026-11-01T12:40:56Z
parent: browserid-ng-ag1l
---

cargo-audit, npm audit, pip-audit as standing CI gates. Dockerfile + .github/workflows (deploy keys, GHCR, secret exposure), age env files, root key file perms (July M8). Confirm broker-key.json and browserid.db in repo root are ignored and never shipped. Logging/PostHog payloads for identifier leaks.
