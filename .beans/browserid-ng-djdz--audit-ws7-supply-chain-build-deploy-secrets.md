---
# browserid-ng-djdz
title: 'Audit WS7: supply chain, build, deploy, secrets'
status: completed
type: task
priority: normal
created_at: 2026-11-01T12:40:56Z
updated_at: 2026-11-02T21:55:40Z
parent: browserid-ng-ag1l
---

cargo-audit, npm audit, pip-audit as standing CI gates. Dockerfile + .github/workflows (deploy keys, GHCR, secret exposure), age env files, root key file perms (July M8). Confirm broker-key.json and browserid.db in repo root are ignored and never shipped. Logging/PostHog payloads for identifier leaks.

## Checklist

- [x] cargo-audit / npm audit / pip-audit run on localtest; advisories tabulated with reachability
- [x] CI gate: .github/workflows/supply-chain.yml + scripts/supply-chain-audit.sh (`make audit`), ignore files with reasons
- [x] Dockerfiles + workflows reviewed (keys, GHCR perms, injection, pinning, cache, image contents, runtime hardening)
- [x] Secrets: gitignore/history/age layout; gitleaks over 1020 commits (clean after allowlisting test fixtures)
- [x] July M8 re-verified (holds)
- [x] Logging + PostHog identifier review
- [x] Q7 infra half: dokku default `x-forwarded-for-value=$remote_addr`, undeclared in sandmill-infra
- [x] Report docs/security-audit-2026-11-ws7-supply-chain.md

## Summary of Changes

- Report: docs/security-audit-2026-11-ws7-supply-chain.md (advisory tables, W7-1..W7-12, R7-1..R7-3, Q7 answer, decisions).
- New CI gate `.github/workflows/supply-chain.yml` (cargo-audit, npm audit, pip-audit, gitleaks; push/PR/weekly; SHA-pinned actions).
- `scripts/supply-chain-audit.sh` + `make audit`: the same policy locally.
- Ignore lists: `.cargo/audit.toml` (two hickory advisories with no fix), `.github/supply-chain/npm-ignore.txt`, `pip-ignore.txt` (empty, documented), `.gitleaks.toml` (test fixtures).
- Gate is red on main until R7-1/2/3 (cargo update, npm audit fix x7, fastmcp pin) land; no production code or infra changed.
