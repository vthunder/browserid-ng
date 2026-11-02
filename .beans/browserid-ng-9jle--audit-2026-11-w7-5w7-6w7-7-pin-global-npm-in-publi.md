---
# browserid-ng-9jle
title: '[Audit 2026-11] W7-5/W7-6/W7-7: pin global npm in publish.yml, npm ci --ignore-scripts with committed locks, optional image digests'
status: todo
type: bug
priority: normal
created_at: 2026-11-02T22:43:20Z
updated_at: 2026-11-02T22:43:20Z
parent: browserid-ng-ag1l
---

Findings: W7-5, W7-6, W7-7 (CI and image hygiene). Severity: Low. Decision: none needed (W7-7 is optional; accept if reproducibility is not wanted).

Where: .github/workflows/publish.yml:37 (npm install -g npm@latest unpinned in the job that holds the OIDC publishing identity); .github/workflows/sdk-tests.yml:26-38 and test.yml (npm install rather than npm ci in five SDK dirs, so CI can resolve a tree different from the lock and run post-install scripts of a newly published version; sdk/js, sdk/agent, sdk/mcp-auth have no committed lock); all Dockerfiles build rust:1.85-bookworm / debian:bookworm-slim / node / python by floating tag.

Change: pin npm@<version> in publish.yml and bump deliberately; npm ci --ignore-scripts where a lock exists and commit locks for sdk/js, sdk/agent, sdk/mcp-auth; optionally pin base images by digest.

Acceptance: workflows green; grep for "npm install" in .github/workflows returns nothing.

Reports: ws7 §2. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.
