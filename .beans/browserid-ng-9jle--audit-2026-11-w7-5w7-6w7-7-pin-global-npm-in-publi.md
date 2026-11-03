---
# browserid-ng-9jle
title: '[Audit 2026-11] W7-5/W7-6/W7-7: pin global npm in publish.yml, npm ci --ignore-scripts with committed locks, optional image digests'
status: completed
type: bug
priority: normal
created_at: 2026-11-02T22:43:20Z
updated_at: 2026-11-03T09:16:18Z
parent: browserid-ng-ag1l
---

Findings: W7-5, W7-6, W7-7 (CI and image hygiene). Severity: Low. Decision: none needed (W7-7 is optional; accept if reproducibility is not wanted).

Where: .github/workflows/publish.yml:37 (npm install -g npm@latest unpinned in the job that holds the OIDC publishing identity); .github/workflows/sdk-tests.yml:26-38 and test.yml (npm install rather than npm ci in five SDK dirs, so CI can resolve a tree different from the lock and run post-install scripts of a newly published version; sdk/js, sdk/agent, sdk/mcp-auth have no committed lock); all Dockerfiles build rust:1.85-bookworm / debian:bookworm-slim / node / python by floating tag.

Change: pin npm@<version> in publish.yml and bump deliberately; npm ci --ignore-scripts where a lock exists and commit locks for sdk/js, sdk/agent, sdk/mcp-auth; optionally pin base images by digest.

Acceptance: workflows green; grep for "npm install" in .github/workflows returns nothing.

Reports: ws7 §2. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.


## Summary of Changes

Done 2026-11-03 on the audit-2026-11 branch.

- W7-5: publish.yml installs `npm@12.2.1` (current latest on 2026-11-03,
  >= 11.5.1 for trusted publishing) instead of `npm@latest`, with a comment
  saying why the job that holds the OIDC identity must not float.
- W7-6: every CI install is now `npm ci --ignore-scripts --no-audit
  --no-fund` (sdk-tests.yml x6, deploy-mcp-demo.yml, deploy-guestbook.yml);
  `grep 'npm install' .github/workflows` returns only the pinned global npm
  line. Lockfiles for sdk/express, sdk/hono, sdk/fastify and sdk/nextauth
  were regenerated (they carried a stale `../js` link at verify 0.2.0, which
  `npm ci` rejects); they now resolve @browserid-ng/verify ^0.3.0 -> 0.3.1
  from the registry, which is what `npm install` in CI was already doing.
  `npm ci --ignore-scripts` + tests verified: nextauth 9, express 7, hono 6,
  fastify 5, all passing. sdk/js, sdk/agent, sdk/mcp-auth, sdk/wallet and
  examples/mcp-agent-auth lockfiles were committed in bean j0rh.
- W7-7: all six Dockerfiles pin their base image by multi-arch manifest
  digest while keeping the tag readable
  (`FROM rust:1.85-bookworm@sha256:...`), with a comment on how to bump.
  Resolved from Docker Hub on 2026-11-03: rust:1.85-bookworm e51d0265...,
  debian:bookworm-slim 99c0b25c..., node:24-bookworm-slim c86ecead...,
  python:3.12-slim b18b261e..., nginx:1.27-alpine 65645c7b.... Not built
  locally (full image builds happen in CI); the digests are the manifest
  lists, so linux/amd64 resolution in CI is unchanged.
- The Dockerfile USER change (W7-8, bean 4c8h) was deliberately not touched.
