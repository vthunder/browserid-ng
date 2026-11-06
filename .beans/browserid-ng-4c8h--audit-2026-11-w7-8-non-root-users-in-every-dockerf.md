---
# browserid-ng-4c8h
title: '[Audit 2026-11] W7-8: non-root users in every Dockerfile, app.json healthcheck; M8 residual key-file mode'
status: todo
type: bug
priority: high
created_at: 2026-11-02T22:43:20Z
updated_at: 2026-11-02T22:44:00Z
parent: browserid-ng-ag1l
blocked_by:
    - browserid-ng-u3q7
---

Findings: W7-8 (Dockerfile side) plus the July M8 residual (Low). Severity: Medium. Decision: Q9 settled 2026-11-02: (a) non-root users in the Dockerfiles and a chown step in sandmill-infra, one app at a time, broker first. The host-side chown is a separate task bean (sandmill-infra).

Where: Dockerfile (broker: no USER, runs as uid 0 with /data key + db root-owned), wallet-service, mcp-demo, guestbook-mcp, python-mcp-demo Dockerfiles (root; node:24-slim's node user unused). No healthcheck, no app.json CHECKS, so a release that fails to bind is only seen as a 502. browserid-broker/src/config.rs:116-144 (save_keypair: fs::write then chmod 0600, a microsecond 0644 window; load_keypair never re-asserts the mode, so a pre-July 0644 file stays 0644).

Change: broker Dockerfile RUN useradd -r -u 10001 broker && chown broker /data; USER broker. Node images USER node; Python image a non-root user. Add app.json with a healthcheck on /.well-known/browserid. Read-only root fs, --tmpfs /tmp and no-new-privileges go in apps/identity/id.conf docker-options (infra). M8 residual: open the key file with OpenOptions::mode(0o600) and assert the mode on load (warn or refuse if group/other bits are set).

Order: infra chown first (the task bean), then the broker image, then the Node and Python images. Verify prod after each deploy.

Reports: ws7 §3 and §4 (M8). Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.
