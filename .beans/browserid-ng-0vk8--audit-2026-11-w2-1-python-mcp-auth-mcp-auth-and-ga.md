---
# browserid-ng-0vk8
title: '[Audit 2026-11] W2-1: python-mcp-auth, mcp-auth and gate stop normalizing the resource audience'
status: todo
type: bug
priority: normal
created_at: 2026-11-02T22:43:20Z
updated_at: 2026-11-02T22:43:20Z
parent: browserid-ng-ag1l
---

Findings: W2-1. Severity: Low (fail-closed: availability, not escalation). Decision: Q25 settled 2026-11-02: (a) stop normalizing; spec §5 audience is byte-exact.

Where: sdk/python-mcp-auth/browserid_mcp_auth/__init__.py:135 (resource.rstrip("/")), sdk/mcp-auth/index.mjs:159 (replace(/\/+$/, "")), sdk/gate/src/mount.mjs:55 (same): the audience sent to /verify is not the audience the record names, so a record for sbo+raw://avail:turing:506/ (the shipped mingo audience, memory: bare form required) never verifies through these three SDKs. @browserid-ng/verify passes the audience verbatim.

Change under (a): drop the normalization; if a canonical form is wanted apply it once at configuration and document it. Under (b): keep it and document that resources must be configured without a trailing slash.

Acceptance: delete the W2-1 row (P-OK-07) from EXPECTED_FAIL in sdk/python-mcp-auth/tests/test_conformance_vectors.py, sdk/mcp-auth/test/conformance-vectors.test.mjs, sdk/gate/test/conformance-vectors.test.mjs. Check mcp-demo / guestbook-mcp / github-mcp resource config before redeploying.

Reports: ws2 §2. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.
