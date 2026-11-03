---
# browserid-ng-0vk8
title: '[Audit 2026-11] W2-1: python-mcp-auth, mcp-auth and gate stop normalizing the resource audience'
status: completed
type: bug
priority: normal
created_at: 2026-11-02T22:43:20Z
updated_at: 2026-11-03T08:20:44Z
parent: browserid-ng-ag1l
---

Findings: W2-1. Severity: Low (fail-closed: availability, not escalation). Decision: Q25 settled 2026-11-02: (a) stop normalizing; spec §5 audience is byte-exact.

Where: sdk/python-mcp-auth/browserid_mcp_auth/__init__.py:135 (resource.rstrip("/")), sdk/mcp-auth/index.mjs:159 (replace(/\/+$/, "")), sdk/gate/src/mount.mjs:55 (same): the audience sent to /verify is not the audience the record names, so a record for sbo+raw://avail:turing:506/ (the shipped mingo audience, memory: bare form required) never verifies through these three SDKs. @browserid-ng/verify passes the audience verbatim.

Change under (a): drop the normalization; if a canonical form is wanted apply it once at configuration and document it. Under (b): keep it and document that resources must be configured without a trailing slash.

Acceptance: delete the W2-1 row (P-OK-07) from EXPECTED_FAIL in sdk/python-mcp-auth/tests/test_conformance_vectors.py, sdk/mcp-auth/test/conformance-vectors.test.mjs, sdk/gate/test/conformance-vectors.test.mjs. Check mcp-demo / guestbook-mcp / github-mcp resource config before redeploying.

Reports: ws2 §2. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.


## Summary of Changes

Decision Q25 (a): the resource audience is byte-exact; none of the three SDKs normalizes it any more.

- sdk/mcp-auth/index.mjs: `createMcpAuth` keeps `resource` verbatim (the `replace(/\/+$/, "")` is gone) and `requestAuthoring` no longer strips the grant audience. `broker` is still origin-trimmed (it is a URL we build paths on, not an audience).
- sdk/gate/src/mount.mjs: `createMount` keeps `resource` verbatim.
- sdk/python-mcp-auth/browserid_mcp_auth/__init__.py: `McpAuth.resource` is no longer `rstrip("/")`-ed.
- READMEs (mcp-auth, python-mcp-auth, gate `--resource`): configure the resource exactly as the records name it; web resources without a trailing slash.

Tests: the mcp-auth pin that expected `RESOURCE + "/"` to reach `/verify` trimmed now asserts it arrives byte-exact. Conformance: the W2-1 half of P-OK-07 is un-listed in all three runners (sdk/mcp-auth, sdk/gate, sdk/python-mcp-auth); the vector stays listed as D7 only (scope entries) until bean oa6s re-records the hosted responses.

Deploy note (from the bean): check the mcp-demo / guestbook-mcp / github-mcp resource configuration has no trailing slash before redeploying with these packages.
