---
# browserid-ng-b873
title: 5-minute integration example (RP login + verify + agent side)
status: completed
type: task
priority: high
created_at: 2026-07-11T23:39:56Z
updated_at: 2026-07-11T23:55:27Z
---

The landing 'Add to your app' CTA needs a real copy-paste path. Build an end-to-end worked example: RP login button -> hosted /verify -> session, plus the agent side via browserid-agent CLI. Uses sdk/js @browserid/verify + verify-quickstart.md.

## Summary of Changes

examples/rp-quickstart — a one-file relying party: serves the browserid-ng sign-in button and verifies the assertion via @browserid/verify (audience pinned to RP_ORIGIN) to start an HMAC-signed session. Runs against hosted browserid.me or a local broker. test.mjs proves the glue (verify -> session -> /api/me, fail-closed, tampered-cookie rejection) against a mock verifier. The agent side is covered by examples/mcp-agent-auth.
