---
# browserid-ng-6q3u
title: '[M2] SDK allowAgent:false default is dead code (verifier dropped subject)'
status: todo
type: bug
priority: normal
created_at: 2026-07-28T23:54:23Z
updated_at: 2026-08-17T09:23:36Z
parent: browserid-ng-wre6
---

docs/security-audit-2026-07-29.md (M2). sdk/js/index.mjs:100 reads json.subject||'user' but AccessVerificationResult has no subject field → agent-rejection branch unreachable; RPs relying on the human-only default silently accept agents.
- [ ] Derive agent-ness from grantee !== email, or remove allowAgent API + doc promise

## Re-verification 2026-08-17 — STILL VALID, provably dead + wider blast radius

sdk/js/index.mjs:100 sets `subject: json.subject || "user"`; gate at :110. Verifier `AccessVerificationResult` (browserid-broker/src/verifier.rs:107-131) has NO `subject` field — comment at :117 says "the old user/agent subject axis is gone." So subject is always "user", branch unreachable, agents pass as human logins. The usable signal `grantee` (differs from `email` when an agent acts) is read at index.mjs:98 only to default it — never compared.

Blast radius grew beyond the single file:
- Adapters forward the dead flag: sdk/express/index.mjs:35,39; sdk/fastify/index.mjs:35,38; sdk/hono/index.mjs:35,38; sdk/nextauth/index.mjs:46,51 (NextAuth adapter is NEW since audit — ships "humans only by default").
- Docs still promise it: sdk/js/README.md:101, sdk/nextauth/README.md:91, sdk/express/README.md:54, sdk/fastify/README.md:26, sdk/hono/README.md:30, examples/rp-quickstart/README.md:44.
- False assurance: sdk/js/index.test.mjs:68 and sdk/nextauth/test/nextauth.test.mjs:88 feed a FAKE verifier that returns `subject` — a shape the real broker never emits.
- Rust browserid-rp crate has no allowAgent equivalent (not affected).

Decision needed: rebuild the gate on `grantee !== email`, OR remove allowAgent + all README promises. Depends on whether the current model still has a meaningful human-vs-agent distinction.
