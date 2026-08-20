---
# browserid-ng-6q3u
title: '[M2] SDK allowAgent:false default is dead code (verifier dropped subject)'
status: completed
type: bug
priority: normal
created_at: 2026-07-28T23:54:23Z
updated_at: 2026-08-20T09:40:13Z
parent: browserid-ng-wre6
---

docs/security-audit-2026-07-29.md (M2). sdk/js/index.mjs:100 reads json.subject||'user' but AccessVerificationResult has no subject field → agent-rejection branch unreachable; RPs relying on the human-only default silently accept agents.
- [x] Decide direction: REMOVE allowAgent (direction A — see Decision below)

## Re-verification 2026-08-17 — STILL VALID, provably dead + wider blast radius

sdk/js/index.mjs:100 sets `subject: json.subject || "user"`; gate at :110. Verifier `AccessVerificationResult` (browserid-broker/src/verifier.rs:107-131) has NO `subject` field — comment at :117 says "the old user/agent subject axis is gone." So subject is always "user", branch unreachable, agents pass as human logins. The usable signal `grantee` (differs from `email` when an agent acts) is read at index.mjs:98 only to default it — never compared.

Blast radius grew beyond the single file:
- Adapters forward the dead flag: sdk/express/index.mjs:35,39; sdk/fastify/index.mjs:35,38; sdk/hono/index.mjs:35,38; sdk/nextauth/index.mjs:46,51 (NextAuth adapter is NEW since audit — ships "humans only by default").
- Docs still promise it: sdk/js/README.md:101, sdk/nextauth/README.md:91, sdk/express/README.md:54, sdk/fastify/README.md:26, sdk/hono/README.md:30, examples/rp-quickstart/README.md:44.
- False assurance: sdk/js/index.test.mjs:68 and sdk/nextauth/test/nextauth.test.mjs:88 feed a FAKE verifier that returns `subject` — a shape the real broker never emits.
- Rust browserid-rp crate has no allowAgent equivalent (not affected).

Decision needed: rebuild the gate on `grantee !== email`, OR remove allowAgent + all README promises. Depends on whether the current model still has a meaningful human-vs-agent distinction.

## Decision 2026-08-20 — Direction A (remove allowAgent entirely)

Discussed with thunder. The subject axis was removed from the protocol on purpose:
nothing constrains minting, and as-you agents present with grantee == email by
design, so no gate can deliver "humans only". A grantee !== email delegation gate
(direction B) was considered and REJECTED: warrants are audience-bound, so a
delegated presentation at an RP already implies explicit per-RP user consent; a
default-closed gate would tax exactly the honest labeling (named agents) the
protocol wants to reward, pushing users toward unlabeled as-you provisioning.
"Require agent" postures likewise have no concrete use case — the owner is strictly
more authorized than any agent they minted, and every presentation is already
warrant-scoped (no bare-identity credential exists to refuse). Blast-radius
limiting is already fully served by warrants + scopes + revocation; grantee/holder
remain advisory provenance for audit/forensics.

Also found: examples/mcp-agent-auth/server.mjs requires subject === "agent" (never
emitted) — that example server rejects EVERY caller today.

- [x] sdk/js: remove subject + allowAgent; throw if allowAgent is passed (loud break — it was a security promise, silently ignoring would be a second M2)
- [x] Adapters (express/fastify/hono/nextauth): drop allowAgent config + subject passthrough; throw on presence
- [x] Tests: fix fake verifiers to the real broker shape (no subject); cover the throw
- [x] READMEs (js/express/fastify/hono/nextauth/rp-quickstart): replace humans-only promise with email/grantee attribution model + delegation-check recipe
- [x] examples/mcp-agent-auth: fix server.mjs subject check; update README

## Summary of Changes

Direction A implemented: `allowAgent` and the phantom `subject` field are gone from the JS SDK surface.

- sdk/js: verify() no longer reads/gates on `subject`; result documents email (attributed) vs grantee (actor of record). Passing `allowAgent` (any value) now THROWS with a pointer to the `grantee !== email` recipe. d.ts + JSDoc typedef updated (typedef also gained the previously missing `grantee`).
- Adapters express/fastify/hono/nextauth: `allowAgent` config throws at config time; `subject` dropped from the returned identity; d.ts updated.
- Tests: all fake verifiers now emit the real broker shape (no subject); new tests cover the delegated-presentation path and the allowAgent throw. 45 tests green across 6 suites.
- examples/mcp-agent-auth: server.mjs subject check (which rejected EVERY caller in production shape) replaced with pure scope enforcement; notes now show by <email> (via agent <grantee>); mock verifier + e2e test updated (the human case became login-only — rejected by scope, not by unverifiable agent-ness). README snippet fixed (it referenced a never-existing `r.agent`).
- scripts/e2e/browser-dialog-test.mjs + signer-device-test.mjs asserted subject == user against /verify-access JSON — also always-false; now assert grantee == email (as-you).
- READMEs (js/express/fastify/hono/nextauth/rp-quickstart/mcp-agent-auth) and marketing/developers.html: humans-only promises replaced with the attribution/actor model.
- Version bumps (breaking): @browserid-ng/verify 0.3.0; express/fastify/hono/nextauth 0.2.0 (verify dep range ^0.3.0). npm publish is a separate manual step.

Rust browserid-rp unaffected (never had the API). Broker untouched — no deploy needed; marketing/developers.html goes out with the next www deploy.
