---
# browserid-ng-ygfi
title: 'README rewrite: agents-first developer front door'
status: completed
type: task
priority: high
created_at: 2026-07-11T23:39:56Z
updated_at: 2026-07-11T23:46:06Z
---

README.md opens 'A modern Rust implementation of the BrowserID protocol, derived from Persona' — human-login-first, protocol-name-first. Contradicts the agents-first landing page. Recast: lead with the capability (delegated, scoped, revocable agent identity answerable to humans), demote human sign-in to a supporting feature. Link the verify-quickstart + integration example.

## Summary of Changes

Rewrote README.md agents-first: leads with delegated/scoped/revocable agent identity answerable to humans, human sign-in demoted to a supporting feature. Added the one-call /verify example (@browserid/verify + quickstart link), the DNS trust-root ASCII picture, the full current crate layout (registrar/agent/rp/sdk-js were all missing), and refreshed stale facts (clone URL, test count, warrant segment in the assertion format, fallback IdPs).
