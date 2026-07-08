---
# browserid-ng-5lau
title: Full protocol + implementation review of browserid-ng
status: completed
type: task
priority: normal
created_at: 2026-07-08T05:47:43Z
updated_at: 2026-07-08T05:52:30Z
---

Comprehensive review requested: protocol-level issues introduced vs original BrowserID, implementation gaps weakening guarantees, spec/impl mismatches, RP/IdP ergonomics, general comments.

- [x] Read browserid-core (assertion, certificate, keys, discovery, dns, verifier)
- [x] Review broker backend (routes, session, cert issuance, verifier endpoint)
- [x] Review JS client stack (include.js, dialog, agent, postMessage surfaces)
- [x] Review SBO typed-signing extension vs design doc
- [x] Review docs/plans vs implementation
- [x] Synthesize findings report

## Summary of Changes

Read-only review (no code changes). Findings delivered to user in chat. Key issues: unauthenticated DNSSEC AD-flag trust (dns_fetcher), two divergent verifier paths with the weaker one wired to /verify, decorative CSRF token, cookie missing Secure/SameSite, no session expiry, core-vs-broker cert-chain handling mismatch, SBO custody hardening (non-extractable key) never implemented, per-origin-not-per-email SBO grant, no SBO grant revocation, unvalidated provisioning_api.js shim. See chat for full report + recommended follow-up beans.
