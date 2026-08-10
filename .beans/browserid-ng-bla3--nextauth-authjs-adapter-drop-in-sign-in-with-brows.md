---
# browserid-ng-bla3
title: 'NextAuth (Auth.js) adapter: drop-in Sign in with BrowserID'
status: draft
type: feature
priority: high
created_at: 2026-08-10T04:30:45Z
updated_at: 2026-08-10T04:30:45Z
---

@browserid-ng/nextauth — a Credentials provider + a tiny client helper that makes 'Sign in with BrowserID' a dependency install for the largest JS auth ecosystem (roadmap Theme 5, RP-side distribution).

Build spec: docs/plans/2026-08-10-nextauth-adapter-build-spec.md.

Shape: a NextAuth CredentialsProvider whose authorize({presentation}) verifies at the hosted /verify-access (via @browserid-ng/verify, sdk/js) — no crypto in JS — returning the identity or null (fail-closed); plus signInWithBrowserID() client helper that loads include.js, drives navigator.id.request(), and hands the presentation to Auth.js signIn(). Audience pinned server-side (the one security-critical config). Humans-only by default (allowAgent:false). Optional refreshBrowserIDSession() re-checks statusRefs via /status/check for long sessions. Working examples/nextauth-app.

Reuse: @browserid-ng/verify (already POSTs /verify-access, fail-closed + checkStatus), include.js, examples/rp-quickstart.

Decisions pending (in the spec): Credentials primary (recommended) vs invest in a generic hosted authorization-code AS for stock OAuth providers; Auth.js v5 primary + v4 compat (recommended); package name @browserid-ng/nextauth.
