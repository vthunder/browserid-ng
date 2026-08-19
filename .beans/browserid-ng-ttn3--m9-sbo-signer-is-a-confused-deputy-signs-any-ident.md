---
# browserid-ng-ttn3
title: '[M9] SBO signer is a confused deputy (signs any identity/audience, unlimited)'
status: todo
type: bug
priority: normal
created_at: 2026-07-28T23:54:23Z
updated_at: 2026-08-17T09:23:48Z
parent: browserid-ng-wre6
---

docs/security-audit-2026-07-29.md (M9). sbo-signer.js:186 gates only on a per-origin boolean; d.email/d.audience opener-supplied + unchecked; popup holds device certs for ALL identities. Granted origin signs as any identity/audience, unlimited.
- [ ] Scope grant to a specific identity + audience
- [ ] Require per-request/per-identity consent

## Re-verification 2026-08-17 — STILL VALID, unchanged in substance

browserid-broker/static/common/js/sbo-signer.js:
- grantedFor(origin) (:47-52): still a bare per-origin boolean from localStorage.siteInfo[origin].sbo_sign_granted. No identity/audience/count in the grant.
- Gate at :186 is exactly `if (!grantedFor(rpOrigin))`. Only addition since audit is a PRESENCE check at :191 (`if (!d.audience)`) — validates non-emptiness, not authorization.
- :198-202 devicePairFor(d.email) → mintPresentation(d.email, d.audience, …): opener-supplied email+audience flow straight into minting a fresh access cert for ANY identity with device certs in that browser.
- :145-151 warrant built client-side with grantor/grantee/audience all from opener input.
- No per-request consent: header comment :14-15 "No user interaction: consent granted once at login"; :118 only logs a counter.
- Grant-writing side unchanged: dialog.js:1977 (read) / :1987 (set sbo_sign_granted=true), origin-keyed boolean only.
- Only pre-existing hardening: e.source !== opener check at :180 (predates audit). No consent-card/warrant work has landed in this file since.

Decision/coordination: scope grant to specific identity+audience + per-request consent. Coordinate with consent-card work in bean browserid-ng-rjmm before implementing.
