---
# browserid-ng-ft55
title: 'BUG: /account revoke on a primary-issued device cert flips the WRONG status list (foreign idx into the broker''s own bitmap)'
status: completed
type: bug
priority: high
created_at: 2026-08-02T22:19:16Z
updated_at: 2026-08-02T23:36:38Z
---

Found 2026-08-03 while comparing warrant vs cert revocation.

primary.rs session join records primary certs with status_idx taken from the PRIMARY's status ref; routes/device.rs revoke_device_cert (and the Sign-out-everywhere loop in account.html, which calls it per cert) then does set_status_revoked_idx(idx) on the BROKER's own list. Two consequences:

1. The primary cert is NOT revoked anywhere a verifier looks (its ref names the primary's list) — the UI shows 'revoked' (revoked_at, cosmetic) while every RP keeps accepting the cert until expiry (90d). Silent false sense of security.
2. COLLATERAL: status indexes are per-issuer counters, so flipping the broker's bit at a foreign cert's index can revoke an unrelated BROKER-issued cert, potentially another user's (availability/logout impact, not takeover).

Fix (near-term, honest): in revoke_device_cert, only set_status_revoked_idx when the record's iss == state.domain; for foreign-issued certs keep the soft-delete and make /account render 'managed by <iss>' (link out) instead of a revoke that pretends. Test: revoking a recorded foreign-iss cert must NOT touch the broker status list; own-iss unchanged.

Real fix (later, spec-level): the cross-issuer revocation endpoint convention noted in docs/plans/2026-08-02-mcp-distribution-design.md (Theme-4 aside) — primaries expose a standard revoke endpoint the broker UI can invoke.

## Summary of Changes

Shipped across three commits, all deployed:
- browserid-core 4a0daed: support-document field `device-revoke` — an IdP advertises its browser-facing revocation page; absent = certs run to expiry.
- bridge ad1a961 (live-verified): GET /idp/revoke-device (first-party page, trusted-origin allowlist, auth-if-needed via the Bluesky OAuth flow, explicit confirmation — granularity is per handle, so one flip signs the handle out of every device and agent at D) + session-scoped POST /idp/revoke_device (401 unauth / 403 foreign handle / 400 not-our-issuance; test proves the bystander's bit survives).
- broker f23e9ac: the original bug fixed — revoke_device_cert flips the broker bit only for own-issued certs (regression test: colliding foreign idx never touches our list); /wsapi/issuer_revoke_url discovers the issuer's page (10-min cache); the /account sign-out flow opens it for foreign certs and reports honestly when an issuer offers no revocation (mingo.place, until mingo-cvj6 adds its status machinery).

The authority model held throughout: the registrar sends the user; only the user's first-party session at the issuer can flip that issuer's bits.

Tests: bridge 171+7, broker suite green incl. new regression, e2e 77/0 twice.
