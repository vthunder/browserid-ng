---
# browserid-ng-ft55
title: 'BUG: /account revoke on a primary-issued device cert flips the WRONG status list (foreign idx into the broker''s own bitmap)'
status: todo
type: bug
priority: high
created_at: 2026-08-02T22:19:16Z
updated_at: 2026-08-02T22:19:16Z
---

Found 2026-08-03 while comparing warrant vs cert revocation.

primary.rs session join records primary certs with status_idx taken from the PRIMARY's status ref; routes/device.rs revoke_device_cert (and the Sign-out-everywhere loop in account.html, which calls it per cert) then does set_status_revoked_idx(idx) on the BROKER's own list. Two consequences:

1. The primary cert is NOT revoked anywhere a verifier looks (its ref names the primary's list) — the UI shows 'revoked' (revoked_at, cosmetic) while every RP keeps accepting the cert until expiry (90d). Silent false sense of security.
2. COLLATERAL: status indexes are per-issuer counters, so flipping the broker's bit at a foreign cert's index can revoke an unrelated BROKER-issued cert, potentially another user's (availability/logout impact, not takeover).

Fix (near-term, honest): in revoke_device_cert, only set_status_revoked_idx when the record's iss == state.domain; for foreign-issued certs keep the soft-delete and make /account render 'managed by <iss>' (link out) instead of a revoke that pretends. Test: revoking a recorded foreign-iss cert must NOT touch the broker status list; own-iss unchanged.

Real fix (later, spec-level): the cross-issuer revocation endpoint convention noted in docs/plans/2026-08-02-mcp-distribution-design.md (Theme-4 aside) — primaries expose a standard revoke endpoint the broker UI can invoke.
