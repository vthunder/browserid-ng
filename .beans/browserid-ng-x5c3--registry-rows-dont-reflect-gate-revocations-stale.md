---
# browserid-ng-x5c3
title: Registry rows don't reflect gate-revocations; stale-class config certs die lazily
status: completed
type: task
priority: normal
created_at: 2026-08-19T21:31:24Z
updated_at: 2026-08-20T07:11:51Z
---

Residuals from the kts0 swap-at-next-use verification (2026-08-19, prod DB forensics — the mechanism itself works end to end).

1. **/account device list lies about gate-revoked certs.** The /access/mint freshness gate flips the presented cert's STATUS BIT (authoritative — the cert is dead) but doesn't stamp the registry row's revoked_at, so /account shows it as active (prod: device_certs row 105 bit-REVOKED, row says active).

2. **Sibling and other-browser stale-class certs die lazily, config certs maybe never.** The gate only sees AUTHENTICATION certs at their next mint (fine per swap-at-next-use for other browsers' auth certs — prod rows 90/91 will die on first use). But the PAIRED old config cert (row 106) has no broker-side use-point: it can still sign warrants for the now-E2 address (verify-access checks its bit, which never flips). Orphaned in practice (the browser deleted the local pair), but technically live mailbox-era signing authority for an E2 address until expiry.

**Clean fix for both**: record the issuance class in the registry — DeviceCertRecord.prov (migration v31, TEXT NOT NULL DEFAULT 'smtp' — the historically true value; add a SqliteStore test per the memory-store rule). Then the freshness gate calls a precise revoke_user_stale_class_certs(user, email, current_class): every registry cert for the (user, email) whose prov != the record's current class gets its bit flipped AND row stamped — auth + config, all browsers, exact (no TTL heuristics, never touches correctly-classed certs). The revoke-on-upgrade in attach_verified/complete_handle_claim can switch to the same helper.

## Summary of Changes (2026-08-20)

- DeviceCertRecord gains `prov` (migration v32: TEXT NOT NULL DEFAULT 'smtp' — historically true for every legacy row); recorded at issuance from the mint decision (/device/issue via owned_mintable_email's class, /auth/device_cert from the record; primary/registrar-recorded rows read 'smtp' — the class machinery gates broker-signed secondary certs only).
- New store method `revoke_user_stale_class_certs(user, email, current_class)`: flips bits + stamps rows for every active cert of the pair whose recorded class differs — auth AND config, all browsers; current-class rows untouched. Sqlite + memory + Arc.
- Wired: the /access/mint freshness gate now class-revokes the WHOLE stale set on one presentation (belt-and-braces bit-flip kept for pre-registry cookie-era certs); the attach_verified / complete_handle_claim upgrade arms switched to the class-scoped revoker (transfers keep the all-certs revoker — change of holder kills every class).
- Tests: one stale presentation stamps all four sibling rows (2 browsers × auth+config); sqlite precision test (current-class + other-address rows survive); v30-migration fixture extended for the v32 ALTER. Workspace 59 suites green; e2e 105/105.
