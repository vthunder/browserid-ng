---
# browserid-ng-hg2j
title: transfer_email leaves the previous holder's device certs live
status: todo
type: bug
priority: normal
created_at: 2026-08-19T17:26:21Z
updated_at: 2026-08-19T17:26:31Z
blocking:
    - browserid-ng-ezlo
---

Found while designing the ownership-change flow (browserid-ng-ezlo, blocks its (d) step).

store transfer_email (sqlite.rs:1147, memory equivalent) is a bare UPDATE on the emails row. Nothing revokes the previous account's device/config certs naming the transferred address, so after ANY transfer (handle to new DID, oidc cold reclaim on a passwordless account, session-attached claim of an address owned elsewhere — handle_claim.rs:155/182, oidc.rs:350/390, primary.rs:119), the old holder's cached certs keep minting access certs at /access/mint and signing into RPs as the departed address until expiry (90d broker-vouched; 7d E2). /access/mint checks cert signature + status bit, not current ownership — by design (the cert IS the credential), which makes revocation-at-transfer the required mechanism.

Fix sketch: at every transfer_email call site (or inside a routes-level transfer helper), look up the OLD account's DeviceCertRecords whose identities include the address, flip their status bits (is_status_revoked_idx machinery exists), and mark rows revoked. Add tests: after a cold handle reclaim by a new DID, the old browser's device cert no longer mints (403 at /access/mint via the status gate). Cover SqliteStore too.

Note the same question applies to update_password/reset ('device certs intentionally left in place' there — but that is same-owner recovery; transfer is a change of OWNER, where leaving certs live is impersonation).
