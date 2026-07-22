---
# browserid-ng-7wj3
title: Primary-issued device certs need status refs (revocation immediacy gap)
status: todo
type: task
created_at: 2026-07-22T15:14:46Z
updated_at: 2026-07-22T15:14:46Z
parent: browserid-ng-oup3
---

Surfaced by the revoke-up-front holder-move design (2026-07-22): mingo-idp (and sandmill) issue device/config certs with status: None, so the broker's up-front revocation (move_holder, forget_holder, revoke_device_cert) only bites broker-issued certs — a primary-rooted device's certs cannot be killed remotely; immediacy is bounded by cert expiry or the device's own re-issue.

Design needed: primaries should embed StatusRef in issued certs and publish a status list (mingo-idp has no status machinery today), plus a revocation surface. Wrinkle: the broker can't tell the primary to revoke (no server-to-server channel by design) — options: (a) primary-side revocation UI/API driven by the user's first-party session; (b) primaries delegate status to a list the user's browser can flip via the broker hop; (c) accept the gap and lean on short cert TTLs for primaries. Needs Dan's ruling.
