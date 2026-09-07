---
# browserid-ng-7wj3
title: Primary-issued device certs need status refs (revocation immediacy gap)
status: todo
type: task
priority: normal
created_at: 2026-07-22T15:14:46Z
updated_at: 2026-09-07T18:24:33Z
parent: browserid-ng-oup3
---

Surfaced by the revoke-up-front holder-move design (2026-07-22): mingo-idp (and sandmill) issue device/config certs with status: None, so the broker's up-front revocation (move_holder, forget_holder, revoke_device_cert) only bites broker-issued certs — a primary-rooted device's certs cannot be killed remotely; immediacy is bounded by cert expiry or the device's own re-issue.

Design needed: primaries should embed StatusRef in issued certs and publish a status list (mingo-idp has no status machinery today), plus a revocation surface. Wrinkle: the broker can't tell the primary to revoke (no server-to-server channel by design) — options: (a) primary-side revocation UI/API driven by the user's first-party session; (b) primaries delegate status to a list the user's browser can flip via the broker hop; (c) accept the gap and lean on short cert TTLs for primaries. Needs Dan's ruling.

2026-09-07, from registry-api-v1 round-3 UX review (A11): revoking a FOREIGN-issued cert at the registry only retires it there and answers revoked:false; site logins keep working until the issuer sets its bit, and wallets will say 'device removed'. Spec now says the wallet MUST route to the issuer before reporting success; this bean covers the issuer side (status refs / immediacy).
