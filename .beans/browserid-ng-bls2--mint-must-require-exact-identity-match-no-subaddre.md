---
# browserid-ng-bls2
title: Mint must require exact identity match (no subaddressing on the auth path)
status: todo
type: bug
priority: normal
created_at: 2026-08-08T10:41:03Z
updated_at: 2026-08-08T10:41:03Z
parent: browserid-ng-8g49
---

identity_matches (browserid-core/src/device.rs) applies RFC 5233 subaddressing, and authorizes_identity is used on BOTH the authorization path (config cert → grantor, device.rs:655, correct) AND the authentication/mint path (device_cert.authorizes_identity(access_request.identity), browserid-broker/src/routes/device.rs:309). Per spec §4.6 (2026-08-08), subaddressing is authorization-only: an auth cert for foo@domain must mint access certs for foo@domain EXACTLY and must NOT be able to act as foo+tag@domain — acting as a subaddress requires an auth cert issued for that sub-identity. Fix: the mint path must use exact-membership matching, not identity_matches. Keep subaddressing on the config/grantor path. Add tests for both directions.
