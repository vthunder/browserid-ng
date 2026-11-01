---
# browserid-ng-4sjc
title: 'Audit WS3: fuzz + property tests (cargo-fuzz, proptest)'
status: todo
type: task
priority: normal
created_at: 2026-11-01T12:40:56Z
updated_at: 2026-11-01T15:43:06Z
parent: browserid-ng-ag1l
blocked_by:
    - browserid-ng-7k3p
---

No fuzz/proptest exists today. Targets: JWS/cert parsing in browserid-core, scope grammar parser, DNS TXT parsing (July M5 class), status-list decoding, request-kind JSON. proptest invariants: sign->verify round trip, canonicalize idempotent, delegation chain never widens root scope. Harnesses live in repo; run via ssh localtest.

## From WS1
Properties from I12-I14 plus S6/D16 (iat unbounded: exp-iat negative passes max-ttl; cap.window rolls from a future iat). D1 (identity_matches subaddress widening in core device.rs:96-111) is a one-line proptest: auth-cert identity_matches must be exact.
