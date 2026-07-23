---
# browserid-ng-68av
title: 'Mint API: access-request jti replay cache unimplemented (B3)'
status: todo
type: bug
created_at: 2026-07-23T21:40:54Z
updated_at: 2026-07-23T21:40:54Z
---

Spec (protocol.md:186, api.md:214-216) says jti is a single-use nonce for replay protection at the mint. The claim exists (device.rs:298) but access_mint never checks it — routes/device.rs:278 'TODO (B2): single-use jti replay cache'. Within the 10-min access-request window a captured request can be replayed to mint additional access certs. Implement a seen-jti cache (bounded by request exp) or note the gap in spec.

From docs/plans/2026-07-23-spec-code-divergence-audit.md (B3).
