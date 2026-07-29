---
# browserid-ng-v1ia
title: '[L1-L12] Security hardening batch (low severity)'
status: in-progress
type: task
priority: low
created_at: 2026-07-28T23:54:42Z
updated_at: 2026-07-29T00:33:20Z
parent: browserid-ng-wre6
---

Low-severity defense-in-depth / consistency / hygiene items from docs/security-audit-2026-07-29.md. Each is independently small; batch or split as convenient.

- [ ] L1: Canonical single-@ email parser; validate exactly-one-@ on identity fields; pick ONE domain-extraction helper (rsplit_once) everywhere (core/device.rs:67, verifier.rs:296, rp/lib.rs:221, consent.rs:851, agent_provision.rs:1329)
- [x] L2: jti single-use replay cache at /access/mint (SEEN_JTIS in device.rs)
- [ ] L3: Tag the fb_email token with a type/domain claim; consider a separate key from the cert-signing root (fallback_idp.rs:125)
- [x] L4: Rewrote stale cross-issuer doc; states caller conformance precondition (core/device.rs)
- [ ] L5: Domain-anchor the single-* glob in identity_matches; gate/drop bare '*' (core/device.rs:54)
- [ ] L6: Document/enforce that RP IdentityVerifier static primaries set must be complete, or use live discovery (rp/lib.rs:220)
- [x] L7: require_csrf added to complete_email_addition
- [x] L8: ct_eq constant-time admin-token compare (account.rs)
- [ ] L9: Tighten CORS on /wsapi/* — don't mirror any Origin for enumeration endpoints (mod.rs:219)
- [ ] L10: Scope/clarify the wallet's key-custody claim; docs note SDK seeds are plaintext-at-rest 0600 (sdk/wallet/server.mjs)
- [ ] L11: Track hickory 0.24→0.25 upgrade to drop EOL rustls 0.21 (Cargo.toml:45)
- [x] L12: broker-key.json + browserid.db* added to .dockerignore
- [ ] Also: enable ed25519-dalek 'zeroize' feature; zeroize secret_bytes String copies (info-level, keys.rs:138 / Cargo.toml)
