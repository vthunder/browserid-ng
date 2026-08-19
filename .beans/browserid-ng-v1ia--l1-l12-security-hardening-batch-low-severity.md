---
# browserid-ng-v1ia
title: '[L1-L12] Security hardening batch (low severity)'
status: in-progress
type: task
priority: low
created_at: 2026-07-28T23:54:42Z
updated_at: 2026-08-17T09:24:06Z
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

## Re-verification 2026-08-17 — status of remaining low items

- L1 (STILL OPEN): no shared core email helper; styles still mixed — `split('@').nth(1)` (first-domain, accepts multi-@) at core/discovery.rs:284, verifier.rs:611/:625, oidc/mod.rs:510, routes/primary.rs:307, rp/lib.rs:233/:335/:356; `rsplit_once`/`rsplit` at core/identity.rs:36/:61, verifier.rs:476, analytics.rs:128, routes/email.rs:110/:314, registrar/lib.rs:62/:83, registrar/consent.rs:777/:1225, agent_provision.rs:1159/:1335; `split_once` at core/device.rs:77, oidc/mod.rs:87, routes/oidc.rs:143, hosted_idp.rs:72, handle_claim.rs:127, device.rs:210, fallback_idp.rs:354, agent_provision.rs:658, consent.rs:48. Only exactly-one-@ check is local to fallback_idp.rs:101-107 (not exported). NOTE: broker routes/consent.rs no longer exists — consent moved to browserid-registrar/src/consent.rs.
- L3 (STILL OPEN): fallback_idp.rs:118-129 issue_email_token signs {email,exp} with state.keypair (root key, state.rs:26-27), no typ field / no domain-sep prefix. Verify at :131-150 accepts any root-key sig over {email,exp}.
- L5 (STILL OPEN): core/device.rs:59-71 — `pattern=="*"` returns true unconditionally (:61); single-* branch (:64-68) is starts_with/ends_with with no @/domain boundary, so `admin*` matches admin@any-other-domain. Subaddress branch (:75-84, new) enforces domain equality but is unreachable for globs.
- L6 (CHANGED, partially done): sync path still static (rp/lib.rs:220-227, issuer_conformant :231-240) but now documented "Offline/testing only" (:209-219). Live discovery path added at :331-341 (browserid_dnssec::resolve_idp_key) used by :354-360. Can likely check off with a doc confirmation.
- L9 (STILL OPEN): routes/mod.rs:280-283 CorsLayer allow_origin(mirror_request()) applied as GLOBAL layer over whole router incl /wsapi/* + registrar routes. Mirroring deliberate for /fedcm/assertion credentialed responses (comment :274-279); no allow_credentials restriction or per-route allowlist. Fix: scope mirror to /fedcm only.
- L11 (STILL OPEN): Cargo.toml:43-45 still pins hickory 0.24; Cargo.lock:1976-1977 still has rustls 0.21.12 (alongside 0.23.35 at :1988). No 0.25 bump.
- Zeroize (STILL OPEN): ed25519-dalek features are ["rand_core","serde"] only (Cargo.toml:20, browserid-core/Cargo.toml:9); zero Zeroize occurrences in any .rs. secret_bytes() (keys.rs:137-139) returns &[u8;32], unzeroized copies at config.rs:115, tenant_keys.rs:47, browserid-agent/src/lib.rs:273/:594.
- Already-done (confirmed): L2, L4, L7, L8, L12.
