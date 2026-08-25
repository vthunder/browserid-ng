---
# browserid-ng-v1ia
title: '[L1-L12] Security hardening batch (low severity)'
status: completed
type: task
priority: low
created_at: 2026-07-28T23:54:42Z
updated_at: 2026-08-25T15:14:16Z
parent: browserid-ng-wre6
---

Low-severity defense-in-depth / consistency / hygiene items from docs/security-audit-2026-07-29.md. Each is independently small; batch or split as convenient.

- [x] L1 (2026-08-25): canonical `identity::email_parts`/`email_domain` (exactly-one-@, non-empty both sides) in browserid-core; all ~25 hand-split sites migrated across core/broker/registrar/rp; identity_eq/grantee_covers/warrant grantor+grantee now reject malformed (multi-@) emails fail-closed
- [x] L2: jti single-use replay cache at /access/mint (SEEN_JTIS in device.rs)
- [x] L3 (2026-08-25): fb_email claims carry `typ: browserid-fb-email-v1`, required at verify — the one raw root-key signature now has typ discipline like every JWS; separate key judged unnecessary once tagged (outstanding cookies invalidated; holders redo the mailbox proof)
- [x] L4: Rewrote stale cross-issuer doc; states caller conformance precondition (core/device.rs)
- [x] L5 (2026-08-25): glob confined to the LOCAL part with exact-match domain; bare '*', @-less globs (admin*), and domain-side stars match NOTHING (no issuer mints them — verified before dropping)
- [x] L6 (2026-08-25): confirmed done earlier — verify_dnssec resolves primaries live per-domain (rp/lib.rs:331-341); the static path is documented 'Offline/testing only'. Checked off
- [x] L7: require_csrf added to complete_email_addition
- [x] L8: ct_eq constant-time admin-token compare (account.rs)
- [x] L9 (2026-08-25): global mirror layer REMOVED. CORS is per-surface: /fedcm/* keeps the mirror (credentialed FedCM reads + include.js logout ping); Any on the public reads (/.well-known/browserid, /status/proxy, /guestbook/feed for the marketing wall, /common/js wasm module imports, and the registrar's /.well-known/browserid-status which the status-poll redirect lands on). /wsapi/* and everything else emit NO CORS headers. Full e2e suite green
- [x] L10 (2026-08-25): README + server.mjs header state plainly: plaintext JSON at rest, 0700/0600, no passphrase/keychain — the machine account is the custody boundary; revoke from /account on compromise
- [x] L11 (2026-08-25): hickory-client 0.25 (tls-ring) + rustls 0.23 + webpki-roots 0.26; EOL rustls 0.21 out of the lockfile; unused hickory deps dropped from the broker. Port validated with a new #[ignore] live DoT test (sandmill.org resolves Secure) — rerun it after future dep bumps
- [x] L12: broker-key.json + browserid.db* added to .dockerignore
- [x] zeroize (2026-08-25): ed25519-dalek 'zeroize' feature on (SigningKey wiped on drop); transient seed copies in the broker key save/load path zeroized. The agent SDK's secret_bytes exports are by-design API surface (documented under L10), not wiped

## Re-verification 2026-08-17 — status of remaining low items

- L1 (STILL OPEN): no shared core email helper; styles still mixed — `split('@').nth(1)` (first-domain, accepts multi-@) at core/discovery.rs:284, verifier.rs:611/:625, oidc/mod.rs:510, routes/primary.rs:307, rp/lib.rs:233/:335/:356; `rsplit_once`/`rsplit` at core/identity.rs:36/:61, verifier.rs:476, analytics.rs:128, routes/email.rs:110/:314, registrar/lib.rs:62/:83, registrar/consent.rs:777/:1225, agent_provision.rs:1159/:1335; `split_once` at core/device.rs:77, oidc/mod.rs:87, routes/oidc.rs:143, hosted_idp.rs:72, handle_claim.rs:127, device.rs:210, fallback_idp.rs:354, agent_provision.rs:658, consent.rs:48. Only exactly-one-@ check is local to fallback_idp.rs:101-107 (not exported). NOTE: broker routes/consent.rs no longer exists — consent moved to browserid-registrar/src/consent.rs.
- L3 (STILL OPEN): fallback_idp.rs:118-129 issue_email_token signs {email,exp} with state.keypair (root key, state.rs:26-27), no typ field / no domain-sep prefix. Verify at :131-150 accepts any root-key sig over {email,exp}.
- L5 (STILL OPEN): core/device.rs:59-71 — `pattern=="*"` returns true unconditionally (:61); single-* branch (:64-68) is starts_with/ends_with with no @/domain boundary, so `admin*` matches admin@any-other-domain. Subaddress branch (:75-84, new) enforces domain equality but is unreachable for globs.
- L6 (CHANGED, partially done): sync path still static (rp/lib.rs:220-227, issuer_conformant :231-240) but now documented "Offline/testing only" (:209-219). Live discovery path added at :331-341 (browserid_dnssec::resolve_idp_key) used by :354-360. Can likely check off with a doc confirmation.
- L9 (STILL OPEN): routes/mod.rs:280-283 CorsLayer allow_origin(mirror_request()) applied as GLOBAL layer over whole router incl /wsapi/* + registrar routes. Mirroring deliberate for /fedcm/assertion credentialed responses (comment :274-279); no allow_credentials restriction or per-route allowlist. Fix: scope mirror to /fedcm only.
- L11 (STILL OPEN): Cargo.toml:43-45 still pins hickory 0.24; Cargo.lock:1976-1977 still has rustls 0.21.12 (alongside 0.23.35 at :1988). No 0.25 bump.
- Zeroize (STILL OPEN): ed25519-dalek features are ["rand_core","serde"] only (Cargo.toml:20, browserid-core/Cargo.toml:9); zero Zeroize occurrences in any .rs. secret_bytes() (keys.rs:137-139) returns &[u8;32], unzeroized copies at config.rs:115, tenant_keys.rs:47, browserid-agent/src/lib.rs:273/:594.
- Already-done (confirmed): L2, L4, L7, L8, L12.

## Summary of Changes (2026-08-25)

All remaining low items landed in one pass (no product decisions needed). Highlights: per-surface CORS (found two consumers the global mirror was silently serving: the marketing wall's /guestbook/feed and the status-poll redirect onto the registrar list — both now explicitly public); canonical strict email parsing with fail-closed malformed handling through the verification paths; hickory 0.25/rustls 0.23 with a live DoT regression test. Full workspace suite (59 targets) + full Playwright e2e (106) green.
