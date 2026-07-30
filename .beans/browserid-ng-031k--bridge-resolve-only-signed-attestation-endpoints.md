---
# browserid-ng-031k
title: 'Bridge: resolve-only + signed attestation endpoints'
status: completed
type: feature
priority: normal
created_at: 2026-07-30T20:35:08Z
updated_at: 2026-07-30T22:42:09Z
parent: browserid-ng-tsqk
---

The bridge stays the atproto specialist; the broker is the issuer. Avoids duplicating oauth.rs/resolve.rs/net.rs/pins.rs into the broker.

- [x] Resolve-only endpoint (is this domain a valid handle binding?), cached — GET /idp/resolve?domain= (bridge commit 13f0ef1, deployed via CI). Binary answer: outage reads as not-a-handle so the broker falls through to MX; 404 when no IdP is configured.
- [x] Attestation endpoint: POST /idp/attest (bridge 755e134) — session + fresh re-resolve + pin check, signs browserid_core::HandleAttestation with the D IdP key, aud = broker host. Plus GET /idp/claim, the dialog-facing interstitial (no keys, no form), and a server-side allowlisted return_page on OAuth flows so the callback lands back on the claim page.
- [x] Trust boundary documented in code: attestation.rs module docs (core), /idp/resolve + /idp/attest doc comments, and the broker's handle_attestor config comment — the broker decides which attestor it accepts by configuration, keys rooted in DNSSEC
- [x] D-shaped primary IdP untouched — all existing idp tests green (169 lib + 7 integration); device-authorize flows unchanged, return_page defaults to device-authorize everywhere

## Summary of Changes

Bridge commits 13f0ef1 (resolve) + 755e134 (attest/claim page), both deployed via CI. Verified live: /idp/resolve answers bsky.app with its DID and gmail.com with valid:false.
