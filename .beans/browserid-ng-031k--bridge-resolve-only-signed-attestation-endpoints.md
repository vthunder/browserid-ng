---
# browserid-ng-031k
title: 'Bridge: resolve-only + signed attestation endpoints'
status: in-progress
type: feature
priority: normal
created_at: 2026-07-30T20:35:08Z
updated_at: 2026-07-30T22:05:26Z
parent: browserid-ng-tsqk
---

The bridge stays the atproto specialist; the broker is the issuer. Avoids duplicating oauth.rs/resolve.rs/net.rs/pins.rs into the broker.

- [x] Resolve-only endpoint (is this domain a valid handle binding?), cached — GET /idp/resolve?domain= (bridge commit 13f0ef1, deployed via CI). Binary answer: outage reads as not-a-handle so the broker falls through to MX; 404 when no IdP is configured.
- [ ] Attestation endpoint: after the OAuth hop, sign 'DID X holds handle H at time T' with the bsky.browserid.me IdP key
- [ ] Document the trust boundary: the bridge is a trusted internal component of the fallback, not a third party
- [ ] Keep the existing D-shaped primary IdP working for already-issued identities
