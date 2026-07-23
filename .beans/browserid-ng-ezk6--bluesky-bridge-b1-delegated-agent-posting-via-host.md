---
# browserid-ng-ezk6
title: 'Bluesky bridge (B1): delegated agent posting via hosted PDS at bsky.browserid.me'
status: todo
type: feature
created_at: 2026-07-23T22:07:39Z
updated_at: 2026-07-23T22:07:39Z
---

Run a stock @atproto/pds plus a Rust pds-bridge sidecar (browserid-rp) at bsky.browserid.me: browserid-provisioned Bluesky accounts, agent warrants with atproto granular scopes (repo:app.bsky.feed.post?action=create, blob:image/*), RFC 7521 bundle->token exchange verified fail-closed, scoped XRPC proxy, receipts + revocation. Design: docs/plans/2026-07-24-bsky-pds-bridge-design.md

Decisions locked: separate service (not in broker); B1 shape (stock PDS + proxy); service origin bsky.browserid.me; granular scope syntax from the start.
Open: handle zone label (*.bsky.browserid.me vs *.at.browserid.me — low stakes, handles are mutable atop the DID).

Related: pv9b (browserid.me-rooted handles), 4lxl (fail-closed status — bridge opts in regardless), 68av (jti replay), i9rr (not blocking — bridge verifies via core, so cross-issuer grantees work).

## Phases
- [ ] P1: pds-bridge crate (axum): provision + token exchange + scoped XRPC proxy; stock PDS deploy; wallet demo posts to Bluesky; receipts in dashboard
- [ ] P2: provenance — linkage attestation (repo record + alsoKnownAs), me.browserid.provenance receipts and/or labeler
- [ ] P3: evaluate rsky-pds in-process integration (collapse the proxy)
- [ ] P4: upstream proposal to atproto community (bundle-native delegation)
