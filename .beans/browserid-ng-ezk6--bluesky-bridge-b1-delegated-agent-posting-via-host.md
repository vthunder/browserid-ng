---
# browserid-ng-ezk6
title: 'Bluesky bridge (B1): delegated agent posting via hosted PDS at bsky.browserid.me'
status: scrapped
type: feature
priority: normal
created_at: 2026-07-23T22:07:39Z
updated_at: 2026-07-24T12:01:28Z
---

Run a stock @atproto/pds plus a Rust pds-bridge sidecar (browserid-rp) at bsky.browserid.me: browserid-provisioned Bluesky accounts, agent warrants with atproto granular scopes (repo:app.bsky.feed.post?action=create, blob:image/*), RFC 7521 bundle->token exchange verified fail-closed, scoped XRPC proxy, receipts + revocation. Design: docs/plans/2026-07-24-bsky-pds-bridge-design.md

Decisions locked: separate service (not in broker); B1 shape (stock PDS + proxy); service origin bsky.browserid.me; granular scope syntax from the start.
Decided: handles under *.at.browserid.me (service origin stays bsky.browserid.me).

Related: pv9b (browserid.me-rooted handles), 4lxl (fail-closed status — bridge opts in regardless), 68av (jti replay), i9rr (not blocking — bridge verifies via core, so cross-issuer grantees work).

## Phases
- [x] P1a: pds-bridge crate (axum): provision + token exchange + scoped XRPC proxy + live fail-closed warrant re-check; scope grammar (repo:/rpc:/blob:) allowlist parser; sqlite store (bindings, hashed tokens, audit log); Dockerfiles (own app + workspace-manifest fix in broker Dockerfile); 12 tests incl. end-to-end vs mock PDS
- [ ] P1b: run against a real stock @atproto/pds locally; fix impedance (createAccount shape, session refresh, invite policy)
- [ ] P1c: wallet MCP demo posts via the bridge; receipts surfaced (dashboard or CLI)
- [ ] P1d: deploy per docs/plans/2026-07-24-bsky-bridge-deploy-plan.md — stage 1: bsky-bridge (CI image -> git:from-image) + bsky-pds apps, two hostnames (bsky.browserid.me = bridge/audience, pds.bsky.browserid.me = PDS direct; sidesteps websocket passthrough), smoke-test script; stage 2: relay requestCrawl + handle verification for *.at.browserid.me (wildcard-cert vs DNS-TXT-API decision)
- [ ] P2: provenance — linkage attestation (repo record + alsoKnownAs), me.browserid.provenance receipts and/or labeler
- [ ] P3: evaluate rsky-pds in-process integration (collapse the proxy)
- [ ] P4: upstream proposal to atproto community (bundle-native delegation)

## Reasons for Scrapping

Not abandoned — MOVED. The bridge (and all bsky work) now lives in its own public repo: https://github.com/vthunder/browserid-bsky (code, design doc, deploy plan, CI). Tracking continues as bean browserid-bsky-aa7g there. browserid-ng stays bsky-free; the bridge consumes browserid-core/browserid-rp as git dependencies.
