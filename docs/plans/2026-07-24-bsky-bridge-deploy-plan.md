# bsky bridge — deployment plan (ezk6 P1b–P1d)

**Date:** 2026-07-24
**Goal:** a deployed, testable bsky.browserid.me. Two testability stages:

- **Stage 1 — private loop (the P1 demo):** provision an account with a
  browserid login, agent gets a warrant + bridge token, posts land in the
  PDS repo. Verified with direct XRPC reads. No federation, no handle
  verification, no relay. Everything under our control.
- **Stage 2 — on the real network:** the relay crawls the PDS, posts appear
  on bsky.app, handles resolve. Adds federation + handle plumbing.

## Topology decision (recommended: two hostnames)

The design doc's single-origin shape (bridge fronts everything) requires
websocket passthrough for the relay firehose, which the bridge doesn't have
yet. For deployment, split the surfaces instead:

- **`bsky.browserid.me`** → the **bridge** (dokku app `bsky-bridge`):
  `/browserid/*`, RFC 8414 metadata, and the scoped `/xrpc/*` proxy for
  agent tokens. This is the **warrant audience** — stable across stages.
- **`pds.bsky.browserid.me`** → the **PDS** directly (dokku app `bsky-pds`
  or a plain docker container): `PDS_HOSTNAME=pds.bsky.browserid.me`, so
  DID docs, human clients, and the relay firehose all talk straight to it.
  No websocket work needed; the bridge reaches it over the internal network.

Trade-off: two public hostnames instead of one; the DID service endpoint
names the PDS host, not the bridge. Acceptable — the bridge is the *grant*
surface, not the data plane. (Single-origin can be revisited at P3.)

## Stage 1 — steps

1. **Build via CI, not on the host** (per the mingo `sbo-daemon` lesson:
   dokku host builds cold-recompile Rust for 40+ min). Reuse the
   `deploy-daemon.yml` pattern: GitHub Actions builds
   `pds-bridge/Dockerfile` → pushes `ghcr.io/vthunder/bsky-bridge:<sha>`
   (public package) → `ssh dokku@HOST git:from-image bsky-bridge <image>`.
   One-time: `DOKKU_SSH_KEY` secret, `packages: write` permission,
   `dokku builder:set bsky-bridge selected dockerfile` not needed
   (from-image), GHCR package public.
2. **PDS app**: run the stock container
   (`ghcr.io/bluesky-social/pds:latest`) as dokku app `bsky-pds` with a
   persistent volume for `/pds`. Required env: `PDS_HOSTNAME`,
   `PDS_JWT_SECRET`, `PDS_ADMIN_PASSWORD`,
   `PDS_PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX`,
   `PDS_DID_PLC_URL=https://plc.directory`, `PDS_DATA_DIRECTORY=/pds`,
   `PDS_BLOBSTORE_DISK_LOCATION=/pds/blocks`,
   `PDS_SERVICE_HANDLE_DOMAINS=.at.browserid.me`. Invite codes stay
   admin-only (the bridge mints them per provisioning).
3. **Bridge app env**: `BRIDGE_ORIGIN=https://bsky.browserid.me`,
   `PDS_URL=http://<bsky-pds internal>`, `PDS_ADMIN_PASSWORD` (same as PDS),
   `BROKER_URL=https://browserid.me`, `HANDLE_DOMAIN=at.browserid.me`,
   `BRIDGE_DB=/data/pds-bridge.db` + persistent `/data` volume.
4. **DNS + TLS**: `bsky.browserid.me` and `pds.bsky.browserid.me` A records
   → the dokku host; `dokku letsencrypt` for both.
5. **Smoke test (scriptable, no browser needed for the agent side):**
   1. Human: sign in at browserid.me once so the config cert exists; run the
      provisioning call with a bundle for audience
      `https://bsky.browserid.me` (small helper script, or a minimal
      `/browserid/provision` page later).
   2. Agent: `browserid-agent` CLI / `@browserid-ng/wallet` requests a
      warrant for audience `https://bsky.browserid.me`, scopes
      `repo:app.bsky.feed.post?action=create` — approve the consent card at
      browserid.me.
   3. Exchange at `POST /browserid/token`, post via
      `POST /xrpc/com.atproto.repo.createRecord`.
   4. Verify: `GET /xrpc/com.atproto.repo.listRecords?repo=<did>&collection=app.bsky.feed.post`
      against `pds.bsky.browserid.me` (public read).
   5. Revoke the warrant in the browserid.me account UI → the next agent
      post must 401 within the status-cache window.

**Stage-1 blockers to fix first (found while writing this plan):**
- [ ] The bridge's warrant re-check refreshes status lists via
  `Verifier::refresh_status`, which only trusts list issuers in its
  issuer-key table — the broker is there via `BROKER_URL`, so warrant lists
  (browserid.me registry) work; access/config-cert lists from *primary*
  IdPs won't refresh (their keys aren't in the table). Fine for stage 1
  (broker-issued identities only); note for P2 (DNSSEC-rooted resolver).
- [ ] `Verifier::refresh_status` and the status re-check assume the broker
  actually serves `/.well-known/browserid-status` with warrant indices —
  it does (egr7), but the deployed broker must be current.

## Stage 2 — federation & handles (separate pass)

1. **Relay crawl**: `POST /xrpc/com.atproto.sync.requestCrawl` to
   `bsky.network` naming `pds.bsky.browserid.me`. Posts then flow to the
   AppView and show on bsky.app profiles.
2. **Handle verification** for `*.at.browserid.me` — the fiddly bit.
   Options, pick one:
   - **(a) Wildcard vhost + wildcard cert**: point `*.at.browserid.me` at
     the PDS (it answers `/.well-known/atproto-did` per Host for its
     service handle domains). Needs a wildcard TLS cert → DNS-01 challenge
     → depends on the DNS provider's API (dokku letsencrypt won't do it;
     acme.sh with provider hook will).
   - **(b) DNS TXT automation**: bridge writes
     `_atproto.<label>.at.browserid.me TXT "did=<did>"` at provisioning via
     the DNS provider API. No wildcard cert needed; requires API access to
     the browserid.me zone.
   - Until one lands, accounts work but bsky.app shows `handle.invalid` —
     harmless for stage-1 testing.
3. **Email**: the PDS wants SMTP for its own account emails
   (`PDS_EMAIL_SMTP_URL`) — optional for testing, needed before real users.

## Open items / decisions for Dan

- Confirm two-hostname topology (vs building websocket passthrough now).
- Confirm CI-image deploys (repo/package public on GHCR?).
- DNS provider for browserid.me — decides handle option (a) vs (b).
- Same dokku host as browserid.me, or elsewhere? (PDS blob storage grows;
  the host is disk-constrained per the mingo lesson.)
