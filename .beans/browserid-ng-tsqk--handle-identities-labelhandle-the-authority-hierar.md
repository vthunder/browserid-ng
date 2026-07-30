---
# browserid-ng-tsqk
title: 'Handle identities: <label>@<handle> + the authority hierarchy'
status: in-progress
type: epic
priority: normal
created_at: 2026-07-30T20:34:46Z
updated_at: 2026-07-30T22:55:03Z
---

Replace the bridge-owned identity shape `<handle>@bsky.browserid.me` with
`<label>@<handle>` (default `me@<handle>`), so an atproto handle identity sits
in the DOMAIN position and inherits BrowserID's per-domain fallback→primary
hinge with no spec extension.

Design: docs/plans/2026-07-30-handle-identities-and-the-authority-hierarchy.md

Claim-time authority hierarchy (NOT a verification rule):
1. DNSSEC-validated `_browserid` record → domain is a primary, we don't issue
2. Valid atproto handle binding (either resolution method + bidirectional check)
   → prove via atproto OAuth
3. MX record → prove via SMTP loop
4. Otherwise refuse

No pinning: re-derived on every issuance.

Key property: RP verification is UNCHANGED. browserid.me is the issuer, so every
RP that already trusts it for email accepts handle identities with no new
config, and no verifier touches DoH/plc.directory/PDS metadata.

Architecture: the bsky bridge stays the atproto specialist and returns a signed
attestation; the broker is the issuer.

## Start here

Fresh-context handoff: `docs/plans/2026-07-30-HANDOFF-handle-identities.md`
Design (authoritative): `docs/plans/2026-07-30-handle-identities-and-the-authority-hierarchy.md`

Roots: browserid-ng-5kf3 (broker hierarchy) and browserid-ng-031k (bridge endpoints, in ~/src/browserid-bsky). browserid-ng-jaa1 is an open DECISION, not a work item.

## Status 2026-07-31

Core build COMPLETE and deployed: 5kf3 (hierarchy + gates), 031k (bridge resolve/attest/claim page), 77mw (attestation acceptance + proof recording), xcy6 (dialog + /account claim flow) all completed. Live-verified in prod: address_info routes me@bsky.app to the atproto lane with the bridge claim URL; gmail.com to smtp. Remaining children: jaa1 (revocation-on-flip DECISION, draft — do not silently implement) and rau4 (atproto-lane e2e + first live claim).
