---
# browserid-ng-rau4
title: e2e coverage for the atproto claim lane + first live handle claim
status: todo
type: task
created_at: 2026-07-30T22:54:26Z
updated_at: 2026-07-30T22:54:26Z
parent: browserid-ng-tsqk
---

Follow-up to browserid-ng-xcy6 (epic browserid-ng-tsqk). Two gaps deliberately left: (1) e2e specs for the atproto lane — needs a mock bridge in the Playwright world: a test endpoint injecting static probes into AuthorityChecker (mirroring mock_primary_idps), a fake /idp/claim page returning a canned attestation signed with handle_attestor_key_override, and specs for cold sign-in via me@handle, add-to-account, bare-handle suggestion, popup-blocked tap-to-continue, and the redirect lane. (2) The first LIVE claim with a real handle (the real test): me@<real handle> at a demo RP, desktop popup + mobile redirect, then re-authorize an agent for the new identity shape — requires interactive Bluesky OAuth, needs a human. Everything server-side is deployed: broker hierarchy + complete_handle_claim, bridge /idp/resolve + /idp/attest + /idp/claim.
