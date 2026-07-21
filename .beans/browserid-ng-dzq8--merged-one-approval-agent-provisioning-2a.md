---
# browserid-ng-dzq8
title: Merged one-approval agent provisioning (2a)
status: in-progress
type: feature
priority: normal
created_at: 2026-07-21T21:07:04Z
updated_at: 2026-07-21T21:52:53Z
parent: browserid-ng-oup3
---

Merge device-cert provisioning (/agent-provision/*) and warrant issuance (/warrant/*) into one request + one approval + one pickup, per docs/plans/2026-07-21-broker-assigned-holder-deep-dive.md §Agent/service path and docs/plans/2026-07-21-HANDOFF-agent-d.md §2a.

Design: /agent-provision/request gains namespace hint + grants[audience+scopes]; new session-authed /agent-provision/prepare assigns the broker holder + allocates warrant status idxs and returns them to the approval page; the page signs the warrant(s) client-side with the user's config cert (matcher <id> default, widenable <ns>.*); /agent-provision/complete validates the signed warrants (shared logic with consent::respond), issues the device cert with the SAME holder, stores registry rows; /agent-provision/poll returns device cert + warrant~config_cert grants.

- [x] registrar: RequestBody grants+namespace; Record extended; info returns grants
- [x] registrar: /agent-provision/prepare (holder assignment + status alloc)
- [x] registrar: complete validates+stores warrants, issues cert with prepared holder; poll returns both
- [x] factor warrant-validation shared with consent::respond
- [x] account.html provision card: show grants, sign warrants with config key, widen checkbox
- [x] CSP hash update + guard green
- [x] tests: end-to-end merged flow in broker integration tests
- [x] browserid-agent SDK: provisioning bootstrap (request/poll -> DeviceCredential + grants)

## Design finding (session 5): primary-domain agents need primary-signed certs
browserid-core AccessPresentation::verify enforces config_cert.iss == access_cert.iss (device.rs:568). The warrant for a mingo-domain agent (dan+poster@mingo.place) is signed by the MINGO-issued config cert in the broker keystore, so the poster's device/access certs must ALSO be mingo-issued — a broker-signed agent cert would provision fine but fail verification at the sbo daemon. The sbo authority rule (email domain == iss OR pinned broker) is not the binding constraint; issuer consistency is.

=> 2b architecture (Option M, honors "one URL one approval" + rule 1):
- registrar `complete` accepts an optional page-supplied `device_cert` (primary-signed): validated to certify the request's pubkey, agent identity, PREPARED holder, purpose=authentication, iss == identity domain.
- account.html approval, for a primary-rooted delegator, hops to the primary's device-authorize popup (agent mode: pubkey+holder+agent identity) to get the cert signed, then calls complete with it.
- mingo-idp /device_cert grows agent mode: session-authed issuance for `<handle>+<tag>@mingo.place` over a supplied pubkey + broker-assigned holder (passthrough), authentication-purpose only.
- Poster = mingo server holding device key + mingo-signed cert + warrant; mints access at mingo's own /access/mint; assembles SBO wire server-side (sbo-core 55314e9 pinned in mingo-idp only; workspace/mingo-app stays a92886c to avoid breaking the classic CLI until its own migration).

2a COMPLETE incl. as-you + primary-signed-cert extensions; see commits 440f545, 5736bdb, 5710ea6, 645d7c9. Remaining: live verification rides the D deploy (bean browserid-ng-3b8m).
