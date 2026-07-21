---
# browserid-ng-dzq8
title: Merged one-approval agent provisioning (2a)
status: in-progress
type: feature
priority: normal
created_at: 2026-07-21T21:07:04Z
updated_at: 2026-07-21T21:21:35Z
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
