---
# browserid-ng-4d80
title: 'mingo follow-ups: CLI device pairing + poster re-enable + derived-identity labels'
status: todo
type: task
created_at: 2026-07-19T14:36:07Z
updated_at: 2026-07-19T14:36:07Z
parent: browserid-ng-oup3
---

Deferred from the mingo site migration (mingo device-migration branch):
- [ ] mingo-app CLI: login.rs/seed.rs (+ appoint/livetest/set_root_admin on top) still classic — need a device-model pairing client in browserid-agent (agent-provision request/poll + warrant request/poll) and a port of seed's write assembly; deploy unaffected (only mingo-idp builds)
- [ ] mingo-poster: re-enable on device model (agent DEVICE cert for mingo-poster@mingo.place, warrants via broker /warrant/request+poll, presentation in the SBO write path); endpoints currently stubbed 503
- [ ] derived-identity 'signs in via' labels: the device flow doesn't call /wsapi/set_parent (no subordinate_to channel in the device-authorize handshake) so new handle identities lack the parent link in the broker chooser
- [ ] merge device-migration -> main in ~/src/mingo once live login is confirmed
