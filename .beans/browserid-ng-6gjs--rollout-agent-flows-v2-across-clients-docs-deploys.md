---
# browserid-ng-6gjs
title: 'Rollout: agent flows v2 across clients + docs + deploys'
status: in-progress
type: task
created_at: 2026-07-26T18:57:41Z
updated_at: 2026-07-26T18:57:41Z
---

Follow-on to eywc/t1jp: update every consumer to the new protocol (grantor pin incl. 'self', message field, two-stage approval, poll reasons), refresh documentation/readmes, and deploy everything for live testing.

- [ ] browserid-ng: browserid-rp — check if any change needed
- [ ] browserid-ng: sdk/wallet + examples (mcp-agent-auth) updated where useful (message, copy)
- [ ] browserid-ng: READMEs/docs sweep for stale flow descriptions
- [ ] browserid-ng: commit + deploy broker
- [ ] mingo: update browserid-agent call sites (new request_provision args), deploy
- [ ] sbo: update if it consumes browserid-agent, deploy
- [ ] browserid-bsky: adopt grantor 'self' pin + message (per HANDOFF), deploy
- [ ] verify deployed broker serves the new pages (CSP hashes, flows)
