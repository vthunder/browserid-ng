---
# browserid-ng-pv9b
title: 'Explore: browserid.me-rooted agent (handle+label@browserid.me) parented to an external primary'
status: todo
type: task
priority: normal
created_at: 2026-07-17T14:30:49Z
updated_at: 2026-07-17T14:31:14Z
parent: browserid-ng-mr2n
---

Roadmap item 3 (see the CLI-auth epic). The conventional fallback if the +label path (item 4) doesn't hold.

The agent identity lives at browserid.me (`dan+mingo-cli@browserid.me`) — which browserid.me CAN mint (given the personal-namespace feature, item 2) — and the warrant delegates an EXTERNAL primary's authority to it (`as: danmills@sandmill.org`). Cross-issuer (browserid-ng-yhcx): U_cert is a sandmill.org cert, agent_cert is browserid.me. Determine: does browserid-broker mint + the daemon's as: path already accept a warrant whose delegator issuer != the agent's issuer? (validate.rs resolves the delegator's on-chain /sys/dnssec, which is the cross-issuer hook.) What broker change is needed to mint an agent whose parent is an external primary the broker did NOT issue? This is the mingo-poster shape (agent@provider, parent=external) generalized. Needs the personal-namespace feature (item 2) + likely a broker mint relaxation. Compare cost/generality vs item 4.
