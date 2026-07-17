---
# browserid-ng-pv9b
title: 'Explore: browserid.me-rooted agent (handle+label@browserid.me) parented to an external primary'
status: todo
type: task
priority: normal
created_at: 2026-07-17T14:30:49Z
updated_at: 2026-07-17T14:36:14Z
parent: browserid-ng-mr2n
---

Roadmap item 3 (see the CLI-auth epic). The conventional fallback if the +label path (item 4) doesn't hold.

The agent identity lives at browserid.me (`dan+mingo-cli@browserid.me`) — which browserid.me CAN mint (given the personal-namespace feature, item 2) — and the warrant delegates an EXTERNAL primary's authority to it (`as: danmills@sandmill.org`). Cross-issuer (browserid-ng-yhcx): U_cert is a sandmill.org cert, agent_cert is browserid.me. Determine: does browserid-broker mint + the daemon's as: path already accept a warrant whose delegator issuer != the agent's issuer? (validate.rs resolves the delegator's on-chain /sys/dnssec, which is the cross-issuer hook.) What broker change is needed to mint an agent whose parent is an external primary the broker did NOT issue? This is the mingo-poster shape (agent@provider, parent=external) generalized. Needs the personal-namespace feature (item 2) + likely a broker mint relaxation. Compare cost/generality vs item 4.

## VERDICT (2026-07-17): recommended path — the hard crypto is already built (yhcx)

The cryptographic foundation for item 3 is DONE + tested via browserid-ng-yhcx: sbo-core/attribution.rs already verifies a CROSS-ISSUER warrant (agent in one domain, delegator/parent in another) by sourcing the delegator's own /sys/dnssec proof; the daemon's resolve_agent_effective + as: path already attribute an agent@X / parent=danmills@sandmill.org write to danmills@sandmill.org and match roles.admin. NO daemon/crypto-core changes needed.

Remaining work for item 3 (all plumbing, none touching the cert-chain trust root):
1. Personal namespace (item 2) — so the user owns a browser.me handle to mint dan+label@browserid.me. Unbuilt (relates browserid-ng-fnr1).
2. Broker mint relaxation (THE crux code change) — today browser mint requires delegator-issuer == broker domain and mints agent@<delegator-domain> with parent=delegator (agent.rs:85, lib.rs:61, agent.rs:211). Item 3 needs the broker to mint an @browserid.me agent cert whose agent.parent is a FOREIGN email (danmills@sandmill.org) it did not issue — decoupling agent-name ownership from the parent. This is the mingo-poster self-mint shape, done by the broker.
3. External-delegator consent path — the inverse of the built external-warrant branch (which assumes a LOCAL delegator); host a warrant whose delegator is external while the agent is local. Parent's sandmill.org key signs in-browser.
4. Assertion-path (warrant.rs::verify_for) cross-issuer relaxation — only if the browser.me agent must log into WEB RPs; NOT needed for SBO CLI writes (yhcx deferred it).

vs item 4: item 3 reuses built crypto + adds broker/consent/namespace plumbing; item 4 requires loosening the cert-chain trust root in TWO security-critical verifiers + a self-hosted revocation scheme. Item 3 is lower-risk. Tradeoff: item 3 hosts the agent @browser.me + needs a handle; item 4 keeps the agent under the user's own domain.

RECOMMEND item 3.
