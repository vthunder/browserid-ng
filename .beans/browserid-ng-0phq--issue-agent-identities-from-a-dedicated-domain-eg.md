---
# browserid-ng-0phq
title: Issue agent identities from a dedicated domain (e.g. agents.browserid.me)
status: todo
type: feature
priority: normal
created_at: 2026-07-12T11:30:12Z
updated_at: 2026-07-12T11:30:12Z
---

Today agent identities are minted at the broker's own domain (browserid.me), sharing the namespace with human identities. Issue them from a dedicated agent domain instead — e.g. agents.browserid.me — so agent handles live in their own namespace, are visually/structurally distinguishable from human identities, and can have their own DNSSEC key / policy / rate limits.

Rationale (from demo use): an agent identity reading '<handle>@browserid.me' is indistinguishable at a glance from a human '<handle>@browserid.me', and the shared namespace couples agent and human handle allocation.

Likely touches a lot:
- Broker: mint/reserve/agent identity email construction currently uses state.domain; introduce an agent-domain (config) and issue agent emails there.
- DNS/discovery: agents.browserid.me needs its own _browserid DNSSEC record / key (or delegated), and verifiers must resolve agent certs' issuer to that domain.
- account.html /agents flow: idpUrl/idpDomain for agents -> the agent domain; the P_cert iss / U_cert issuer expectations.
- Verifier (verifier.rs + @browserid/verify): issuer authorization for agent certs must accept the agent domain.
- @browserid/agent + wallet + agent_cli: idp/idpDomain derivation.
- Reservation/quota keyed by the agent domain namespace.
- Migration: existing agent identities on browserid.me.

Design first (a short plan doc): decide subdomain vs separate domain, key delegation, discovery, and migration, then implement. Worth it for the clearer namespace + policy separation.
