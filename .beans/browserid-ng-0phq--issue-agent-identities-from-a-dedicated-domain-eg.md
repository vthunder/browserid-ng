---
# browserid-ng-0phq
title: Issue agent identities from a dedicated domain (e.g. agents.browserid.me)
status: todo
type: feature
priority: normal
created_at: 2026-07-12T11:30:12Z
updated_at: 2026-07-12T12:33:51Z
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

## Decision to make: global-unique vs per-owner-scoped handle namespace

Today agent handles are a FLAT global namespace (<handle>@browserid.me), unique across all users first-come-first-served — which is the entire source of the cross-user squatting surface (see reservation-hardening bean). Moving to a dedicated agent domain is the natural moment to decide:
- Keep global-unique (short handles, but needs squatting defenses: expiry, rate limits, Sybil resistance), OR
- Scope handles per-owner, e.g. <handle>@<user>.agents.browserid.me or <handle>.<user>@agents.browserid.me — every human gets their own handle namespace, eliminating cross-user squatting entirely, at the cost of longer identifiers and more DNS/discovery structure.
Decide this as part of the domain design; it shapes discovery, cert iss, and the verifier's issuer-authorization.
