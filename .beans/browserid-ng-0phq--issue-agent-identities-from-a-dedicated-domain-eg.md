---
# browserid-ng-0phq
title: Issue agent identities from a dedicated domain (e.g. agents.browserid.me)
status: completed
type: feature
priority: normal
created_at: 2026-07-12T11:30:12Z
updated_at: 2026-07-12T23:06:46Z
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

## DECISION (2026-07-12): sub-addressing for fallback users; bare names as a primary-IdP incentive

We are NOT moving fallback agents to a flat dedicated domain. Instead, scope agent
handles per-owner by construction:

- **Fallback / broker-rooted humans** (e.g. `vthunder@gmail.com`, where gmail runs no
  IdP and browserid.me vouches): agents are **sub-addressed under the human's own
  verified email** — `<local>+<handle>@<domain>`, e.g. `vthunder+claude@gmail.com`.
  RFC 5233 sub-addressing (a spec form, provider-agnostic — the address never needs to
  receive mail, it's an identifier). This is per-owner-scoped and globally unique for
  free: you can only mint `vthunder+X@gmail.com` if you proved `vthunder@gmail.com`.
  **Cross-user squatting is impossible**, so this largely dissolves the reservation-
  hardening bean for fallback users. Verifies through the SAME fallback path as the
  human (browserid.me already authoritative for `gmail.com`) — zero new DNS/discovery.

- **Primary-IdP humans** (their email domain runs browserid): keep **bare-name
  reservation** — `<handle>@<their-domain>`. This stays a global-unique namespace at
  that domain, and we deliberately KEEP it as an incentive to use a primary-IdP email.

- **Rejected:** flat shared `@browserid.me` (or flat `@agents.browserid.me`) for
  fallback agents — that's the squatting surface. A dedicated agent domain is not
  needed for the fallback case; distinguishability comes from the warrant (agent field),
  not the email shape.

### Implementation sketch
1. `browserid-registrar/src/consent.rs` (~L202 `agent_email`): branch on primary vs
   fallback. Fallback (idp_domain == broker domain != human's email domain): build
   `<local>+<name>@<email-domain>` from the delegator's verified email (parse it out of
   the registered U_cert subject, not just the issuer). Primary (idp_domain == email
   domain): keep bare `<name>@<idp_domain>`.
2. `registrar_glue.rs reserve_agent_names` / quota: for sub-addressed agents uniqueness
   is inherently per-owner — scope the reservation key by owner email; drop the cross-
   account collision scan for that path. Keep global reservation for primary bare names.
3. Verifier (verifier.rs + @browserid-ng/verify): ensure a sub-addressed agent email
   verifies via the fallback path; no check that rejects `+` local parts or requires the
   agent email to equal a reserved bare handle.
4. `@browserid-ng/agent` + wallet + account.html /agents: derive/display the sub-
   addressed identity; multi-name unaffected.
5. Update reservation-hardening bean: note it's moot for fallback users under this model.

## Summary of Changes (implemented 2026-07-12)

Implemented the per-owner-scoped model (sub-address for fallback, bare for primary).

- `browserid_registrar::agent_identity_email(delegator, idp_domain, name)` — the
  single source of truth; used by consent.rs, agent.rs (mint/reserve/revoke),
  registrar_glue.rs, with a JS mirror (`agentIdentityEmail`) in account.html.
- Agent SDK stores its handle explicitly (`StoredIdentity.handle`, serde-default
  for legacy files) — the handle can contain `+`, so it's not recoverable from
  the email; warrant-request/remint/revoke use the stored handle. Fixed a real
  bug where the SDK derived the name from the email local-part.
- Added `Warrant::scopes()` accessor.
- Verification note: fallback identities (human OR agent) verify only via the
  DNS-aware hosted /verify — the offline Rust verifiers are primary-only
  (pre-existing). Decision (user): scope out offline-fallback; tests that verify
  offline use a primary human; fallback shape covered by reserve tests +
  guestbook e2e. New test: two owners' `+shared` handles don't collide.
- All 378 workspace tests green.

Remaining: deploy + a fresh-start DB wipe (orphaned bare-name test identities).
The reservation-hardening bean is largely moot for fallback users under this model.

Deployed (sha 756e201) and production DB wiped for a clean start under the new model. Live.

## Model revised (2026-07-13): constraint holds the FULL local-part (no +splice)

The runtime `<local>+<name>` translation was removed (it forced handle != email,
a footgun that broke the warrant path twice). New model:
- The provisioning-cert constraint `names` ARE the full email local-parts.
- `agent_identity_email(delegator, name) = <name>@<owner's email domain>` on any
  IdP — no translation.
- Anti-squatting enforced at REGISTRATION: fallback owners (email domain != U_cert
  issuer) may only register `<local>+…` names; primary owners (own the domain) may
  use bare or sub-addressed. `agent_name_allowed` replaces `is_canonical_agent_email`.
- SDKs use the email local-part directly again (name == local-part). No "handle".
- Deployed sha 142b540. Existing pre-change identities must be re-provisioned
  (their constraint holds short handles).
