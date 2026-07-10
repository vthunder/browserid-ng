---
# browserid-ng-5zdh
title: Agent identity capability constraints — scope what a delegated agent can do
status: in-progress
type: feature
priority: high
created_at: 2026-07-10T08:09:05Z
updated_at: 2026-07-10T16:02:26Z
parent: browserid-ng-gsnm
---

## Problem

The landing-page pitch (and the intuition behind agent-native identity) promises that a user can give an agent a **limited** identity — "it can only do what you allow." **The protocol does not support this today.** A provisioned agent gets an email-form identity + cert that is **indistinguishable from a human user's**: same shape, same verification, and — by design — an **offline, self-contained credential** the agent can present invisibly at any relying party. There is no notion of scope, allowed audiences, or capability on the credential, and nothing an RP could enforce even if it wanted to.

So the real, honest agent safety property today is **isolation** (the agent holds its own key, not the user's password / not a shared master key), NOT **restriction**. We want to close the gap to restriction.

## What "limiting an agent" could mean

- **Distinguishability first.** Before you can restrict an agent, RPs must be able to tell it's an agent and who it acts for. Bake claims into the cert: `agent: true`, `parent: <user identity>`, maybe `purpose`. (cm8z already labels derived identities in the chooser UI — this is the RP/cert-level version.)
- **Capability/scope claims.** Cert carries allowed actions/scopes and/or an **audience restriction** (valid only at RP X, or a set). RPs read and honor them.
- **Time-boxing.** Short-lived agent certs already limit exposure; capabilities could be scoped per-cert and refreshed.

## The hard part: offline credentials

Because assertions are offline and self-contained, **the IdP is not in the loop at use time** — enforcement has to live either (a) in the credential (cert-baked, RP-enforced) or (b) at the RP via a policy/status check. That means:
- Cert-baked constraints are **advisory unless RPs enforce them.** A naive RP that only checks "valid email cert" ignores the constraints and treats the agent like any user → confused-deputy risk.
- We likely need a spec'd, standardized set of agent claims + a clear statement of the RP's enforcement responsibility, so constraints mean something.

## Open questions (why this is design-first)

- Which constraints are worth expressing: scopes? audiences (per-RP)? rate/quotas? purpose strings?
- How do we get RPs to enforce — SDK defaults that fail-closed on agent certs? A conformance requirement?
- Interaction with revocation (see sibling bean) and short TTLs.
- On-chain angle: for SBO/mingo, the owner is a key-rooted identity; capability constraints there could be policy-side rather than cert-side. Keep the two models coherent.

## Related
- Sibling: credential revocation bean (agents + general). cm8z (label derived identities). The delegation-chain provisioning spec: docs/specs/agent-provisioning-and-grant-api.md.
- Surfaced while building the browserid landing page — the page has been pulled back to claim only isolation until this lands.

## Resolution (2026-07-10) — warrant model

Design converged; canonical write-up: `docs/plans/2026-07-10-agent-identity-v3-and-gtm-plan.md` (§2–3). Supersedes the open questions above.

- **Distinguishability**: IdP-minted agent cert carries `agent: {parent, name}` block; parent disclosure default-on; invisible-agent mode removed entirely. Reverses the v2 "never protocol-visible" rule.
- **Audience + scopes live in warrants, not the cert**: user's identity key signs one warrant per audience — `{typ: browserid-agent-warrant-v1, agent, aud (exact origin, no wildcards), scopes (opaque RP-vocabulary strings), iat, exp}` — verified via the same `U_cert` signing-time semantics as `P_cert`. Preserves the Persona privacy property structurally: IdP/registrar never see warrants; RP X sees only its own; no artifact ever holds the full audience list (hashing rejected: top-sites brute force).
- **Fail-closed by construction**: agent certs get their own `typ` (`browserid-agent-cert-v1`; core §6.2 rejects unrecognized typ) and the warrant rides *inside* the tilde chain (`agent_cert~warrant~assertion`) so a verifier cannot skip it. Cert+key leak without warrants is useless everywhere.
- **Enforcement layers**: warrant `aud` — any verifier; `scopes` — RP token endpoint at grant exchange (§5.3) intersects with its own vocabulary; SDK ships fail-closed defaults.
- **Rejected for v3**: caveat/attenuation tokens (Biscuit-style), purpose strings in cert, agent-side downscoping (delegation-time-only scoping is policy).

### Todo
- [x] Spec v0.4: agent claims block + cert typ (core §4, §6.2)
- [x] Spec v0.4: warrant format + chain framing (agent module — §5, incl. warrant binding by agent identity email with embedded parent-cert)
- [x] browserid-core: warrant type, chain parsing, typ enforcement (warrant.rs; agent typ/block in certificate.rs; warrant-in-chain + VerifiedPresentation in assertion.rs)
- [x] browserid-rp: fail-closed verification + scope intersection at token endpoint (with_scopes, TokenGrant, challenge scopes param)
- [x] browserid-agent: warrant storage + presentation (add_warrant, NoWarrant fail-closed, persisted warrants)
- [ ] Registrar UI: manual warrant creation (MVP fallback; JIT flow is sibling bean)

## Implementation notes (2026-07-10)

Core/broker/rp/agent shipped; all workspace tests green. Broker mints agent certs (typ + parent) via issue_certificate for EmailType::Agent; /verify returns agent{parent,scopes}. **Breaking by design**: once an agent re-mints (≤24h), warrant-less presentations are rejected everywhere — mingo RPs must move to the warrant flow (browserid-rp handles it transparently; agents need add_warrant). Remaining here: registrar UI manual warrant creation. mingo-idp adoption tracked under 1pnf.
