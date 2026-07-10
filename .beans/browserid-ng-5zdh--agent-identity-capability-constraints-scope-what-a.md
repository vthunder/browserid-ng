---
# browserid-ng-5zdh
title: Agent identity capability constraints — scope what a delegated agent can do
status: draft
type: feature
priority: high
created_at: 2026-07-10T08:09:05Z
updated_at: 2026-07-10T08:09:05Z
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
