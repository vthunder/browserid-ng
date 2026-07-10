---
# browserid-ng-egr7
title: Credential revocation — agent credentials and identities in general
status: todo
type: feature
priority: high
created_at: 2026-07-10T08:09:05Z
updated_at: 2026-07-10T15:34:37Z
parent: browserid-ng-gsnm
---

## Problem

There is no real revocation story — for **agent credentials** specifically, and for **identities in general**. browserid certs are **offline, self-contained** credentials: an RP verifies a signature against a DNS/well-known-published key with no phone-home, which is great for simplicity and privacy but means a credential, once issued, is valid until it **expires**. Today the only lever is short cert TTL. The landing page's "flip an agent off in one click" is not backed by anything.

## Why it matters

- **Agent compromise / cleanup.** A user should be able to kill a specific agent's identity (leaked key, misbehaving agent, done with a task) without waiting for TTL and without rotating their own identity.
- **User key compromise.** If a user's identity key leaks, there must be a way to invalidate outstanding certs/assertions faster than expiry.
- **On-chain identities (SBO/mingo).** A key-rooted `/sys/names/<name>` claim persists; revoking it (or an agent claim under it) needs defined semantics + who's authorized.

## Options to weigh

- **Short TTL only (status quo).** Simple, no infra; exposure window = TTL. Fine as a floor, insufficient alone.
- **Revocation / status list (OCSP-like).** IdP (or broker) publishes revoked cert IDs; RPs check. Reintroduces an online dependency + privacy considerations (RP learns who's checking). Could be pull (RP polls a signed list) to limit leakage.
- **Delegation-root revocation.** Revoke the provisioning cert / the parent's endorsement so derived agent certs can't be re-minted; existing short-lived agent certs still expire naturally. Cheap and aligned with the delegation chain.
- **Epoch / key rotation.** Bump an identity epoch so all prior certs are stale; blunt (revokes everything, not one agent).
- **On-chain revocation records.** For SBO, a revocation object RPs/validators honor; deterministic + auditable, but only helps on-chain consumers.

Likely answer is a **layered** one: short TTL + delegation-root revocation for agents + an optional signed status list for RPs that need fast revocation; on-chain revocation records for the SBO path.

## Open questions (design-first)

- Who is authorized to revoke what (self, parent, broker, domain)?
- Where does revocation state live and how do RPs consume it without a heavy online dependency or a privacy leak?
- Coherence between the browserid-cert world and the SBO on-chain identity world.
- Interaction with the agent-constraints bean (a constrained + revocable agent is the real target).

## Related
- Sibling: agent capability-constraints bean. Delegation-chain spec: docs/specs/agent-provisioning-and-grant-api.md. Surfaced while building the browserid landing page.

## Resolution (2026-07-10) — layered stack

Design converged; canonical write-up: `docs/plans/2026-07-10-agent-identity-v3-and-gtm-plan.md` (§5). The "layered" hunch above is confirmed, concretely:

1. **Short TTL floor** (24h / 1h ephemeral) — unchanged. Do NOT shorten TTLs to fake fast revocation: every re-mint is a registrar round trip and short TTLs make the registrar HA-critical.
2. **Delegation-root revocation** (already shipped): registry revoke starves endorsements → no re-mint. The "kill this agent" primitive.
3. **Signed status list**: certs carry `status: {uri, index}`; IdP publishes a compact signed bitmap; RPs fetch + cache ~5 min. **Adopt IETF OAuth Token Status List format** — do not invent one. Privacy-good (fetching the list reveals nothing about the subject checked). Soft online dependency: unreachable list → TTL semantics; fail-open/closed is RP policy (SDK default TBD, see open questions).
4. **User-key compromise**: user certs get status entries too; epoch bump stays the nuclear option.
5. **Offline/on-chain (sbo)**: detached status-list snapshot with freshness window composes with core §6.3 detached DNSSEC proofs.

Warrants need no separate revocation: they're only meaningful alongside a live agent cert (see sibling 5zdh).

Resulting story: instant for new sign-ins at status-checking RPs; ≤ cache window for live sessions there; ≤ TTL at naive RPs.

### Todo
- [x] Spec v0.4: status claim in certs + list format/endpoint (IETF token-status-list) — core §6.4
- [ ] Broker/IdP: status list publication + revocation wiring to registry switch
- [ ] browserid-rp: status check with cache, fail-open/closed policy knob
- [ ] Decide SDK default: fail-open grace window vs hard fail-closed
- [ ] sbo path: detached snapshot semantics
