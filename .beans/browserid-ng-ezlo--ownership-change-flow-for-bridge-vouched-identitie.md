---
# browserid-ng-ezlo
title: Ownership-change flow for bridge-vouched identities (rotation vs transfer vs compromise)
status: draft
type: feature
created_at: 2026-08-19T17:25:52Z
updated_at: 2026-08-19T17:25:52Z
---

Design discussion with owner 2026-08-19, following kts0. When a bridge-vouched identifier's binding changes (handle → new DID, address → new Google subject), the new prover legitimately controls the identifier NOW, but must not automatically get the old browserid account.

## The cases
1. **Self-rotation** — the same person changes their handle's DID / Google account. Desired: same browserid account, same emails, binding re-pinned.
2. **True transfer** — the identifier changed hands (corp address reassigned, handle sold/re-registered). Desired: old account loses the address (and only the address); new owner uses it in their own (possibly fresh) account.
3. **Compromise** — an attacker with temporary control of the bridge account produces the same proof as case 2. Desired: nothing durable changes; the legitimate owner can recover. Indistinguishable from case 2 by the proof itself — only time + the old owner's reaction separates them.

## The unifying discriminator
Case 1's owner can do something cases 2/3's provers cannot: **prove the NEW binding while authenticated to the OLD account**. That is ground truth for "same person," and the server mechanism already exists — a bridge claim under the owning session re-pins in place (attach arm sets the new proof_subject/DID), and a claim under a DIFFERENT account's session transfers the address INTO that session's account. So:

- **Rotation = session-gated re-claim.** Sign into your browserid account by any means (password, another identity, an existing session), run the claim, binding re-pins, nothing else moves. Works today; needs UI/docs surfacing ("changed your handle's DID? re-verify here").
- **Cold conflicting proof = transfer with a recovery tombstone.** Keep the per-email transfer semantics (atproto today; passwordless-oidc today), but add:
  (a) a tombstone on the old account: "address X left this account on DATE";
  (b) notification through the old account's remaining channels;
  (c) a recovery affordance: sign into the old account and re-claim — proving the new binding under the old session transfers the address BACK with history intact (server mechanism exists; case 1 users who rotated without re-claiming first use this);
  (d) revoke the old account's device certs for the departed address at transfer time (see browserid-ng cert-revocation bug — without this, 'loses access' is not real for up to 90d);
  (e) optionally: during a grace window after a cold transfer, the address mints only short-TTL certs in its new account, bounding case-3 impersonation while the old owner reacts.
- Case 3 then degrades to: attacker gets the address (bounded by (d)/(e)) until the real owner recovers control of the bridge account and re-claims — which mirrors reality: whoever durably controls the identifier's root of trust owns the identifier.

## Provenance asymmetries to respect (already in code, kts0)
- **Handles (atproto):** the DID binding outranks the broker password (mailed resets refused for handle domains; bridge is the only re-proof channel) → cold conflicting proof transfers even from password-backed accounts. The tombstone/recovery flow is the safety net.
- **Google (oidc):** the broker password outranks mailbox control for account binding → cold conflicting proof against a password-backed account is refused ('password required'); the legitimate new owner's channel is the reset flow (bounded by kgb9: siblings unverify, E1/E2 unusable to the taker). Passwordless accounts get the transfer+tombstone path.

## Open questions
- Tombstone/window duration; what notification channels exist for a single-identity account (none — accept that rotation-without-preparation on such accounts risks orphaning?).
- Should recovery-by-re-claim expire (attacker who holds the identifier long-term shouldn't fear an eternal takeback?) — probably yes, same window.
- Does (e) interact with the pr3a bridge-TTL machinery (already short for E2)?
