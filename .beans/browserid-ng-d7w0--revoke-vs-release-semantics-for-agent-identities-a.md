---
# browserid-ng-d7w0
title: Revoke vs release semantics for agent identities and emails
status: draft
type: feature
created_at: 2026-07-10T20:51:10Z
updated_at: 2026-07-10T20:51:10Z
---

Deferred design (vthunder, 2026-07-10). /account needs a way to turn off an agent (or email) — but the two operations are distinct:

- **Revoke**: invalidate the current key/credential (status bit set → certs+warrants die within a cache window; provisioning cert revoked → no re-mint). A **new key can be issued for the same handle** — the identity persists, it's the credential that's killed. (NOT "re-enable" — that wrongly implies reactivating the same key.)
- **Release** (better name than "delete"): revoke **and** release the handle. Whether anyone — including this same account — may reclaim it later is up to the primary IdP.

## Implications to work out
- Broker `ensure_agent_identity` currently treats a revoked (unverified) agent record as permanently dead ("revoked; sticks"). Revoke-then-new-key needs the *owner* to re-provision the same handle (fresh key, cleared status bit) while still never handing it to a *different* account. Small spec relaxation.
- Status index is per-identity + stable, so revoke = set bit, re-provision = clear bit. Release = free the handle record + reclaim quota; the status bit can stay set (its certs are dead) since the index is retired with the handle.
- Federated IdPs (mingo): release policy is theirs (§4 revoked-names-never-recycled vs owner-reclaim). Coordinate with 1pnf.
- UI: per-agent Revoke (prominent) + Release (destructive, confirm). Per-email likewise (Revoke = sign this email's certs off; Release = remove from account). Warrant-level revoke already exists (egr7).
