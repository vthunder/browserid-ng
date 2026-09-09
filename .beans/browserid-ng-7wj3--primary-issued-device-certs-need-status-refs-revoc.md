---
# browserid-ng-7wj3
title: 'Revocation of primary-issued certs is weak: blank status refs accepted, no remote kill'
status: todo
type: task
priority: high
created_at: 2026-07-22T15:14:46Z
updated_at: 2026-09-09T22:13:29Z
parent: browserid-ng-9yyk
---

Surfaced by the revoke-up-front holder-move design (2026-07-22): mingo-idp (and sandmill) issue device/config certs with status: None, so the broker's up-front revocation (move_holder, forget_holder, revoke_device_cert) only bites broker-issued certs — a primary-rooted device's certs cannot be killed remotely; immediacy is bounded by cert expiry or the device's own re-issue.

Design needed: primaries should embed StatusRef in issued certs and publish a status list (mingo-idp has no status machinery today), plus a revocation surface. Wrinkle: the broker can't tell the primary to revoke (no server-to-server channel by design) — options: (a) primary-side revocation UI/API driven by the user's first-party session; (b) primaries delegate status to a list the user's browser can flip via the broker hop; (c) accept the gap and lean on short cert TTLs for primaries. Needs Dan's ruling.

2026-09-07, from registry-api-v1 round-3 UX review (A11): revoking a FOREIGN-issued cert at the registry only retires it there and answers revoked:false; site logins keep working until the issuer sets its bit, and wallets will say 'device removed'. Spec now says the wallet MUST route to the issuer before reporting success; this bean covers the issuer side (status refs / immediacy).

2026-09-10 (Dan): broaden — this is about making revocation of primary-IdP certs robust overall, not only immediacy. Today the registry's validity bar (registry-api-v1 §7.1 cert_revoked) and RP verifiers ACCEPT a cert with no status ref at all, so a primary that never publishes a list issues certs that cannot be revoked by anyone before expiry. Sign-out from /account now revokes the device's login key and explicitly retires each cert attached under it (revoking a key does not itself touch certs); for a foreign issuer that only retires the row here, returns it in `unrevocable`, and the page sends the user to the issuer's revoke page — a hop with no confirmation the bit was set.

Questions to settle:
- [ ] Require a status ref on every device cert the registry records / RPs accept (conformance rule for primaries; grace period or accepted-fallback exception?)
- [ ] Short TTLs as the floor for primaries that cannot publish a list — what TTL, and does the wallet re-issue silently
- [ ] The issuer-revoke hop: standardize the page (fallback-IdP API) and confirm against the issuer's signed list before the account page reports success
- [ ] sandmill / mingo-idp: embed StatusRef, publish a list, expose the revoke page
- [ ] Verifier side: fail closed on missing ref once the rule exists (core spec + browserid-core + gate)
