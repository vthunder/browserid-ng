---
# browserid-ng-jipx
title: Broker-side warrant registry — drop the no-server-record rule (§6.4)
status: todo
type: feature
created_at: 2026-07-10T18:05:49Z
updated_at: 2026-07-10T18:05:49Z
---

Design change (vthunder, 2026-07-10): there should be no expectation of privacy *from the broker* — it already mediates logins for broker-rooted identities and serves the key-custody surface, so hiding warrant metadata from it buys little and costs real UX. The broker SHOULD keep a per-identity list of warrants.

## What changes

- Spec: revise agent spec §6.4 (delete-on-delivery) and the §3 audience-privacy rule: the *registrar* MAY retain warrant records (agent, audience, scopes, exp) for the delegator's own account view. Keep what still matters: RP X never sees other RPs' warrants; the IdP-as-verifier path is unchanged; federated self-hosted registrars hold only their own users' records (consistent with 1pnf).
- Broker: persist warrant records at consent approval (and optionally at manual signing via a register call); wsapi to list per identity; feed /account agent detail from the server instead of localStorage (browser log becomes a cache, works cross-browser).
- Pairs with egr7: server-known warrants can get status entries → real per-warrant revocation UI ("revoke this grant" instead of "revoke the whole agent").

## Notes

- Landing copy currently doesn't promise registrar-blindness — verify before shipping and adjust the spec's privacy-properties list (§5.2) which does.
- /account currently ships a localStorage-only warrant log (2026-07-10) — that becomes the offline cache.
