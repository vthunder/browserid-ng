---
# browserid-ng-1pnf
title: Registrar unbundling — endorser role defaults to the IdP, hosted registrar becomes the product
status: todo
type: feature
priority: high
created_at: 2026-07-10T15:24:05Z
updated_at: 2026-07-10T15:34:37Z
parent: browserid-ng-gsnm
---

v2 conflated three roles under "broker": fallback IdP (unchanged), mediator/UX (unchanged; agents never used it), and the **registrar** — P_cert registry, key-mgmt UI, revocation switch, endorsement signing. This bean moves only the third. Canonical design: `docs/plans/2026-07-10-agent-identity-v3-and-gtm-plan.md` (§6).

## Why

Under the identity-domain rule an agent always mints at its delegator's own IdP, which issued the U_cert and can run its own quota — there is no cross-IdP sybil surface needing a global view. Mandatory browserid.me endorsement for federated IdPs adds nothing they can't do themselves, while granting browserid.me visibility into and a veto over other domains' agent activity, plus an availability coupling (broker down → every federated agent dead within one TTL). It's the "Persona centralization" critique handed to critics.

## Changes

- Spec: rename endorsement issuer broker→**registrar**; IdP config "accepted brokers" → "accepted registrars", **default = self**. Wire formats unchanged; endorser/issuer collapse exactly like the broker-rooted path already does.
- Broker-rooted users: registrar *is* browserid.me — long tail unaffected.
- Natively-rooted users: their IdP is the registrar; browserid.me not in the path.
- An IdP MAY configure an **external registrar** (browserid.me) to outsource registry/policy/key-mgmt UI/consent surface → the opt-in managed product (GTM revenue line), not a mandatory dependency.
- Cost: v2 deleted mingo-idp key management ("key mgmt is broker-only"); ship registry + endorsement signer + key-mgmt/consent UI as a **reusable component** — that component IS the self-host story. Absorbs/relates to bean btmg (key-mgmt UI, currently broker-landing-scoped).

User story: **you manage your agents where your identity lives.**

### Todo
- [x] Spec v0.4: registrar terminology + accepted-registrars default-self + external-registrar config
- [ ] Extract registrar component (registry, endorsement signer, key-mgmt UI) from broker
- [ ] mingo-idp: adopt registrar component (or external-registrar config path)
- [ ] Reconcile with bean btmg scope
