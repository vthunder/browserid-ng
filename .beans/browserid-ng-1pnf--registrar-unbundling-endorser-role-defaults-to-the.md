---
# browserid-ng-1pnf
title: Registrar unbundling — endorser role defaults to the IdP, hosted registrar becomes the product
status: completed
type: feature
priority: high
created_at: 2026-07-10T15:24:05Z
updated_at: 2026-07-11T00:04:20Z
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
- [x] Extract registrar component (registry, endorsement signer, consent/warrant API, status list) from broker — browserid-registrar crate; UI remains broker-served reference impl for now
- [x] mingo-idp: external-registrar config path confirmed working (registrar-is-browserid.me, ddd7189); self-host adoption now unblocked by the crate — do when mingo wants it
- [x] Reconcile with bean btmg scope — btmg (API-key mgmt UI) retargeted to /account; that UI is the registrar component's reference surface, packaged with the component later

## Summary of Changes (2026-07-11)

Registrar extracted into the browserid-registrar crate: RegistrarStore (registrar-owned tables, host persistence) + RegistrarHost (sessions, email ownership, agent-identity enumeration stay host-side) + router() serving the wire-stable paths. The broker mounts it via registrar_glue (UserStore-delegating adapters), running IdP + registrar in one process; routes/warrant.rs deleted, routes/agent.rs reduced to the target-IdP mint/reserve/list/revoke role. Wire compatibility proven by untouched integration suites (360 tests green).

Deliberately deferred:
- Packaging the consent/key-mgmt UI (consent.html + /account agent sections) with the component — broker pages remain the reference implementation; a self-hosting IdP needs equivalents of /wsapi/session_context + a cert-refresh endpoint for the consent page's client-side signing.
- Actual mingo-idp self-host adoption (separate repo/deploy; external-registrar mode confirmed working and remains its configuration).
- Spec: v0.4 already carries registrar terminology + accepted-registrars default-self; no further spec change needed here.
