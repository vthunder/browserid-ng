---
# browserid-ng-bw9q
title: 'Registry lane for native wallets: device-cert-authenticated approvals inbox (+ client-supplied holder)'
status: in-progress
type: feature
priority: normal
created_at: 2026-08-27T08:57:24Z
updated_at: 2026-08-27T18:02:03Z
---

The menubar-wallet prototype exposed that every registry operation is session-cookie-only, so a native wallet is a second-class registry client standing on borrowed cookies:

- **Approvals inbox**: /wsapi/warrant_requests requires a broker session; the wallet polls it with a persisted Electron session that dies with the cookie. Clean fix: a device-cert-authenticated inbox — e.g. POST /warrant/inbox { device_cert } returning the same PendingRequestInfo set for the cert's account. The auth primitive already exists in warrant_request (consent.rs ~1219: parse cert, verify against IdP key, purpose Authentication, unexpired, unrevoked, authorizes identity) and store.list_pending_warrant_requests(user_id) is already the backing query.
- **Client-supplied holder on the fallback lane** is the sibling gap, already tracked in kmvm.

Bigger picture (client-broker vs server-broker delineation, recorded on 7v5l): making registry operations cert-authed is what turns the wallet into a first-class registry client, and is the prerequisite for anyone self-hosting the registry role.

**Direction from Dan (2026-08-28):** build this as a carefully specified, well-defined API — not ad-hoc per-call device-cert auth. Shape: an auth endpoint that exchanges a presentation for a bearer token; the bearer token then authorizes all other registry endpoints (inbox, devices/holders, warrants, revocation). Spec-quality bar: an independent broker implementation must be buildable from the API spec alone, without reverse-engineering the current broker. Design carefully: token scoping/lifetime/revocation, relationship to auth_with_presentation (which mints a cookie session today — the token exchange is its API-shaped sibling), and how the existing cookie-authed /wsapi surface maps onto or retires into this. See docs/plans/2026-08-28-native-wallet-design-handoff.md.

## Design decisions (2026-08-28 session with Dan)

- **Token binding: sender-constrained.** DPoP-style — each API call carries a JWS proof (method, URL, timestamp, nonce) signed with the device key; the token is bound to the key thumbprint. Exchange endpoint under a new clean namespace (`/api/v1/…`), not content-negotiation on auth_with_presentation (which stays as the cookie-shaped sibling of the same primitive).
- **Lifetime/refresh: short-lived (~1h), no refresh tokens.** Re-exchanging a fresh presentation IS the refresh. Token names the device-cert serial; every authorized call checks cert revocation status, so revoking the device kills its tokens with no extra bookkeeping.
- **Consent goes fully API-driven — warrant_respond is in the API.** Dan rejected visibility-only as theater, and the code agrees: approval is ALREADY a client-side signing ceremony (consent page signs each warrant with the config-cert key; consent.rs respond validates the signed warrants — the cookie only identifies the grantor). A key-holding client could always sign; the browser never enforced human presence. Reframed invariant: approval must carry device-key-signed warrants under the sender-constrained token (a signing ceremony, not a flag flip); human-in-the-loop is the trusted user agent's obligation (principle 8), not the registry's enforcement.
- **API family: one auth + error taxonomy, separate spec docs.** Registry spec defines presentation→token exchange, DPoP proof format, error taxonomy; the fallback-IdP spec (d0xb) references it.
- **Sequencing: this spec draft first**, gxi9 build next, then token endpoint + inbox as first API implementation, lbla as a rider, then d0xb.
- **Spec artifact:** docs/specs/registry-api-v1.md. Bar: independently implementable — wire examples per endpoint, single error taxonomy, explicit versioning rule.
- **Structural note:** browserid-registrar is already a separate crate with its own Store trait, mounted via registrar_glue.rs — the spec describes the registrar's surface as THE registry API; the broker is merely its first host.

## Work plan

- [x] Recon: exact wire shapes of the cookie-authed registry surface + spec house conventions (2026-08-28)
- [x] Spec skeleton: docs/specs/registry-api-v1.md — auth (token exchange + DPoP-style proof), endpoint inventory with legacy mapping, error taxonomy, invariants, open questions
- [x] Dan reviewed skeleton; all §10 questions resolved (decision log in spec). #5 confirmed WITH cookie-lane alignment (bean ig9p). Discovery merged into the /.well-known/browserid support document as a registry key (no separate document).
- [x] Fleshed out: wire examples per endpoint, §7.1 machine-reason enumeration, normative holder/namespace grammars, 204/200 response conventions (2026-08-28)
- [x] Adversarial review pass (fresh-eyes agent, 2026-08-28): 15 findings (3 high), all fixed — v1-warrant bootstrap coherence, per-kind consent validation bars, normative account resolution (self-presentation required, reason delegated_presentation), same-origin discovery endpoints + single-use exchange, htu/audience canonicalization, token-endpoint abuse controls, consent decision added to §10 log, all 'as today' references replaced with normative behavior, cross-ref corrections (core §4 typ rule). All handoff security invariants verified HELD.
- [x] Implement: token exchange + proof verification + first consumer (inbox GET) — landed 2026-08-27: `/api/v1/token` + DPoP-proof extractor + `GET /api/v1/requests` in browserid-registrar/src/api.rs (host verification via PresentationVerifier trait, glue in registrar_glue.rs); api_tokens in BOTH stores (sqlite migration v33) + explicit sqlite round-trip test; in-memory replay cache (proof jtis + exchange assertions); registry key on /.well-known/browserid; ig9p phase 1 (dialog.js broker-audience warrants carry registry scope; broker logs scopeless); 7 integration tests incl. live-listener full-verification flow (tests/registry_api_test.rs)
- [ ] Remaining §5 endpoints over the token lane: requests/respond + requests/claim, warrants (list/register/revoke/forget/allocate_status), devices (list/revoke/status), holders + namespaces (§5.4)

**§10 #7 RESOLVED (Dan, 2026-08-28): self-issued (secondary-identity) presentations ACCEPTED at the token exchange.** Rationale: the cookie lane rightly rejects them because a session is full account control including the password root that secondary certs derive from; the token's authority is scope-bounded to registry ops (no root ops in this API), a strict subset — so acceptance mints less than the session the cookie lane refuses. Per-scope gate: every future scope in the token family must re-justify self-issued acceptance (obligation recorded on d0xb). Practical win: secondary-only wallets get the token lane immediately, without waiting for d0xb.

Deferred SHOULDs from §3.1 (not yet implemented, 2026-08-27): per-source/per-identity rate limiting on the exchange (429 + Retry-After); inbox long-poll `wait` (ignoring it is conformant). Note for future tests: full server-side presentation verification in broker tests needs a REAL listener (tests/registry_api_test.rs `live_broker()`) — the axum_test harness can't serve the localhost well-known self-discovery, and fallback_idp_test step 9 only ever exercised the failure path.
