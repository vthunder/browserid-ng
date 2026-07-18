# browserid end-to-end flow (canonical reference)

Status: living reference. Current design as of 2026-07-18 (device-cert model,
3 cert types). Supersedes the earlier 3-cert "user-signed provisioning cert"
sketch. The durable credentials are all **IdP-signed**.

`OPEN:` marks a point still to be decided.

## Terminology: two senses of "broker"

- **Client broker** — software operating the **user's keystore on a device**.
  Holds device certs, mints access certs, and can sign warrants locally if the
  device holds a config cert.
- **Hosted broker (browserid.me)** — fallback IdP, hosted verifier, and the
  warrant **registry / revocation UI / RP status endpoints**. It records warrants
  for revocation/status. It MAY also hold a **config cert server-side** (a
  deployment convenience, not a protocol requirement).

## Device certs: two orthogonal fields (purpose × subject)

Every credential the RP relies on is **IdP-issued**. A device cert carries two
orthogonal fields (verifiers **fail closed** on unknown values of either):

- **purpose**: `authentication` (mints access request tokens → access certs) or
  `authorization` (signs warrants). This is the least-privilege axis: **logging
  in ≠ authorizing.**
- **subject**: `user`, `agent`, or blank/any — which *kind* of identity the cert
  acts for. Same axis the warrant ranges over.

The three common combinations (with shorthand names used below):

| Shorthand | purpose | subject | can sign | RP sees? |
|---|---|---|---|---|
| **user cert** | authentication | user | access request token → access cert | no |
| **agent cert** | authentication | agent | access request token → access cert | no |
| **config cert** | authorization | (blank/any) | warrant | yes (verifies it) |

Other combinations are legal and useful: `authorization + user` is a
**self-scoped config cert** (may author warrants only for your own logins, not
agents); `authorization + agent` may authorize only agents. `authentication`
normally carries a concrete subject (a login device is `user`; an agent device is
`agent`). An `authentication` cert can **only** mint access request tokens (never
warrants); an `authorization` cert can **only** sign warrants (never mint access
certs).

Plus the two RP-facing objects:

| Object | Signed by | RP sees? |
|---|---|---|
| **Access cert** — certifies a **fresh key**; the assertion chains from it | IdP mint API | yes |
| **Warrant** — authorizes **(identifier, subject) → audience[+scopes]** | a config cert | yes |

**Config-cert placement (protocol-agnostic storage choice):**
- **Server-side at the hosted broker** (convenient default): the broker issues
  warrants on the user's behalf. A compromised broker already runs the login UI +
  keystore, so this doesn't meaningfully weaken security.
- **Client-side on the user's main machines**: the paranoid keep config certs off
  the server; other machines hold only a user cert (login there, but can't
  authorize new grants).

**What the RP sees:** access cert (fresh key) + assertion + warrant + the **config
cert** that signed the warrant. It never sees a user or agent device cert.

```
config cert → Warrant ───────────────────────┐
IdP → Access cert (fresh key) → Assertion ────┘→ RP checks BOTH
(user/agent device certs stay private: device/broker ↔ IdP only)
```

---

## Stage 1 — Device-certificate issuance (bootstrap)

Cold start; user has never touched this RP, browserid, or the broker.

1. Arrive at RP, click **login**. The client broker opens (browserid.me), asks
   for an email; discovery on the domain (`_browserid` DNSSEC + `.well-known`).
2. The device generates a **device keypair** (ideally non-extractable), in the keystore.
3. **No primary** → the **fallback IdP** (browserid.me) SMTP-verifies the email
   and issues certs (iss: `browserid.me`). **Primary** → the client broker opens
   the domain's login page; the user authenticates; the **domain IdP** issues
   certs (iss: the domain). `OPEN:` return transport (no hidden iframe).
4. The IdP issues this device a **user device cert** (login: mints access request
   tokens), certifying the device key with metadata: **identities** (one/many/
   wildcard, all from this IdP), **type**, **validity** (IdP decides; broker MAY
   request a preference). A **config cert** (to author warrants) is issued
   separately and need not live on every device — server-side at the broker by
   default, or momentarily on a main machine (Stage 3).

### Agent variant
The agent's device keypair is generated **off-browser**; the agent can't
authenticate to the IdP, so the **user authorizes** issuance and the **IdP issues
the agent device cert directly** (no user-signed intermediary — the IdP must
issue the access cert anyway):
- The agent's device pubkey flows to the IdP **via the client broker** (device-
  grant / pairing; `agent_provision.rs` is the basis). `OPEN:` confirm transport.
- The user approves an **agent device cert** with chosen identities (maybe a
  wildcard) + validity. It is agent-typed → mints access tokens only, never warrants.
- The IdP signs it; the agent mints access certs headlessly thereafter. The
  warrant authorizing the agent is issued separately by the user's **config cert**.

---

## Stage 2 — Access-certificate minting

1. The holder (client broker or agent) signs an **access request token** with its
   user/agent device key, naming the target identity + a **fresh access pubkey**,
   and posts it to the IdP's **mint API** (+ `OPEN:` optional cookies — never
   *required*, or cross-origin ITP returns).
2. The IdP verifies the device cert (own signature, unrevoked, in-validity,
   identity in its list) and returns a short-lived **access cert** certifying the
   fresh access key. It **may refuse** even a nominally-valid device cert
   (abuse/compromise) → error → re-login.

No registrar/endorsement step. The access cert certifies a **fresh** key, so
user/agent device certs never leave the device/broker↔IdP channel.

**Why online + IdP-discretionary:** the IdP gates every access cert and can
refuse/revoke → short access certs stay meaningful, IdP keeps control, no cookie
(survives ITP), headless (agents).

---

## Stage 3 — Warrant (issued by a config cert, over identity+type)

A warrant is **always** present at the RP. It authorizes an **(identifier,
subject) → audience [+ scopes]** — e.g. "`danmills+agent@sandmill.org`, subject
`user`, may sign into `https://mingo.place/`". Crucially it is **over the
identifier + subject, not bound to any device/access key.** Consequences:

- Signed **once** by a **config cert** (which need exist only momentarily, on a
  main machine or server-side), then **stored** (hosted broker registry) and
  **reused device-agnostically**: any device that can mint an access cert for that
  identity presents the stored warrant alongside it. A login-only device (user
  cert, no config cert) just fetches the stored warrant — this is what dissolves Q12.
- **Long-lived**, independent of any single device cert; re-stamping the config
  key lets a warrant outlive the config cert that signed it (renew to keep it live).
- **Not a secret:** a leaked warrant is useless without a matching IdP-minted
  access cert for that identity, so warrants can be stored/served openly.
- **User login:** default scopes for the RP (auto, first time). **Agent:** user
  picks scopes/restrictions at consent. Either way the config cert signs it once.
- **Registry / revocation / status:** the hosted broker stores warrants (`jipx`),
  hosts the revocation UI, and serves the RP status endpoint; revoking a warrant
  (or its config cert) cuts off the grant within the status cache window.

---

## Stage 4 — Login / access at the RP

1. Sign a login **assertion** for the RP's audience with the **access key**.
2. Present **access cert + assertion + warrant + the config cert**. User/agent
   device certs are not presented.
3. The RP verifies, DNSSEC-rooted: access cert + assertion (→ this fresh key
   speaks for identity X, subject user, at this audience) **and** the warrant (→
   X, subject user, is authorized for this audience + scopes), **joining the two
   by (identity, subject, audience)** — the warrant is not key-bound; the access
   cert supplies the key→identity binding. It checks revocation of the access cert
   (IdP) and the warrant/config cert (hosted broker). Or posts to the hosted
   `/verify` for convenience.

**Breaking change (accepted):** every RP processes a warrant on every login.
Unifies the user/agent path; not backward-compatible.

---

## Properties

- **Least privilege:** login (user cert) is separate from authorization (config
  cert); a compromised login-only device can't authorize grants.
- **ITP:** device certs replace the session cookie as the mint credential →
  cookie-free minting → survives third-party-cookie/iframe death.
- **Agents:** first-class; an agent is a device with an agent-typed device cert;
  its warrant comes from the user's config cert.
- **Config placement is a choice:** server-side broker (convenient) or client
  main machines (minimize broker trust) — same protocol.
- **IdP one-time:** IdP roots issuance of all cert types but is not in the
  per-warrant or per-login-assertion loop.
- **Long-lived warrants:** issued directly by the long-lived config cert.
- **Device-agnostic warrants:** a warrant is over (identity, subject, audience),
  signed once, stored, and reused by any device presenting an access cert for
  that identity — not key-bound, not secret. Authentication (access cert,
  per-device, key-bound) and authorization (warrant, identity-bound, reusable)
  are cleanly separated.

---

## Conformance (required) & verification

**Every IdP MUST implement** device-cert issuance (both `authentication` and
`authorization` purposes) and the access-cert mint API. Not optional:

- **No-primary domains** are served by a **fallback IdP** (browserid.me), which
  issues device + access certs itself (iss: the fallback).
- **Domains with a primary** MUST have that primary implement the full API. The
  fallback **cannot** issue on a primary's behalf — a fallback-issued cert for a
  domain that already has a primary fails verification (issuer mismatch). So a
  non-conformant primary means its users simply cannot log in via browserid until
  it adopts the endpoints. (This is the sharp end of "agents as a required core
  verb": login and agents ride the same mandatory API.)

**Verification (RP's choice, unspecified by the protocol):** the RP **receives or
discovers** the signed bundle — access cert + assertion + warrant + config cert —
and either verifies the DNSSEC-rooted chain itself, or outsources to a convenience
verifier at its own discretion. browserid.me continues to run such a verifier, as
it does today. The protocol specifies *what the RP receives*, not *how it verifies*.

---

## Open questions (remaining)

- **Q5 — Cookies at mint:** optional-only (confirmed); define what they add.
- **Q8 — Transports (no hidden iframe):** domain-primary device-cert return leg;
  agent device-cert pairing hand-off.

Resolved: Q1/Q2 (warrants signed by config certs, held server-side or on-device),
Q3 (access cert = fresh key; user/agent device certs hidden), Q4 (multi-identity/
wildcard), **Q6 (conformance REQUIRED — fallback can't issue for a domain with a
primary; non-conformant primary → its users can't log in)**, Q7 (mandatory
warrants — yes), **Q9 (RP receives/discovers the signed bundle and verifies it
itself or outsources to a convenience verifier at its discretion; protocol doesn't
specify; browserid.me runs one)**, Q10 (long-lived warrants via config cert), Q11
(only the config cert is RP-visible), Q12 (warrants over (identity, subject,
audience), not key-bound), agent issuance (IdP-issued, user-authorized).

---

## Delta vs. what was built (Phases 1–3, the demo) — SUPERSEDED

- Built: a **user-signed** provisioning cert + `subject` axis on a user
  constraint + registrar endorsement + a **plain login cert with no warrant**.
- New: **three IdP-issued device-cert types** (user/agent mint access request
  tokens → access certs; config mints warrants) + direct IdP mint on a **fresh
  key** + an **always-present config-signed warrant**.
- Carries over: `subject` self/agent → device-cert **type** (user vs agent);
  D2's "self is privileged" → cert-**type** capability separation, IdP-controlled
  at issuance; online-mint principle (no registrar). The `/demo-self-login` page +
  Phase-1/2 core+broker changes will be re-cut against this model.
