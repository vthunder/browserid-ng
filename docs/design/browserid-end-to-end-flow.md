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

## Three device-cert types + the access cert + the warrant

Every credential the RP relies on is **IdP-issued**. Device certs are
**capability-typed**:

| Cert | Type can sign | Signed by | Seen by RP? |
|---|---|---|---|
| **User device cert** | an **access request token** (→ access cert) | IdP | no |
| **Agent device cert** | an **access request token** (→ access cert) | IdP | no |
| **Config device cert** | a **warrant** | IdP | yes (verifies the warrant) |
| **Access cert** | an assertion | IdP mint API | yes; certifies a **fresh key** |
| **Warrant** | (the presented authorization) | a **config cert** | yes |

- **User / agent certs** can *only* mint access request tokens, exchanged online
  at the IdP for short-lived **access certs**. They can **not** issue warrants.
- **Config certs** can *only* issue **warrants** (long-lived; the config cert is
  long-lived and issues them directly). They can **not** mint access certs.
- Separation = least privilege: **logging in ≠ authorizing.** A login-only device
  holds just a user cert; only a config-cert holder can authorize grants.

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
4. The IdP issues, for this device/identity:
   - a **user device cert** (login: mints access request tokens);
   - `OPEN:` (Q12) a **config cert** — where? server-side at the broker by
     default, and/or a self-scoped config cert to this device so it can warrant
     its own login (see Q12).
   Each cert certifies the relevant key with metadata: **identities** (one/many/
   wildcard, all from this IdP), **type**, **validity** (IdP decides; broker MAY
   request a preference).

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

## Stage 3 — Warrant (issued by a config cert)

A warrant is **always** present at the RP; it is issued by a **config cert** and
is **long-lived** (the config cert is long-lived; re-stamping the config key can
let warrants outlive a single config cert — renew to keep them working).

- **User login:** a warrant with default scopes for this RP, signed by a config
  cert (server-side broker, or a self-scoped config cert on the device — Q12).
- **Agent:** the user selects scopes/restrictions at consent time; the user's
  config cert signs a warrant authorizing the agent identity + audience + scopes.
- **Registry / revocation / status:** the hosted broker records issued warrants
  (`jipx`), hosts the revocation UI, and serves the RP status endpoint. Warrants
  carry a status ref; revoking one (or the config cert) cuts off the grant within
  the status cache window.

---

## Stage 4 — Login / access at the RP

1. Sign a login **assertion** for the RP's audience with the **access key**.
2. Present **access cert + assertion + warrant + the config cert**. User/agent
   device certs are not presented.
3. The RP verifies, DNSSEC-rooted: access cert + assertion (→ this key speaks for
   identity X at this audience) **and** the warrant (→ X's config cert authorizes
   this audience + scopes), checking revocation of the access cert (IdP) and the
   warrant/config cert (hosted broker). Or posts to the hosted `/verify` for
   convenience.

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

---

## Open questions (remaining)

- **Q5 — Cookies at mint:** optional-only (confirmed); define what they add.
- **Q6 — Conformance:** classic primaries must add device-cert issuance (user +
  config types) and the access-cert mint API. Require adoption vs. hosted-broker/
  fallback covers non-conformant domains vs. staged.
- **Q8 — Transports (no hidden iframe):** domain-primary return leg; agent pairing.
- **Q9 — RP-side warrant verification:** full offline chain vs. hosted status
  query; how the RP roots the config cert.
- **Q12 — Login-only devices vs. always-warrant (the live tension):** a device
  with only a user cert can't sign its own login warrant. Options: (a) server-side
  broker config cert signs login warrants (server-side config becomes the de-facto
  default); (b) exempt pure self-login from the warrant rule (weakens uniformity);
  (c) issue every login device a **self-scoped** config cert (login device can
  warrant only itself; full config certs, for authorizing agents/others, stay on
  main machines / server). Leaning (c).

Resolved: Q1/Q2 (warrants signed by config certs, held server-side or on-device),
Q3 (access cert = fresh key; user/agent device certs hidden), Q4 (multi-identity/
wildcard), Q7 (mandatory warrants — yes), Q10 (long-lived warrants via config
cert), Q11 (only the config cert is RP-visible), agent issuance (IdP-issued,
user-authorized).

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
