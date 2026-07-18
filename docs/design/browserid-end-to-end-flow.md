# browserid end-to-end flow (canonical reference)

Status: living reference. Current design as of 2026-07-18 (device-cert model).
Supersedes the earlier 3-cert "user-signed provisioning cert" sketch, which had
two flaws: (a) it rooted a 90-day credential in a 24h identity cert + a registrar
record rather than a live IdP attestation; (b) it made the durable credential
user-signed, forcing a registrar-endorsement dance for the IdP to trust it. The
device-cert model fixes both: the durable credential is **IdP-signed**.

`OPEN:` marks a point still to be decided.

## The two certificates + the warrant

Everything the RP relies on is **IdP-signed**. There are two certificates and one
warrant. The RP sees the **access cert**, the **assertion**, the **warrant**, and
the broker's **warrant cert** — it does **not** see the minting device cert.

| Object | Lifetime | Signed by | Seen by RP? | Role |
|---|---|---|---|---|
| **Device certificate** | IdP-chosen (long) | the **IdP** (primary or fallback) | **no** | authorizes a *device* to request access certs for given identities; metadata: identities (one/many/wildcard), kind (self/agent), validity, may-sign-warrants |
| **Access certificate** | short (e.g. 24h) | the **IdP** mint API | yes | the RP-facing identity claim; certifies a **fresh access key**; the assertion chains from it |
| **Warrant** | short–medium | the **broker's** warrant-capable device cert | yes (+ the broker's cert) | authorization/scoping; **always** present |

**Key reframe (why a long-lived IdP-signed device cert is fine):** the device
cert is a **request token, not an RP-facing identity claim** — RPs never see it.
The IdP's long-lived signature only authorizes *requests*; every actual identity
claim is a short-lived access cert the IdP mints on demand and **may refuse**.

**Chains presented to the RP:**
```
broker device cert (may-sign-warrants) → Warrant ────────┐
IdP → Access cert (fresh access key) → Assertion ────────┘→ RP checks BOTH
(the user's / agent's minting device cert stays private: device/broker ↔ IdP only)
```

---

## Stage 1 — Device-certificate issuance (bootstrap)

Cold start; the user has never touched this RP, browserid, or the broker.

1. Arrive at RP, click **login**. The **broker** (browserid.me) opens, asks for
   an email.
2. Broker does **discovery** on the email domain (`_browserid` DNSSEC + `.well-known`).
3. The device generates a **device keypair** (ideally non-extractable).
4. **No primary** → the broker's **fallback IdP** verifies control of the email
   (SMTP challenge) and issues a **device cert** (iss: `browserid.me`).
   **Domain has a primary** → the broker opens the domain's login page; the user
   authenticates with their existing IdP credentials; the **domain IdP** issues a
   **device cert** (iss: the email domain). `OPEN:` the return transport for the
   domain-primary case (top-level redirect / popup / same-tab — not a hidden iframe).
5. The device cert certifies the device key with metadata: the **identities** it
   may request access certs for (one, several, or a wildcard — all from this same
   IdP), the **kind** (self-login vs agent), a **validity period** (IdP decides;
   broker MAY request a preference), and **may-sign-warrants** (normally false —
   see Stage 3).
6. **Broker warrant authorization.** As part of the authenticated bootstrap, the
   user authorizes the IdP to issue **the broker** a **may-sign-warrants** device
   cert for this identity, so the broker can warrant on the user's behalf (Stage
   3). For the fallback case (broker = IdP) this is internal; for a primary
   domain it is an explicit **IdP→broker** authorization the domain IdP must
   support.

Output: a durable, IdP-signed **device certificate** ("your logged-in device";
revoke it to log that device out), plus the broker's warrant authority for this
identity.

### Agent variant of Stage 1
The agent's device keypair is generated **off-browser**. The agent can't
authenticate to the IdP itself, so the **user authorizes** its issuance and the
**IdP issues it directly** (no user-signed intermediary — since the IdP must
issue the access cert anyway, a user-minted agent cert would buy nothing):
- The agent's device pubkey flows to the IdP **via the broker** (a device-grant /
  pairing hand-off; `agent_provision.rs` is the existing basis). `OPEN:` confirm transport.
- The authenticated user approves a device cert for the agent's key with a
  constraint they choose (identities — possibly several or a wildcard, kind =
  agent, **may-sign-warrants = false**, validity).
- The IdP signs the agent's device cert. The agent mints its own access certs
  headlessly thereafter.

---

## Stage 2 — Access-certificate minting

The device cert mints a short-lived **access cert** via an **online, IdP-operated**
mint API:

1. The holder (browser or agent) calls the IdP's **mint API** with its **device
   cert**, the target identity/kind, and a **fresh access pubkey** to certify
   (proving device-key possession by signing the request). `OPEN:` cookies MAY be
   sent as a bonus freshness signal — never *required*, or cross-origin ITP returns.
2. The IdP verifies the device cert (own signature, unrevoked, in-validity,
   identity in its list) and mints a short-lived **access cert** (iss: IdP)
   certifying the fresh access key for the requested identity. It **may refuse**
   even a nominally-valid device cert (abuse/compromise) → error → the user may
   re-login (re-bootstrap).

No registrar/endorsement step: the device cert is the IdP's own signature, so the
IdP mints directly from it. The access cert certifies a **fresh** key, so the
device cert never leaves the device/broker↔IdP channel.

**Why online + IdP-discretionary:** the IdP gates every access cert and can
refuse/revoke, so short access certs stay meaningful and the IdP keeps control —
with no session cookie (survives ITP) and headless (agents).

---

## Stage 3 — Warrant (issued by the broker)

A warrant is **always** present at the RP (so the access cert needs no
"warrant-required" flag). In principle any holder of a may-sign-warrants device
cert could sign one; **in practice only the broker does.**

- The **broker** holds a may-sign-warrants device cert (Stage 1.6) and **issues
  all warrants**: for a **user login**, auto-generated with default scopes for
  this RP (no user interaction); for an **agent**, with the scopes/restrictions
  the user selected at consent time (as today).
- The **broker hosts** the warrant registry, the **revocation UI**, and the
  **status endpoint** RPs consult. Revoking a warrant there cuts off the agent/
  login at RPs within the status cache window.
- IdPs **MAY** constrain may-sign-warrants device certs (shorter validity for
  shared machines, a per-identity count cap) — an allowed differentiation point,
  not a mandate; they are not expected to cap at 1.

Because warrants are signed by a long-lived broker device key, that cert carries
a **status ref** and RPs check it. `OPEN:` whether RPs verify the warrant chain
fully offline vs. query the broker's status endpoint (convenience-trust).

---

## Stage 4 — Login / access at the RP

1. The holder signs a login **assertion** for the RP's audience with the **access
   key**.
2. It presents **access cert + assertion + warrant** (+ the broker's warrant
   cert). The minting device cert is **not** presented.
3. The RP verifies, server-side, the DNSSEC-rooted path: access cert + assertion
   (→ this key speaks for identity X at this audience) **and** the warrant (→ X's
   broker authorizes this audience + scopes), checking revocation status of the
   access cert (IdP) and the warrant (broker). Or, for convenience only, it posts
   to the broker's hosted `/verify`.

**Breaking change (accepted):** every RP now processes a warrant on every login.
This unifies the user and agent path; it is not backward-compatible.

---

## Properties

- **ITP:** the device cert replaces the session cookie as the mint credential →
  cookie-free minting → survives third-party-cookie/iframe death.
- **Agents:** first-class — an agent is a device with a `may-sign-warrants=false`
  device cert; humans and agents share the mint + presentation path.
- **IdP control:** long-lived signature only on the (RP-invisible) request token;
  every identity claim is a short-lived IdP-gated access cert; the IdP can refuse
  any mint.
- **Broker role (deliberate, load-bearing):** the broker is the warrant authority
  (signs, revokes, serves status). User-chosen and replaceable, but concentrates
  warrant trust + availability in it.
- **Uniform RP path:** access cert + assertion + warrant for everything; the RP
  never sees a device cert except the broker's warrant cert.

---

## Open questions (remaining)

- **Q5 — Cookies at mint:** optional-only (confirmed); define what they add.
- **Q6 — Conformance:** classic primaries must add (a) device-cert issuance,
  (b) the access-cert mint API, and (c) issuing the broker a may-sign-warrants
  device cert. Require adoption, allow broker-mints-on-behalf, or stage both?
- **Q8 — Transports (no hidden iframe):** domain-primary device-cert return leg;
  agent device-cert pairing hand-off.
- **Q9 — RP-side warrant verification:** full offline chain vs. broker status
  query (convenience-trust), and how the RP roots the broker's warrant cert.
- **Q10 — Warrant lifetime:** short per-login vs. medium for agents (so a headless
  agent isn't forced back to the broker every access-cert refresh).

Resolved: Q1 (broker signs warrants), Q2 (broker is the practical authority; IdPs
may constrain), Q3 (access cert certifies a fresh key; device cert hidden from
RP), Q4 (multi-identity/wildcard device certs), Q7 (mandatory warrants — yes),
agent issuance (IdP-issued, user-authorized, no user-signed intermediary).

---

## Delta vs. what was built (Phases 1–3, the demo) — SUPERSEDED

The built code does **not** match this design and needs re-cutting:
- Built: a **user-signed** provisioning cert + `subject` axis on a user
  constraint + registrar endorsement + a **plain login cert with no warrant** +
  D2 on the user constraint.
- New: an **IdP-signed device cert** (identities/kind/validity/may-sign-warrants
  as IdP metadata) + direct IdP mint of an access cert on a **fresh key** + an
  **always-present broker-signed warrant**.
- Carries over conceptually: `subject` self/agent → device-cert **kind**; D2's
  "self is privileged" → the IdP's control of **kind + may-sign-warrants** at
  issuance; online-mint principle (now without a registrar). The `/demo-self-login`
  page and the Phase-1/2 core+broker changes will be re-cut against this model.
