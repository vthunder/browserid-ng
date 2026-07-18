# browserid end-to-end flow (canonical reference)

Status: living reference. Current design as of 2026-07-18 (device-cert model).
Supersedes the earlier 3-cert "user-signed provisioning cert" sketch, which had
two flaws: (a) it rooted a 90-day credential in a 24h identity cert + a registrar
record rather than a live IdP attestation; (b) it made the durable credential
user-signed, forcing a registrar-endorsement dance for the IdP to trust it. The
device-cert model fixes both: the durable credential is **IdP-signed**.

`OPEN:` marks a point still to be decided.

## The two certificates + the warrant

Everything the RP sees is **IdP-signed**. There are two certificates and one
warrant.

| Object | Lifetime | Signed by | Role |
|---|---|---|---|
| **Device certificate** | IdP-chosen (long, e.g. weeks) | the **IdP** (primary or fallback) | authorizes a *device* to request access certs for given identities; carries metadata (identities, kind, validity, may-sign-warrants) |
| **Access certificate** | short (e.g. 24h) | the **IdP**, via the mint API | the RP-facing identity claim; the assertion chains from it |
| **Warrant** | short | a **warrant-capable device cert** | authorization/scoping; **always** present at the RP |

**Key reframe (why a long-lived IdP-signed device cert is fine):** the device
cert is a **request token, not an RP-facing identity claim.** RPs fail closed on
it (never accept it as proof of identity). So the IdP's long-lived signature only
authorizes *requests*; every actual identity claim is a short-lived access cert
the IdP mints on demand and **may refuse** (abuse/compromise). Long-lived
authorization + short-lived, IdP-gated claims.

**Chains presented to the RP:**
```
device cert (may-sign-warrants)                → Warrant ─┐
device cert (iss: IdP) → Access cert (iss: IdP) → Assertion ┘→ RP checks BOTH
```

---

## Stage 1 — Device-certificate issuance (bootstrap)

Cold start; the user has never touched this RP, browserid, or the broker.

1. Arrive at RP, click **login**.
2. The **broker** (browserid.me) opens, asks for an email.
3. Broker does **discovery** on the email domain (`_browserid` DNSSEC + `.well-known`).
4. The device generates a **device keypair** (ideally non-extractable).
5. **No primary** → the broker's **fallback IdP** verifies control of the email
   (SMTP challenge) and issues a **device cert** (iss: `browserid.me`).
   **Domain has a primary** → the broker opens the domain's login page; the user
   authenticates with their existing IdP credentials; the **domain IdP** issues a
   **device cert** (iss: the email domain). `OPEN:` the return transport for the
   domain-primary case (top-level redirect / popup / same-tab — not a hidden iframe).
6. The device cert certifies the device key with metadata: the **identities** it
   may request access certs for, the **kind** of access cert (self-login vs
   agent), a **validity period** (IdP decides; the broker MAY request a
   preference), and **may-sign-warrants** (true for a user's own login device;
   false for an agent).

Output: a durable, IdP-signed **device certificate**. This is "your logged-in
device" — revoking it logs that device out everywhere.

### Agent variant of Stage 1
The agent's device keypair is generated **off-browser**. The agent cannot
authenticate to the IdP itself, so the **user authorizes** its issuance:
- The agent's device pubkey flows to the IdP **via the broker** (a device-grant /
  pairing hand-off; `agent_provision.rs` is the existing basis). `OPEN:` confirm
  this transport.
- The authenticated user approves a device cert for the agent's key with a
  constraint they choose (identities, kind = agent, **may-sign-warrants =
  false**, validity). `OPEN:` the IdP MAY limit how many may-sign-warrants
  device certs exist per identity.
- The IdP signs the agent's device cert. The agent now holds it and can mint its
  own access certs headlessly.

So the agent's durable credential is an **IdP-signed device cert too** — same
object class as the human's, just with `may-sign-warrants = false`.

---

## Stage 2 — Access-certificate minting

The device cert mints a short-lived **access cert** via an **online, IdP-operated**
mint API:

1. The holder (browser or agent) calls the IdP's **mint API** with its **device
   cert** (+ `OPEN:` optionally session cookies as a bonus freshness signal —
   never *required*, or cross-origin ITP returns) and the identity/kind it wants.
2. The IdP verifies the device cert (its own signature, unrevoked, in-validity)
   and mints a short-lived **access cert** (iss: IdP) for the requested identity.
   It **may refuse** even a nominally-valid device cert (device abusive /
   compromised) → error → the user may be required to re-login (re-bootstrap a
   device cert).

No registrar/endorsement step: the device cert is the IdP's own signature, so the
IdP mints directly from it. `OPEN:` what key the access cert certifies — the
device key reused, or a fresh per-session access key the mint certifies.

**Why online + IdP-discretionary (answers "what's the point / palatable to
IdPs?"):** the IdP gates every access cert and can refuse/revoke, so short access
certs stay meaningful and the IdP keeps control. It needs no session cookie
(survives ITP) and works headless (agents) — the two wins over the old
iframe-session mint.

---

## Stage 3 — Warrant

A warrant is **always** present at the RP (so the access cert needs no
"warrant-required" flag — one always is). It is signed by a **warrant-capable
device cert**.

- **User login:** the warrant is auto-generated (default scopes for this RP), no
  user interaction. `OPEN:` who signs it — the user's own may-sign-warrants
  device key, or the broker centrally? (Interacts with whether every login device
  is warrant-capable, or only a primary one.)
- **Agent:** the user manually selects scopes/restrictions (as today), and the
  warrant is signed by the **user's** may-sign-warrants device cert (the agent's
  own device cert cannot sign warrants). The warrant names the agent identity +
  audience + scopes.

Because warrants may be signed offline by a long-lived device key, the device
cert carries a **status ref** and the **RP checks its revocation** when verifying
the warrant.

---

## Stage 4 — Login / access at the RP

1. The holder signs a login **assertion** for the RP's audience with the access
   cert's key.
2. It presents **access cert + warrant + assertion** (and the warrant-signing
   device cert, so the RP can check the warrant signature).
3. The RP verifies, server-side, the whole DNSSEC-rooted path: the access cert +
   assertion (→ this key speaks for identity X at this audience) **and** the
   warrant (→ X, via an IdP-blessed warrant-capable device, authorizes this
   audience with these scopes), checking both certs' revocation status. Or, for
   convenience only and if it chooses to trust it, it posts to the broker's
   hosted `/verify`.

**Breaking change:** every RP now processes a warrant on every login (previously
human logins were a plain `cert~assertion`). This unifies the user and agent
verification path but is not backward-compatible.

---

## Properties

- **ITP:** the device cert replaces the session cookie as the mint credential →
  cookie-free minting → survives third-party-cookie/iframe death.
- **Agents:** first-class — an agent is just a device with a `may-sign-warrants =
  false` device cert; humans and agents share the mint + presentation path.
- **IdP control:** long-lived signature only on the request token; every
  identity claim is a short-lived, IdP-gated access cert; revoke the device cert
  to cut off both minting and (via status check) its warrants.
- **Uniform RP path:** access cert + warrant + assertion for everything.

---

## Open questions (consolidated)

- **Q1 — Self-login warrant signer:** the user's own device key vs. the broker.
- **Q2 — Warrant-capability distribution:** every login device warrant-capable
  (so it can self-sign its login warrant) vs. a limited/primary one only (then
  self-login warrants must come from the broker).
- **Q3 — Access-cert key:** reuse the device key vs. a fresh per-session key.
- **Q4 — Device cert scope:** per-identity vs. multi-identity; is
  kind/warrant-capability per-identity within a multi-identity cert?
- **Q5 — Cookies at mint:** optional-only (must be), and what they add.
- **Q6 — Conformance (H1):** classic primaries must add device-cert issuance +
  the mint API. Require adoption, allow broker-mints-on-behalf, or stage both?
- **Q7 — Mandatory warrants:** confirm the RP-breaking uniform-warrant change.
- **Q8 — Bootstrap/pairing transport:** domain-primary return leg + agent
  device-cert pairing hand-off (no hidden iframe).

---

## Delta vs. what was built (Phases 1–3, the demo)

The **built code does NOT match this design** and needs rework:
- Built: a **user-signed** provisioning cert (`P_cert`) + `subject` axis on a
  user constraint + registrar endorsement + a **plain login cert with no
  warrant** (D1) + D2 capability on the user constraint. → Superseded.
- New: an **IdP-signed device cert** (kind/identities/validity/may-sign-warrants
  as IdP metadata) + direct IdP mint (no endorsement) + an **always-present
  warrant** (D1 reversed).
- What carries over conceptually: the `subject` self/agent distinction becomes
  the device cert's **kind**; D2's "self is a privileged capability" becomes the
  IdP's control over **kind + may-sign-warrants** at device-cert issuance; the
  online-mint principle stands (now without a registrar). The `/demo-self-login`
  page and the Phase-1/2 core+broker changes will need to be re-cut against the
  device-cert model.
