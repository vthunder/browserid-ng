# browserid end-to-end flow (canonical reference)

Status: living reference. Current design as of 2026-07-18 (device-cert model).
Supersedes the earlier 3-cert "user-signed provisioning cert" sketch (which
rooted a 90-day credential in a 24h identity cert + a registrar record, and made
the durable credential user-signed). The durable credential is now **IdP-signed**.

`OPEN:` marks a point still to be decided.

## Terminology: two senses of "broker"

- **Client broker** — software that operates the **user's keystore on each
  device**. It holds the device certs, mints access certs, and **signs warrants
  locally** with the user's key. Warrant signing is on-device; no remote party
  signs on the user's behalf.
- **Hosted broker (browserid.me)** — the fallback IdP, the hosted verifier, and
  the warrant **registry / revocation UI / RP status endpoints**. It *records*
  warrants for revocation/status; it does **not** sign them.

## The two certificates + the warrant

Everything the RP relies on is **IdP-signed**.

| Object | Lifetime | Signed by | Seen by RP? | Role |
|---|---|---|---|---|
| **Device certificate** | IdP-chosen (long) | the **IdP** (primary or fallback) | only the warrant-signing one | authorizes a *device* to request access certs; metadata: identities (one/many/wildcard), kind (self/agent), validity, may-sign-warrants |
| **Access certificate** | short (e.g. 24h) | the **IdP** mint API | yes | RP-facing identity claim; certifies a **fresh access key**; the assertion chains from it |
| **Warrant** | short–medium | the **user's** warrant-capable device cert (in the device keystore the client broker operates) | yes | authorization/scoping; **always** present |

**Key reframe:** a device cert is a **request token, not an RP-facing identity
claim.** The IdP's long-lived signature only authorizes *requests*; every actual
identity claim is a short-lived access cert the IdP mints on demand and **may
refuse**.

**What the RP sees vs. doesn't:**
- Sees: the **access cert** (fresh key) + **assertion**, and the **warrant** +
  the **warrant-signing device cert** that signed it.
- Does **not** see: any **minting-only** device cert — notably the agent's
  (`may-sign-warrants=false`) cert stays private (device/broker ↔ IdP). For
  self-login the user's device cert is both minting- and warrant-capable, so it
  is visible via the warrant; the access cert still certifies a separate fresh key.

```
user's warrant-capable device cert → Warrant ───────────┐
IdP → Access cert (fresh access key) → Assertion ───────┘→ RP checks BOTH
```

---

## Stage 1 — Device-certificate issuance (bootstrap)

Cold start; the user has never touched this RP, browserid, or the broker.

1. Arrive at RP, click **login**. The client broker opens (hosted at
   browserid.me), asks for an email.
2. Discovery on the email domain (`_browserid` DNSSEC + `.well-known`).
3. The device generates a **device keypair** (ideally non-extractable), held in
   the device keystore.
4. **No primary** → the **fallback IdP** (browserid.me) verifies control of the
   email (SMTP challenge) and issues a **device cert** (iss: `browserid.me`).
   **Domain has a primary** → the client broker opens the domain's login page;
   the user authenticates; the **domain IdP** issues a **device cert** (iss: the
   domain). `OPEN:` return transport (top-level redirect / popup / same-tab — no
   hidden iframe).
5. The device cert certifies the device key with metadata: **identities** it may
   request access certs for (one, several, or a wildcard, all from this IdP),
   **kind** (self-login vs agent), **validity** (IdP decides; broker MAY request
   a preference), and **may-sign-warrants**. For a user's own login device the
   IdP sets **may-sign-warrants = true**; IdPs MAY constrain this (shorter
   validity on shared machines, a per-identity cap) as a differentiation point,
   but are not expected to cap at 1.

Output: a durable, IdP-signed **device cert** in the user's keystore ("your
logged-in device"; revoke it to log that device out).

### Agent variant of Stage 1
The agent's device keypair is generated **off-browser**. The agent can't
authenticate to the IdP itself, so the **user authorizes** its issuance and the
**IdP issues it directly** (no user-signed intermediary — since the IdP must
issue the access cert anyway, a user-minted agent cert would buy nothing):
- The agent's device pubkey flows to the IdP **via the client broker** (a
  device-grant / pairing hand-off; `agent_provision.rs` is the basis). `OPEN:` confirm.
- The authenticated user approves a device cert for the agent's key with the
  constraints they choose (identities — possibly several or a wildcard, kind =
  agent, **may-sign-warrants = false**, validity).
- The IdP signs it; the agent mints access certs headlessly thereafter.

---

## Stage 2 — Access-certificate minting

The device cert mints a short-lived **access cert** via an **online, IdP-operated**
mint API:

1. The holder (client broker or agent) calls the IdP's **mint API** with its
   **device cert**, the target identity/kind, and a **fresh access pubkey** to
   certify (proving device-key possession by signing the request). `OPEN:`
   cookies MAY be a bonus freshness signal — never *required*, or cross-origin
   ITP returns.
2. The IdP verifies the device cert (own signature, unrevoked, in-validity,
   identity in its list) and mints a short-lived **access cert** (iss: IdP)
   certifying the fresh access key. It **may refuse** even a nominally-valid
   device cert (abuse/compromise) → error → the user may re-login (re-bootstrap).

No registrar/endorsement step: the device cert is the IdP's own signature, so the
IdP mints directly from it. The access cert certifies a **fresh** key, so a
minting-only device cert never leaves the device/broker↔IdP channel.

**Why online + IdP-discretionary:** the IdP gates every access cert and can
refuse/revoke, so short access certs stay meaningful and the IdP keeps control —
with no session cookie (survives ITP) and headless (agents).

---

## Stage 3 — Warrant

A warrant is **always** present at the RP (so the access cert needs no
"warrant-required" flag). It is signed **on-device** by the **user's**
warrant-capable device cert, via the client broker operating the keystore.

- **User login:** the client broker auto-generates the warrant (default scopes
  for this RP, no user interaction) and signs it with the user's device key.
- **Agent:** the user selects scopes/restrictions at consent time (as today);
  the **user's** device signs the warrant authorizing the agent identity +
  audience + scopes. (The agent's own device cert is not warrant-capable, so it
  cannot self-warrant.)
- **Registry / revocation / status:** the hosted broker (browserid.me) *records*
  issued warrants (`jipx`), hosts the **revocation UI**, and serves the **status
  endpoint** RPs consult. Warrants carry a status ref pointing there; revoking one
  cuts off the login/agent at RPs within the status cache window.

`OPEN:` (Q9) whether the RP verifies the warrant chain fully offline vs. queries
the hosted status endpoint (convenience-trust), and how it roots the
warrant-signing device cert.

---

## Stage 4 — Login / access at the RP

1. The holder signs a login **assertion** for the RP's audience with the **access
   key**.
2. It presents **access cert + assertion + warrant + the warrant-signing device
   cert**. Minting-only device certs are not presented.
3. The RP verifies, server-side, the DNSSEC-rooted path: access cert + assertion
   (→ this key speaks for identity X at this audience) **and** the warrant (→ X's
   warrant-capable device authorizes this audience + scopes), checking revocation
   status of the access cert (IdP) and the warrant (hosted broker). Or, for
   convenience only, it posts to the hosted `/verify`.

**Breaking change (accepted):** every RP now processes a warrant on every login.
Unifies the user and agent path; not backward-compatible.

---

## Properties

- **ITP:** the device cert replaces the session cookie as the mint credential →
  cookie-free minting → survives third-party-cookie/iframe death.
- **Agents:** first-class — an agent is a device with a `may-sign-warrants=false`
  device cert; humans and agents share the mint + presentation path.
- **IdP control:** long-lived signature only on the request token; every identity
  claim is a short-lived IdP-gated access cert; the IdP can refuse any mint.
- **Decentralized signing:** warrants are signed on-device with the user's key
  (the client broker); the hosted broker only *records* them for revocation/
  status. No remote party signs on the user's behalf.
- **Uniform RP path:** access cert + assertion + warrant for everything; the only
  device cert an RP sees is the warrant-signing one.

---

## Open questions (remaining)

- **Q5 — Cookies at mint:** optional-only (confirmed); define what they add.
- **Q6 — Conformance:** classic primaries must add (a) device-cert issuance
  (incl. `may-sign-warrants` on the user's login device cert) and (b) the
  access-cert mint API. Require adoption, allow the hosted broker/fallback to
  cover non-conformant domains, or stage both?
- **Q8 — Transports (no hidden iframe):** domain-primary device-cert return leg;
  agent device-cert pairing hand-off.
- **Q9 — RP-side warrant verification:** full offline chain vs. hosted status
  query; how the RP roots the warrant-signing device cert.
- **Q10 — Warrant lifetime:** short per-login vs. medium for agents (so a headless
  agent isn't forced back to the client broker on every access-cert refresh).
- **Q11 — Confirm:** the warrant-signing device cert is unavoidably RP-visible
  (needed to verify the warrant); only minting-only device certs are hidden.

Resolved: Q1/Q2 (warrants signed on-device by the user's warrant-capable device
cert, operated by the client broker; hosted broker records/revokes/serves
status; IdPs may constrain warrant-capable certs), Q3 (access cert certifies a
fresh key; minting-only device certs hidden), Q4 (multi-identity/wildcard device
certs), Q7 (mandatory warrants — yes), agent issuance (IdP-issued, user-authorized,
no user-signed intermediary).

---

## Delta vs. what was built (Phases 1–3, the demo) — SUPERSEDED

The built code does **not** match this design and needs re-cutting:
- Built: a **user-signed** provisioning cert + `subject` axis on a user
  constraint + registrar endorsement + a **plain login cert with no warrant** +
  D2 on the user constraint.
- New: an **IdP-signed device cert** (identities/kind/validity/may-sign-warrants
  as IdP metadata) + direct IdP mint of an access cert on a **fresh key** + an
  **always-present warrant** signed on-device by the user's warrant-capable
  device cert.
- Carries over conceptually: `subject` self/agent → device-cert **kind**; D2's
  "self is privileged" → the IdP's control of **kind + may-sign-warrants** at
  issuance; online-mint principle (now without a registrar). The `/demo-self-login`
  page and the Phase-1/2 core+broker changes will be re-cut against this model.
