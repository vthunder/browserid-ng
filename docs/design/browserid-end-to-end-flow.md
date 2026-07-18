# browserid end-to-end flow (protocol overview)

A short overview of how identity, authentication, and authorization move through
browserid — for the uninitiated. Build/migration details live in the migration
plan (`docs/plans/2026-07-18-device-cert-model-migration-plan.md`).

## Two senses of "broker"

- **Client broker** — software operating the **user's keystore on a device**.
  Holds device certs, mints access certs, and signs warrants when the device
  holds a config cert.
- **Hosted broker (browserid.me)** — the fallback IdP, a hosted verifier, and the
  warrant **registry / revocation UI / status endpoints**. It records warrants;
  it does not sign them.

## Credentials

Everything the RP relies on is **IdP-issued**. A device cert carries two
orthogonal fields:

- **purpose**: `authentication` (mints access request tokens → access certs) or
  `authorization` (signs warrants) — the least-privilege axis: logging in ≠ authorizing.
- **subject**: `user`, `agent`, or blank/any — which *kind* of identity it acts
  for. The same axis a warrant ranges over.

Common combinations (with the shorthand names used below):

| Shorthand | purpose | subject | can sign | RP sees? |
|---|---|---|---|---|
| **user cert** | authentication | user | access request token → access cert | no |
| **agent cert** | authentication | agent | access request token → access cert | no |
| **config cert** | authorization | (blank/any) | warrant | yes |

`authorization + user` is a self-scoped config cert (authors warrants only for
your own logins); `authorization + agent` authorizes only agents. An
`authentication` cert can only mint access request tokens; an `authorization`
cert can only sign warrants. Verifiers reject unknown `purpose`/`subject` values.

Plus the two RP-facing objects:

| Object | Signed by | RP sees? |
|---|---|---|
| **Access cert** — certifies a **fresh key**; the assertion chains from it | IdP mint API | yes |
| **Warrant** — authorizes **(identifier, subject) → audience[+scopes]** | a config cert | yes |

A **config cert must be issued by the identity's own IdP** — `config_cert.iss ==
domain(identity)`, DNSSEC-rooted, subject to the same primary/fallback conformance
as the access cert (a fallback-issued config cert for a domain that has a primary
fails). Without this binding an RP would accept a warrant signed by *any*
authorization cert from *any* IdP — a privilege-escalation hole. So a config cert
can only live **server-side at the hosted broker for fallback (no-primary)
identities** (which the broker already fully controls as their IdP); for a
**primary** identity the config cert is issued by that primary and is
**device-resident** (non-extractable), never broker-held. Storage is a choice
*within* those bounds, not across them.

The RP sees the access cert (fresh key) + assertion, and the warrant + the config
cert that signed it; it never sees a user/agent (authentication) cert.

---

## Stage 1 — Device-certificate issuance (bootstrap)

Cold start; the user has never touched this RP, browserid, or the broker.

1. Arrive at RP, click **login**. The client broker opens (browserid.me) and asks
   for an email; it does discovery on the domain (`_browserid` DNSSEC + `.well-known`).
   The interactive step uses the existing **WinChan popup** channel — a
   first-party popup, not a hidden cross-origin iframe.
2. The device generates a **device keypair** (ideally non-extractable), in the keystore.
3. **No primary** → the **fallback IdP** (browserid.me) verifies control of the
   email (SMTP challenge) and issues cert(s) (iss: `browserid.me`). **Primary** →
   the popup opens the domain's login page; the user authenticates; the **domain
   IdP** issues cert(s) (iss: the domain).
4. The IdP issues one or more device certs for this device. A single request may
   ask for **several at once** — e.g. a **user cert** (for login) together with
   one or more **agent certs** — each certifying its key with metadata:
   identities (one/many/wildcard, all from this IdP), purpose, subject, validity.

Output: durable, IdP-signed device cert(s) in the keystore ("your logged-in
device"; revoke one to log that device/agent out).

### Agent variant
An agent's device keypair is generated **off-browser**. The agent can't
authenticate to the IdP, so the **user authorizes** issuance and the **IdP issues
the agent device cert directly**: the agent's pubkey flows to the IdP via the
client broker (a device-grant / pairing hand-off), the user approves the
constraints (identities, subject `agent`, validity), and the IdP signs it. The
agent then mints access certs headlessly.

---

## Stage 2 — Access-certificate minting

1. The holder (client broker or agent) signs an **access request token** with its
   `authentication` device key, naming the target identity + a **fresh access
   pubkey**, and posts it to the IdP's **mint API**.
2. The IdP verifies the device cert (own signature, unrevoked, in validity,
   identity in its list) and returns a short-lived **access cert** certifying the
   fresh access key. It **may refuse** even a nominally-valid device cert
   (abuse/compromise); the user then re-logs-in.

The access cert certifies a **fresh** key, so the device cert never leaves the
device/broker↔IdP channel. The IdP gates every access cert online, so short
access certs stay meaningful, no session cookie is needed (survives ITP), and
agents work headless.

---

## Stage 3 — Warrant

A warrant is **always** present at the RP. It authorizes an **(identifier,
subject) → audience [+ scopes]** — e.g. "`danmills+agent@sandmill.org`, subject
`user`, may sign into `https://mingo.place/`". It is over the identifier +
subject, **not** bound to any device/access key. So:

- It is signed **once** by a **config cert**, then **stored** (hosted broker
  registry) and **reused device-agnostically**: any device that can mint an access
  cert for that identity presents the stored warrant alongside it.
- It is **long-lived**, independent of any single device cert.
- It is **not a secret** — a leaked warrant is useless without a matching
  IdP-minted access cert. But warrants **should not be intentionally published or
  made easily queryable**, because in aggregate they disclose which sites and
  services a user uses.
- **User login:** default scopes for the RP, auto. **Agent:** the user picks
  scopes/restrictions at consent time.

The hosted broker stores issued warrants, hosts the revocation UI, and serves the
status endpoint RPs consult.

---

## Stage 4 — Login / access at the RP

1. The holder signs a login **assertion** for the RP's audience with the **access key**.
2. It presents **access cert + assertion + warrant + config cert** (the
   user/agent device certs are not presented).
3. The RP verifies the DNSSEC-rooted path over **two independent issuer
   discoveries** — the **access cert** (`iss` must be the identity's IdP,
   conformance-checked) and the **config cert** (`iss` must *also* be the
   identity's IdP, same conformance check) — then: access cert + assertion (→ this
   fresh key speaks for identity X, subject user, at this audience) **and** the
   warrant (→ X, subject user, authorized for this audience + scopes, signed by an
   IdP-issued `authorization` config cert for X), **joining by (identity, subject,
   audience)**. It checks **three** revocation authorities via each object's
   status link: the **access cert** (→ IdP, per-*device* index so revoking one
   device kills its access certs), the **config cert** (→ its IdP), and the
   **warrant** (→ hosted broker). All three status checks are **fail-closed**.

The RP either verifies the bundle itself or outsources to a convenience verifier
(browserid.me runs one); the protocol specifies what the RP receives, not how it
verifies.

---

## Conformance

Every IdP **MUST** implement device-cert issuance (both `authentication` and
`authorization` purposes) and the access-cert mint API. No-primary domains are
served by the fallback IdP (browserid.me). A domain **with** a primary must have
that primary implement the full API — the fallback cannot issue on its behalf (a
fallback-issued cert for a domain that has a primary fails verification). So
login and agents ride one required API.

---

## Properties

- **Least privilege:** authentication (login) is separate from authorization
  (warrants); a compromised login-only device can't authorize grants.
- **ITP-proof:** device certs replace the session cookie as the mint credential →
  cookie-free minting.
- **Agents first-class:** an agent is a device with an `agent`-subject cert;
  humans and agents share the mint + presentation path.
- **IdP one-time:** the IdP roots all issuance but is not in the per-warrant or
  per-assertion loop.
- **Device-agnostic warrants:** authorization is over (identity, subject,
  audience) — signed once, stored, reused; authentication (access cert,
  per-device, key-bound) stays separate.
- **Uniform RP path:** access cert + assertion + warrant for everything.
