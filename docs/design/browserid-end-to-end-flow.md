# browserid end-to-end flow (protocol overview)

A short overview of how identity, authentication, and authorization move through
browserid — for the uninitiated. It is organized around the **actors**, the
**artifacts** they exchange, and the **ceremonies** (stages) that produce them.
Build/migration details live in the migration plan
(`docs/plans/2026-07-18-device-cert-model-migration-plan.md`).

## Actors

Three roles matter to the protocol. (The two senses of "broker" below are
client/hosted *infrastructure*, not identity actors.)

- **IdP** — a domain authoritative for its own identities. It issues **device
  certs** (which let a device prove an identity, optionally constrained to certain
  identities) and runs the **mint API**; a device cert with `purpose:
  authorization` (a *config cert*) additionally lets its holder **grant
  permissions** for that identity. A domain that publishes a `_browserid` DNSSEC
  record is its own **primary** IdP; domains that don't are served by the
  **fallback** IdP (browserid.me).
- **Grantor** — an identity holder who *authorizes* permissions for their identity
  by signing a **warrant** with a config cert. A grantor is always pinned to an
  IdP authoritative for that identity (its config cert's issuer).
- **Grantee** — an identity holder who *acts*: accesses a resource or takes an
  action, presenting an **access cert + assertion** that prove live control of the
  grantee identity. In a plain self-login the grantor and grantee are the **same**
  identity; they differ for a delegated ("on behalf of") grant, and the two
  identities may even live at **different IdPs**.

Key asymmetry: when signing a warrant the grantor may name **any** grantee; at
presentation the grantee is **fixed** — the presented access cert's identity must
equal the warrant's grantee.

## Artifacts

All four objects an RP relies on are **IdP-signed or IdP-chained**; the RP never
sees a (authentication) device cert.

| Artifact | Issued/signed by | Suggested lifetime | Carries | RP sees? |
|---|---|---|---|---|
| **Device cert** (`authentication`) | IdP | durable (90d) | a holder; the identities it may act for | no |
| **Config cert** = device cert (`authorization`) | IdP | durable (90d) | a holder; the identities it may grant for | yes |
| **Access cert** | IdP mint API | short (24h) | a **fresh key** + the device's holder, for one identity | yes |
| **Assertion** | the fresh access key | very short | one audience | yes |
| **Warrant** | a **config cert** | long-lived | grantor → grantee, holder-matcher, audience [+scopes] | yes |

Lifetimes are **protocol suggestions / our implementation defaults**, not fixed —
each issuer MAY choose its own validity window when it signs.

The **presentation bundle** an RP receives is exactly, tilde-joined:
`access_cert ~ assertion ~ warrant ~ config_cert`.

### Two senses of "broker"

- **Client broker** — software operating the **user's keystore on a device**.
  Holds device certs, mints access certs, signs warrants when the device holds a
  config cert, and **assigns this device's opaque `holder` id** (below). It talks
  to IdPs **directly** — there is no server-to-server broker↔IdP channel.
- **Hosted broker (browserid.me)** — the fallback IdP, a hosted verifier, and the
  warrant **registry / revocation UI / status endpoints**. It also owns the
  account's **holder namespaces** (browsers / agents / services) and **records**
  every issued device cert + warrant for the central revocation UI. It records; it
  does not sign warrants.

### Holders

Each device cert (and, copied at mint, each access cert) carries an opaque,
high-entropy **`holder`** id naming *which of your things* is acting — a browser
("Main Laptop"), an agent, a service — organized into user-private namespaces
(`browsers` / `agents` / `services`) via a randomized `<ns>.<rand>` prefix. It is
**assigned by the client broker**, reused across **every identity on that device**
(one browser ⇒ one holder), and treated as **opaque passthrough** by IdPs (signed
verbatim, copied device→access at mint). A malicious browser could forge its own
holder — out of scope (it already owns the keystore); the isolation that matters
is between *separate* non-browser parties (service 1 vs service 2), whose holders
the broker assigns at provisioning so neither can name the other's. See
`docs/plans/2026-07-20-holder-authorization-model.md`.

### More on device/config certs

A device cert carries two orthogonal fields:

- **purpose**: `authentication` (mints access request tokens → access certs) or
  `authorization` (signs warrants) — the least-privilege axis: logging in ≠
  authorizing.
- **holder**: the opaque broker-assigned id (above) — *which of your things* holds
  this cert. Copied into the access cert at mint; a warrant ranges over it via a
  matcher.

An `authentication` cert can only mint access request tokens; an `authorization`
(config) cert can only sign warrants. All device certs — browser, agent, or
service — are the same shape; the **holder** (and its namespace) says which is
which, opaquely. Verifiers reject unknown `purpose` values and a missing/malformed
holder.

**Config certs are device-resident and non-extractable** (like access certs),
issued by the identity's IdP **alongside the device cert at login** (one batch
request yields both). The browser signs its own login warrant locally with its
config cert; the signed warrant then syncs to the hosted-broker registry for
device-agnostic reuse.

### How a warrant is rooted (the grantor binding)

A warrant names a **grantor** (the identity the action is attributed to) and a
**grantee** (the identity allowed to act). It is signed by a **config cert**, and
that config cert **must be issued by the grantor's own IdP** — DNSSEC-rooted,
subject to primary/fallback conformance (a fallback-issued config cert for a
domain that *has* a primary fails). The grantee's access cert is **independently**
rooted in the grantee's own IdP. The two IdPs need not be the same: safety comes
from **each issuer being authoritative for its own identity** — issuer X can only
ever attribute a write to an identity X vouches for — not from forcing
`config.iss == access.iss`.

> An earlier design *did* force `config.iss == access.iss`. That equality happened
> to block cross-issuer forgery, but only as a side effect, and it also blocked
> legitimate delegation (an `@sandmill.org` agent acting on behalf of an
> `@bsky.browserid.me` handle). It is superseded by the per-identity authority
> rule above. **Note for implementers:** the core `verify()` does *not* itself
> enforce that each issuer is authoritative for its identity — it returns the
> `(grantor, grantor-issuer)` and `(grantee, grantee-issuer)` pairs and the
> caller's key resolver must enforce the binding. Getting this wrong re-opens
> attribution forgery (see the audit, `browserid-ng-25kf`/`browserid-ng-kh0j`).

---

## Stage 1 — Device-certificate issuance (bootstrap)

Cold start; the user has never touched this RP, browserid, or the broker.

1. Arrive at RP, click **login**. The client broker opens (browserid.me) and asks
   for an email; it does discovery on the domain (`_browserid` DNSSEC +
   `.well-known`). The interactive step uses the existing **WinChan popup** channel
   — a first-party popup, not a hidden cross-origin iframe.
2. The device generates a **device keypair** (ideally non-extractable), in the
   keystore. The client broker also determines **this device's `holder`** — one per
   browser, reused across identities: it fetches the account's `browsers` namespace
   prefix from the hosted broker and generates `<prefix>.<rand>` on first use, then
   stores it in the keystore and reuses it thereafter.
3. **No primary** → the **fallback IdP** (browserid.me) verifies control of the
   email (an SMTP challenge, or another supported proof of control where
   applicable) and issues cert(s) (iss: `browserid.me`). **Primary** →
   the popup opens the domain's login page; the user authenticates; the **domain
   IdP** issues cert(s) (iss: the domain).
4. The IdP issues one or more device certs for this device. The client broker's
   request includes the **holder**, which the IdP treats as opaque passthrough
   (signs it verbatim). A single request may ask for **several at once** — e.g. a
   **device cert** (for login) plus a **config cert** — each certifying its key with
   metadata: identities (one/many/wildcard, all from this IdP), purpose, holder,
   validity. Both certs of a browser device carry the same holder.

Output: durable, IdP-signed device cert(s) in the keystore ("your logged-in
device"; revoke one to log that device/agent out).

### Agent variant
An agent's device keypair is generated **off-browser**. The agent can't
authenticate to the IdP, so the **user authorizes** issuance and the **IdP issues
the agent device cert directly**: the agent's pubkey flows to the IdP via the
client broker (a device-grant / pairing hand-off), the user approves the
constraints (identities, validity, and the holder — a broker-assigned id in the
user's `agents`/`services` namespace, which the agent cannot choose), and the IdP
signs it. The agent then mints access certs headlessly.

---

## Stage 2 — Access-certificate minting

1. The client broker (or agent) signs an **access request token** with its
   `authentication` device key, naming the target identity + a **fresh access
   pubkey** (and echoing the device cert's holder), and posts it to the IdP's
   **mint API**. The IdP copies the device cert's holder into the access cert.
2. The IdP verifies the device cert (own signature, unrevoked, in validity,
   identity in its list) and returns a short-lived **access cert** certifying the
   fresh access key. It **may refuse** even a nominally-valid device cert
   (abuse/compromise); the user then re-logs-in.

The access cert certifies a **fresh** key, so the device cert never leaves the
device/broker↔IdP channel. The IdP gates every access cert online, so short access
certs stay meaningful, no session cookie is needed (survives ITP), and agents work
headless.

---

## Stage 3 — Warrant

A warrant is **always** present at the RP. It authorizes a **grantor → grantee**
delegation over a **holder-matcher → audience [+ scopes]** — e.g.
"`danmills@sandmill.org` (grantor) authorizes `danmills@sandmill.org` (grantee),
holders matching `browsers.*`, to sign into `https://mingo.place/`". The matcher is
`*` (any holder), `<ns>.*` (a namespace — logins use this), or `<id>` (one isolated
holder — a specific service). A warrant is over the grantor/grantee + matcher,
**not** bound to any device/access key. So:

- It is signed **once** by the grantor's **config cert**, then **stored** (hosted
  broker registry) and **reused device-agnostically**: any device that can mint an
  access cert for the grantee presents the stored warrant alongside it. (This
  device-agnostic reuse is *why* a warrant is signed by the long-lived config cert
  rather than a short-lived access cert — the grantor is not acting and has no
  liveness to prove at presentation.)
- It is **long-lived**, independent of any single device cert.
- It is **not a secret** — a leaked warrant is useless without a matching
  IdP-minted access cert, so a user may publish an individual warrant without harm
  (the SBO on-chain case publishes it as part of the verification bundle). The only
  concern is **bulk** publication or enumeration of a user's warrants, which in
  aggregate discloses which sites and services they use.
- **User login:** grantor == grantee, default scopes for the RP, auto.
  **Delegated/agent:** the grantor picks the grantee, scopes, and restrictions at
  consent time.

The hosted broker stores issued warrants, hosts the revocation UI, and serves the
status endpoint RPs consult.

---

## Stage 4 — Login / access at the RP

1. The client broker (or agent) signs a login **assertion** for the RP's audience
   with the **access key**.
2. It presents **access cert + assertion + warrant + config cert** (the
   authentication device certs are not presented).
3. The RP verifies the DNSSEC-rooted path over **two independent issuer
   discoveries** — the **access cert** (its `iss` must be authoritative for the
   **grantee's** identity, conformance-checked) and the **config cert** (its `iss`
   must be authoritative for the **grantor's** identity, same conformance check) —
   then joins: access cert + assertion (→ this fresh key, held by holder H, speaks
   for the **grantee** identity at this audience) **and** the warrant (→ attributes
   to the **grantor**, allows any holder matching M, for this audience + scopes,
   signed by an IdP-issued `authorization` config cert for the grantor), **joining
   by (grantee == access-cert identity, holder H ∈ matcher M, audience)** and
   attributing the action to the grantor. It checks **three** revocation
   authorities via each object's status link: the **access cert** (→ IdP,
   per-*device* index so revoking one device kills its access certs), the **config
   cert** (→ its IdP), and the **warrant** (→ hosted broker). All three status
   checks are **fail-closed**.

The RP either verifies the bundle itself or outsources to a convenience verifier
(browserid.me runs one); the protocol specifies what the RP receives, not how it
verifies.

---

## Conformance

Every IdP **MUST** implement device-cert issuance (both `authentication` and
`authorization` purposes) and the access-cert mint API. No-primary domains are
served by the fallback IdP (browserid.me). A domain **with** a primary must have
that primary implement the full API — the fallback cannot issue on its behalf (a
fallback-issued cert for a domain that has a primary fails verification). So login
and agents ride one required API.

---

## Properties

- **Least privilege:** authentication (login) is separate from authorization
  (warrants); a compromised login-only device can't authorize grants.
- **ITP-proof:** device certs replace the session cookie as the mint credential →
  cookie-free minting.
- **Agents first-class:** an agent is a device with its own broker-assigned holder
  (in the `agents`/`services` namespace); humans and agents share the mint +
  presentation path — the holder, not a `subject` flag, says which is which.
- **Delegation across IdPs:** a warrant attributes to a grantor and empowers a
  grantee that may live at a different IdP; each issuer is authoritative only for
  its own identity.
- **IdP one-time:** the IdP roots all issuance but is not in the per-warrant or
  per-assertion loop.
- **Device-agnostic warrants:** authorization is over (grantor → grantee,
  holder-matcher, audience) — signed once, stored, reused; authentication (access
  cert, per-device, key-bound) stays separate.
- **Uniform RP path:** access cert + assertion + warrant + config cert for
  everything.
