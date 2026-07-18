# browserid end-to-end flow (canonical reference)

Status: living reference. Captures the intended flow (as described 2026-07-18),
verified against the implementation + spec, with the built-vs-intended deltas
called out. Refer to this often; keep it current.

There are **three certificates** in play. Naming them precisely is the whole
game, because the intended-flow language ("provisioning cert") maps onto a
specific one of them, and the confusion is about *who signs the long-lived one*.

| Cert | Lifetime | Signed by | Certifies | Role |
|---|---|---|---|---|
| **Identity cert** (`U_cert`) | ~24h | the **IdP** (email domain, or browserid.me fallback) | the user's identity key `U` | the ordinary login cert; the root of a delegation |
| **Provisioning cert** (`P_cert`) | ~90d | the **user's key `U`** (self-signed delegation), registered at the registrar | a provisioning key `P` + a `constraint` (subjects/names/patterns) | the durable credential ("the provisioning cert") |
| **Access cert** | ~24h | the **IdP**, via `/provision/mint` (registrar-endorsed) | an access key (login key, or the agent's key) | signs assertions the RP verifies |

**The single most important fact:** the long-lived provisioning cert is
**signed by the user, not the IdP.** The IdP only ever signs ≤24h certs
(the `U_cert` and access certs). It stays in control of the durable credential
through the **registrar** (it registered the delegation; it endorses every
mint; revoking the registration stops all future mints) — not through a
long-lived signature. This is exactly the "IdPs shouldn't mint long-lived certs"
property, achieved without an IdP long-lived signature.

---

## Stage 1 — Provisioning-cert issuance (the one-time bootstrap)

Cold start; the user has never touched this RP, browserid, or the broker.

1. Arrive at RP, click **login**.
2. The **broker** (browserid.me) opens, asks for an email.
3. Broker does **discovery** on the email's domain (`_browserid` DNSSEC + `.well-known`).
4. **No primary for the domain** → the broker's **fallback IdP** verifies control
   of the email (SMTP challenge) and issues a `U_cert` (issuer: `browserid.me`).
   **Domain has a primary** → the broker opens the domain's provisioning/login
   page, sends the user's identity pubkey `U`; the user authenticates with their
   existing IdP credentials; the **domain IdP** issues a `U_cert` (issuer: the
   email domain).
5. In-browser, the user's key `U` **self-signs a `P_cert`** delegating to a fresh
   provisioning key `P`, scoped by a `constraint` (for human login:
   `subjects:[self]`). The browser holds `P` (ideally non-extractable).
6. The browser **registers** the delegation (`U_cert~P_cert`) at the registrar
   (browserid.me) while the `U_cert` is fresh. The registrar records the
   `U → P` delegation; from here on it can endorse mints without re-seeing `U_cert`.

Output: a **long-lived provisioning cert** (`U_cert~P_cert`, user-signed,
registrar-registered). This replaces "get a fresh 24h cert from the IdP every
time" with "hold one durable, constrained, revocable delegation."

### Agent variant of Stage 1
An agent's keypair is generated **off-browser**. To be authorized it must be
**delegated by the user**, because the IdP has no way to authenticate the agent
directly (the agent is not the user). So:
- The agent's provisioning pubkey flows **to the browser** (a device-grant /
  pairing hand-off — RFC-8628-style), not straight to the IdP.
- The user, in-browser, signs a `P_cert` delegating to the agent's key with a
  `constraint` they approve (`subjects:[agent]`, specific names/patterns).
- The registrar records it; the agent now holds `U_cert~P_cert` and can mint its
  own access certs headlessly.

The agent's "long-lived provisioning cert" is the **same object** as the human's
— a user-signed, registrar-registered delegation. There is **no IdP-issued
long-lived cert for the agent's key.** (This is why the delegation model is not
optional: it is the only way to authorize a key the IdP can't authenticate.)

---

## Stage 2 — Access-cert minting (from the provisioning cert)

The provisioning cert mints a ~24h **access cert**, and this is an **ONLINE,
endorsed** operation — *not* offline:

1. The holder (browser or agent) builds a short-lived request `R` (`action:mint`,
   `subject:self|agent`, target `domain`, the access pubkey, a `jti`), signed by
   the provisioning key `P`. Bundle = `U_cert~P_cert~R`.
2. `POST /provision/endorse` to the **registrar** → the registrar checks the
   `P_cert` is registered + unrevoked and returns a short-lived endorsement `E`
   bound to the exact bundle.
3. `POST /provision/mint` to the **IdP** → it verifies the chain + `E` and mints
   the ~24h access cert (`subject:self` → plain user cert for the user's email;
   `subject:agent` → agent cert attributed to the user).

**Why it is online (the answer to "what's the point / would IdPs hate offline
minting?"):** because the registrar endorses every mint, the IdP stays in
control — revoke the provisioning cert and endorsements stop, so no more access
certs can be minted (within the endorsement TTL). Offline minting would make the
provisioning cert an unrevocable bearer token and the 24h cert pointless; the
endorsed-online design is what makes short access certs meaningful **and**
palatable to IdPs. No session cookie is needed (survives ITP), and it works
headless (agents) — the two wins over the old iframe-session mint.

---

## Stage 3 — Login / access

1. With the ~24h access cert, the browser or agent signs a login **assertion**
   for the RP's audience → `access_cert ~ assertion` (agents additionally carry a
   user-signed **warrant** scoping the audience/scopes).
2. The RP takes the assertion server-side and **verifies the whole trust path**
   cryptographically (DNSSEC-rooted), or — for convenience only, if it chooses to
   trust it — posts to the broker's hosted `/verify`.

---

## Verification verdict (correctness)

- **Human login:** the intended flow is correct and matches the build, with one
  clarification — the "provisioning cert" is **user-signed + registrar-registered**,
  not IdP-signed. That distinction is what delivers the property the intended
  flow wants (IdP never signs long-lived certs).
- **Agents:** the intended flow's "agent pubkey flows to the IdP to mint the
  cert" is **imprecise**. The agent pubkey flows **to the browser** for the user
  to delegate (sign a `P_cert`); the agent then mints access certs at the IdP
  from that delegation. There is no IdP-issued long-lived agent cert. The
  delegation is mandatory precisely because the IdP cannot authenticate an
  agent's key on its own.
- **Offline concern:** valid, and resolved — Stage-2 minting is online + endorsed,
  so the IdP retains control and short access certs stay meaningful.
- **Conformance dependency:** Stage 2 requires the **domain IdP to serve the
  mint/endorse verbs**. Classic primaries that only do interactive login (e.g.
  sandmill.org today, `browserid-ng-3nsg`) can issue a `U_cert` but cannot mint
  access certs → the user would fall back to the broker or the domain must adopt
  the verbs. This is the conformance mandate (spec §9).

---

## Deltas vs. what was built (the demo + Phases 1–3)

1. **The demo skips Stage 1's cold start.** `/demo-self-login` requires an
   existing broker **session** (sign in at `/account` first) and issues the
   `U_cert` via `/wsapi/cert_key`. That is a shortcut standing in for
   "enter email → discovery → fallback SMTP / domain-IdP auth." The confusion
   ("why must I already have a cert at /account?") is justified — the real flow
   starts cold at the RP. **Mismatch: bootstrap ceremony.**
2. **The demo conflates the three stages on one page** and re-does the whole
   bootstrap every run (fresh U/P each click) instead of: bootstrap once → hold a
   durable provisioning cert → mint access certs per session. **Mismatch:
   provisioning cert is not actually persisted/reused as the durable credential.**
3. **No RP.** The demo is self-contained (mints + self-verifies). There is no
   cold "arrive at an RP, click login" entry point. **Mismatch: no RP-initiated
   flow / no broker dialog.**
4. **Correct parts:** the core mechanism is right — `subject:self` mint through
   `/provision/mint`, plain login cert, D2 capability enforcement, online
   endorsed mint, RP-verifiable assertion. Proven end-to-end in prod. The engine
   matches; the *entry point and lifecycle* do not.

---

## Open holes / questions to resolve (discussion)

- **H1 — Domain-primary mint support.** Classic primaries can't mint access
  certs. Do we (a) require them to adopt mint/endorse (conformance), (b) let the
  broker mint on their behalf (trust implications), or (c) both, staged?
- **H2 — Where does the provisioning cert live + its reuse lifecycle?** Persisted
  client-side (browser: IndexedDB + non-extractable `P`; agent: on disk). Re-mint
  access certs until `P_cert` expiry (~90d), then re-bootstrap. The demo doesn't
  model this yet.
- **H3 — The bootstrap hand-off transport.** For the domain-primary case, how
  does `U` + the domain-issued `U_cert` come back to the browser without the dead
  hidden iframe? (top-level redirect / popup / same-tab — the mingo-ytrs handshake.)
- **H4 — Agent pairing channel.** The device-grant that carries the agent's
  pubkey to the browser for delegation (exists as `agent_provision.rs`; confirm
  it fits Stage 1).
- **H5 — Revocation UX.** "Log out / deauthorize everywhere" = revoke the
  provisioning cert at the registrar. Endorsement TTL bounds the residual window.
- **H6 — Is the 3-cert structure the right shape, or should the intended
  2-cert framing (IdP-issued provisioning cert) be adopted instead?** The 3-cert
  (user-signed delegation) model is what makes agents work and keeps IdPs off
  long-lived signatures — but it is more moving parts. Decision to confirm.
