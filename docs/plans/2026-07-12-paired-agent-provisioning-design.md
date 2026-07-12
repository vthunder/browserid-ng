# Paired agent provisioning — design (bean 74u1)

## Problem

Every step of the agent lifecycle has a protocol except the *first* one. Warrant
consent is a clean device-grant flow (request → `verification_uri` → poll →
pickup). But obtaining the initial **agent credential** has none: the human goes
to `/agents`, the browser generates a provisioning keypair, and the **private
key** is downloaded as `agent-credential.json` and handed to the agent
out-of-band. The demo papers over the handoff by polling `~/Downloads`.

We standardize the bootstrap as a pairing flow that mirrors warrant consent, and
— crucially — **the agent generates the provisioning keypair itself**, so no
private key ever transits browserid.me or a file.

## Two modes (one signing page)

Both modes are the *same* signing UI; they differ only in **where the
provisioning public key comes from**:

| | Paired (default) | Portable (advanced) |
|---|---|---|
| Provisioning key born in | the **agent** | the **browser** |
| Private key ever leaves origin | **no** | yes — downloaded as a file |
| Best for | a present, interactive agent bootstrapping itself | provision-here-deploy-there, headless/air-gapped, thin/non-SDK, batch |
| Handoff | poll → delegation (public) | download JSON (secret) |

Paired is the prominent path (SDK `bootstrap()`, wallet `provision` tool).
Portable stays as an explicit, clearly-labeled "this file contains a private
key" escape hatch. Keeping both is cheap because the verify page is shared — the
paired flow is just its "an agent is present (code `X`)" branch.

## Paired flow

```
agent (holds provisioning privkey)                 browser (human, authenticated)        broker
  │ generate provisioning keypair                                                         │
  ├──POST /agent-provision/request ─────────────────────────────────────────────────────▶│  create pending record
  │   { provisioning_pubkey, requested_handles?, label?, hint? }                          │  code = "aprv_…"
  │◀── { code, verification_uri, interval, expires_in } ───────────────────────────────── │
  │ show verification_uri to human ───────────────▶ opens /agent-provision/<code>         │
  │                                                  reviews: pubkey fp, requested handles │
  │                                                  picks delegating identity, edits      │
  │                                                  handles, reissue/new                  │
  │                                                  identity key SIGNS delegation over    │
  │                                                  the AGENT's provisioning pubkey ──────▶│  register delegation +
  │                                                  (session-auth) reserve handles ───────▶│  reserve (session-auth),
  │                                                                                         │  store result on record
  ├──POST /agent-provision/poll { code } (loop) ───────────────────────────────────────── ▶│  single-delivery
  │◀── { status:"completed", credential:{delegation, broker, idp, names, patterns} } ───── │
  │ assemble Credential locally (held privkey + delegation) → ready Agent                   │
```

### Endpoints (mirror `warrant/request` + `warrant/poll`)

`POST {broker}/agent-provision/request`
```jsonc
// request
{ "provisioning_pubkey": { "algorithm":"Ed25519", "publicKey":"<b64url>" },
  "requested_handles": { "names": ["researcher"], "patterns": [] },  // optional hint; human can edit
  "label": "my research agent",                                       // optional, shown to human
  "hint": "agent@host" }                                              // optional, shown for recognition
// response
{ "success": true, "code": "aprv_…",
  "verification_uri": "https://browserid.me/agent-provision/aprv_…",
  "expires_in": 900, "interval": 5 }
```

`POST {broker}/agent-provision/poll`
```jsonc
// request
{ "code": "aprv_…" }
// responses
{ "status": "pending" }
{ "status": "denied" }
{ "status": "expired" }
{ "status": "completed",
  "credential": { "delegation": "<U_cert>~<P_cert>", "broker": "https://browserid.me",
                  "idp": "https://mingo.place", "names": ["researcher"], "patterns": [] } }
```
Same discipline as consent: HTTP 410 → expired, 429 → poll-too-fast (treat as
pending), record single-delivery and deleted on completed pickup, rate-limited
per code, `cleanup_expired` on request.

### The `/agent-provision/<code>` page

Reuses the account/consent signing stack. On load (authenticated; if not, prompt
sign-in first):
1. Fetch the pending record; show **label/hint**, the **provisioning-key
   fingerprint** (so a human who is intentionally pairing can confirm it matches
   what their agent displayed — the device-grant anti-phishing confirmation), and
   the **requested handles**.
2. Human picks the delegating identity (their activated identities), edits the
   handles (add/remove/patterns), sees reissue-vs-new per handle.
3. Their **identity key signs the `P_cert`** over the **agent-supplied**
   provisioning public key + the final constraint (this is the only crypto the
   page does; it never generates a provisioning key in paired mode).
4. Session-authenticated: **register** the delegation (`register_provisioning_cert`)
   and **reserve** the handles (see below), then **store the result** on the
   pending record so the agent's poll returns it.
5. "Approve" / "Deny" — Deny marks the record denied.

### Reservation at verify time

Today reservation (`/provision/reserve`, `agent.rs`) is proven by a
**provisioning-key-signed** request bundle — fine when the *agent* reserves, but
the browser in the paired flow does not hold that key. Since the human is
authenticated, reservation here is **session-authenticated**: fold it into the
delegation registration (reserve the constraint's `names` for the account) or add
a sibling session-authed reserve. This preserves create-time handle locking
without the provisioning key. (Analysis of the current reuse/reissue semantics —
handles are account-scoped, idempotent for the owner, revocation sticks — is in
the session notes; the page surfaces those choices.)

## Data model — pending provision record

Mirror `WarrantRequestRecord`:
```
AgentProvisionRecord {
  code, provisioning_pubkey, requested_names, requested_patterns, label, hint,
  status: pending | completed | denied,   // + implicit expired via expires_at
  result_delegation, result_idp, result_names, result_patterns,  // filled on completion
  created_at, expires_at, last_poll_at
}
```
Single-delivery: deleted when a `completed` poll hands the credential over.

## Security properties

- **No secret transit / storage.** The provisioning private key is generated by
  and never leaves the agent. The browser and broker only ever handle **public**
  keys and **signed certs**.
- **The poll result is not a secret.** The returned delegation is public and
  useless without the provisioning private key (which only the requesting agent
  holds). So interception of the poll response grants nothing — a strictly
  stronger property than the download flow.
- **Binding.** The delegation is signed over the *agent-supplied* provisioning
  pubkey, cryptographically tying the credential to the agent that initiated the
  code.
- **Phishing (device-grant class).** The risk is tricking a human into completing
  an attacker-initiated code, yielding an agent identity delegated from the
  human. Mitigations: the page states plainly "*An agent is asking to act for you
  as `<handle>@domain`*," shows the **key fingerprint** for intentional-pairing
  confirmation, requires explicit approval, and — critically — a provisioned agent
  **still cannot act anywhere without separate per-audience warrant consent**, so
  the blast radius is "an extra revocable identity under your account," not access
  to any RP. Rate-limit request creation; short code TTL; the human can revoke.
- **Reuses consent hardening**: code entropy, expiry, single-delivery, poll rate
  limiting, arming/anti-clickjacking on the approve button.

## SDK + tooling

`@browserid/agent`:
```js
const { verificationUri, ready } = await Agent.bootstrap({
  broker: "https://browserid.me", requestedHandles: { names: ["researcher"] }, label: "my agent",
});
console.log("Approve at:", verificationUri);
const agent = await ready;          // resolves when the human completes; polls internally
await agent.save("agent.identity.json");
```
Internally: generate provisioning keypair → `/agent-provision/request` → return
`verificationUri` + a `ready` promise that polls `/agent-provision/poll` and
assembles the `Credential` + `Agent`.

Wallet MCP server: a **`provision`** tool returning `PROVISION_URL: <uri>`, then
`get_assertion`/`identity` work as before. This **deletes the `~/Downloads`
discovery hack** for the paired path (discovery stays only for the portable mode).

## Compatibility / migration

- Portable download stays, unchanged, behind an "advanced" affordance on `/agents`.
- Existing credentials keep working (unchanged wire formats).
- No verifier/RP changes — provisioning output is the same delegation shape.

## Open questions

1. **Code display** — URL only, or also a short human-typeable code + fingerprint
   confirmation (stronger anti-phishing, more steps)? Lean: URL + show fingerprint
   on the page; optionally echo it from the agent.
2. **Reservation home** — fold into `register_provisioning_cert`, or a separate
   session-authed `reserve`? Lean: fold in (one authenticated action).
3. **Unauthenticated start** — the page must handle "not signed in": sign in, then
   resume the code. Reuse the dialog/session gate.
4. **Relation to a dedicated agent domain (0phq)** — the `idp`/`idpDomain` the
   record returns should come from the delegating identity's issuer; if agents
   move to `agents.browserid.me`, this flow inherits it with no shape change.

## Sequencing

Design (this) → broker endpoints + record store → `/agent-provision/<code>` page
(reuse account signing) → `@browserid/agent` `bootstrap()` → wallet `provision`
tool → docs. Build the happy path first (single identity, no reissue edits), then
the edit/reissue affordances.
