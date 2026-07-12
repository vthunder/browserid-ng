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
// response — all entry points; the agent shows whichever fits its context
{ "success": true, "code": "aprv_…",
  "verification_uri": "https://browserid.me/link",              // type user_code here (headless/cross-device)
  "verification_uri_complete": "https://browserid.me/agent-provision/aprv_…", // one-click (desktop)
  "user_code": "WXYZ-1234",                                     // short, typeable
  "fingerprint": "4F-2A-9C",                                    // of provisioning_pubkey; confirm on the page
  "expires_in": 900, "interval": 5 }
```
Desktop agents surface `verification_uri_complete` (one click). Headless/remote
agents print `user_code` for the human to type at `verification_uri`. The verify
page shows `fingerprint` for pairing confirmation.

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

### The verify page — a MODE of `/account`, reached by `<code>` or a typed `user_code`

It is **not a new page**: it's the existing account/agents UI with a pending-code
context layered on, so a brand-new user can complete first-time setup in-flow
(the common path). On entry (`/agent-provision/<code>` or `/link` after entering a
`user_code`):
1. **Auth / new-user gate.** If not signed in → sign up / sign in. If the user has
   no usable identity yet → **add email → verify → activate** inline (reusing
   account.html), because delegating from a just-added email is the normal
   brand-new-user path. Also covers "signed in but this identity's key isn't in
   this browser" (same gate the consent page uses).
2. Show **label/hint**, the **fingerprint** of the agent's provisioning key (for
   pairing confirmation), and the **requested handles**.
3. Human picks the delegating identity, edits handles (add/remove/patterns), sees
   reissue-vs-new per handle.
4. Their **identity key signs the `P_cert`** over the **agent-supplied**
   provisioning public key + final constraint (the only crypto the page does; it
   never generates a provisioning key in paired mode).
5. Session-authenticated: **register** the delegation
   (`register_provisioning_cert`) and **reserve** the handles (see below), then
   **store the result** on the pending record for the agent's poll.
6. "Approve" / "Deny" — Deny marks the record denied.

### Reservation — a standalone primitive, two auth modes

Reservation is a single `reserve(handles)` operation, decoupled from registration,
reached two ways:
- **session-authenticated** — the logged-in human reserves their own handles;
  used by this verify page and by the future reservation-only web flow.
- **provisioning-key-authenticated** — the agent reserves under its constraint;
  the existing `/provision/reserve` (`agent.rs`), unchanged.

Both hit the same underlying logic (`ensure_agent_identity`). Keeping it a
primitive (rather than folding it into registration) preserves agent-suggested
names (a `requested_handles` hint the human confirms), agent-driven reservation,
and the reservation-only flow. Create-time locking holds because the paired flow
reserves at the moment the human approves. (Reuse/reissue semantics — handles
account-scoped, idempotent for the owner, revocation sticks — surfaced on the
page.)

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
const pairing = await Agent.bootstrap({
  broker: "https://browserid.me", requestedHandles: { names: ["researcher"] }, label: "my agent",
});
// pairing: { verificationUri, verificationUriComplete, userCode, fingerprint, ready }
console.log("Approve at:", pairing.verificationUriComplete);        // desktop: one click
// or, headless:  `Go to ${pairing.verificationUri} and enter ${pairing.userCode}`
const agent = await pairing.ready;   // resolves when the human completes; polls internally
await agent.save("agent.identity.json");
```
Internally: generate provisioning keypair → `/agent-provision/request` → return
the entry points + a `ready` promise that polls `/agent-provision/poll` and
assembles the `Credential` + `Agent`. The wallet `provision` tool surfaces the
same fields for the agent to show the human.

Wallet MCP server: a **`provision`** tool returning `PROVISION_URL: <uri>`, then
`get_assertion`/`identity` work as before. This **deletes the `~/Downloads`
discovery hack** for the paired path (discovery stays only for the portable mode).

## Compatibility / migration

- Portable download stays, unchanged, behind an "advanced" affordance on `/agents`.
- Existing credentials keep working (unchanged wire formats).
- No verifier/RP changes — provisioning output is the same delegation shape.

## Resolved decisions (2026-07-12)

1. **Entry points — return all of them; the agent picks by context (like OAuth
   device flow).** The `request` response carries `verification_uri` (clickable),
   `user_code`, and `verification_uri_complete` (URL with the code baked in), plus
   a provisioning-key **fingerprint**:
   - Desktop / local agent → show the clickable URL → **one click** (the smooth
     path is never given up).
   - Headless / remote agent (server, CI, no browser) → print `user_code`; the
     human types it at `{broker}/link` on their own device. This cross-device
     case — not anti-phishing — is the primary reason for the code.
   - The **fingerprint** is shown on the verify page and (optionally) by the agent
     as an "is this the agent I meant" confirmation.
   `/link` is a thin page: resolve a typed `user_code` → the same verify page.

2. **Reservation is a standalone primitive with two auth modes — NOT folded into
   registration.** One `reserve(handles)` operation, reached by:
   - **session-auth** — the logged-in human reserves their own handles (paired
     verify page + the future reservation-only web flow, bean for that filed),
   - **provisioning-key-auth** — the agent reserves under its constraint (the
     existing `/provision/reserve`).
   Registration stays decoupled from reservation. This preserves agent-suggested
   names (a `requested_handles` hint the human confirms), agent-*driven*
   reservation, and the reservation-only flow with a single reusable primitive.
   Create-time locking holds because the paired flow reserves at human approval.

3. **The verify page is a MODE of the existing `/account` (or `/agents`) UI, and
   must support new-user setup in-flow.** Adding + verifying + activating a new
   email and delegating from it is the **common** path for a brand-new user, not
   an edge case. So the page reuses account.html's add-email / activate-identity /
   create-agent machinery with the pending-code context layered on: sign up/in →
   add email → verify → activate → select as delegator → approve. This also
   subsumes "signed in but this identity's key isn't in this browser" (same gate
   the consent page uses).

4. **Agent domain (0phq):** `idp`/`idpDomain` comes from the delegating identity's
   issuer; if agents move to `agents.browserid.me`, this flow inherits it in one
   place with no shape change. No v1 action.

## Sequencing

Design (this) → broker endpoints + record store → `/agent-provision/<code>` page
(reuse account signing) → `@browserid/agent` `bootstrap()` → wallet `provision`
tool → docs. Build the happy path first (single identity, no reissue edits), then
the edit/reissue affordances.
