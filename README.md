<!-- This Source Code Form is subject to the terms of the Mozilla Public
   - License, v. 2.0. If a copy of the MPL was not distributed with this
   - file, You can obtain one at http://mozilla.org/MPL/2.0/. -->

# browserid-ng

**Identity for agents, answerable to humans** — an open, DNS-rooted protocol that
gives AI agents their own cryptographic identity, delegated from a human, scoped
to exactly where and what the human approved, and revocable at any time. Human
passwordless sign-in comes along for free.

Live at **[browserid.me](https://browserid.me)**. Descended from Mozilla
[Persona] / the [BrowserID protocol][], rebuilt in Rust and re-centered on agents.

[BrowserID protocol]: https://github.com/mozilla/id-specs
[Persona]: https://github.com/mozilla/persona

## Why

Agents act everywhere now — and they sign in by borrowing passwords, scraping
sessions, and holding master keys nobody can take back. browserid-ng gives an
agent an identity of its own:

- **Attributable** — every action traces to a specific agent *and* the human it
  acts for. No more "was that Alice, or Alice's bot?"
- **Bounded** — a human signs a **warrant** naming one audience and a set of
  scopes. That is all the agent can present, there and nowhere else.
- **Revocable** — cut an agent off instantly via signed status lists, without
  rotating the human's own key or password.

Everything verifies **offline against DNS signatures** — no company sits between
you and your users, and nothing breaks if browserid.me disappears.

Three properties fall out of the design:

- **Agent-native, headless.** An agent is just a device with an `agent`-subject
  device cert. It mints its own short-lived **access certs** through the IdP's
  mint API — no browser, no user in the loop at mint time. Humans and agents ride
  the identical mint + presentation path.
- **Least privilege: authentication ≠ authorization.** Device certs come in two
  purposes — `authentication` (mints access certs → logging in) and
  `authorization` (a **config cert** that signs warrants → granting). A
  compromised login-only device can't authorize new grants.
- **Works with any email, any domain — because every IdP implements the same
  thing.** Conformance is mandatory: every IdP MUST implement device-cert
  issuance (both purposes) and the access-cert mint API. Domains without their own
  IdP are served by the `browserid.me` fallback.

## For app developers: verify in one call

Your users (and their agents) sign in; your backend POSTs the assertion to a
`/verify` service and gets back who signed in — and, for an agent, who it acts
for and what it may do here.

```js
import { createVerifier } from "@browserid-ng/verify";
const verifier = createVerifier();               // hosted verifier, or point at your own

const r = await verifier.verify(bundle, "https://app.example.com");
if (r.ok) {
  session.user = r.email;                         // the verified identity (identifier)
  // r.subject         → "user" or "agent"
  // r.scopes          → what the identity's config cert authorized at this audience
} else {
  reject(r.reason);                               // fail-closed on anything else
}
```

`bundle` is the four-object presentation the client sends —
`access_cert~assertion~warrant~config_cert` (see [Protocol notes](#protocol-notes)) —
but as a relying party you never parse it: you POST it and read back
`{ email, subject, scopes, issuer }`.

- **JS/TS wrapper:** [`sdk/js`](./sdk/js) (`@browserid-ng/verify`) — thin, typed, fail-closed.
- **Agent side (Node):** [`sdk/agent`](./sdk/agent) (`@browserid-ng/agent`) — obtain an
  agent device cert, mint access certs headlessly, obtain warrants, present the bundle —
  for agents integrating in Node/TS.
- **Any language:** [`docs/verify-quickstart.md`](./docs/verify-quickstart.md) — the
  `/verify` HTTP contract with Python / Go / curl examples.
- No registration, no client IDs, no secrets to manage.

**Runnable examples:**
- [`examples/rp-quickstart`](./examples/rp-quickstart) — a complete relying party
  in one file: passwordless human sign-in, verify → session.
- [`examples/mcp-agent-auth`](./examples/mcp-agent-auth) — an MCP server whose
  tools require an agent identity + human-signed warrant, gated per scope.

## For agent authors: give your agent an identity

Add one line to your MCP client (Claude Code / Cursor / Claude Desktop) — no
checkout, no build:

```json
{ "mcpServers": { "browserid": { "command": "npx", "args": ["-y", "@browserid-ng/wallet"] } } }
```

Then ask your agent:

> Provision a browserid-ng identity and sign the guestbook saying "hello from my agent".

It shows you an approval link (open it, confirm the fingerprint, approve), then
signs the **public guestbook** at [browserid.me/guestbook](https://browserid.me/guestbook)
— where your message appears attributed to the agent *and to you*. See
[`sdk/wallet`](./sdk/wallet).

## Repository layout

| Crate / dir | What it is |
|---|---|
| **browserid-core** | Protocol primitives — Ed25519 keys, JWT/JWS, **device / access / config certs** (`device.rs`), assertions, warrants, status lists, DNSSEC-first discovery |
| **browserid-broker** | IdP + hosted broker: human auth (passwordless email), **device-cert issuance (both purposes) + the access-cert mint API**, consent + the warrant registry, revocation, and the hosted `/verify` endpoint |
| **browserid-registrar** | The hosted broker's warrant surface — consent, warrant **registry / status-list authoring** (the warrant itself is signed client-side by the user's config cert, not here) |
| **browserid-agent** | Agent-side library + CLI — obtain an agent device cert, mint access certs headlessly, request warrants, present the bundle |
| **browserid-rp** | Relying-party helpers — fail-closed verification with scope enforcement |
| **sdk/js** | `@browserid-ng/verify` — the zero-dependency hosted-verify client (RP side) |
| **sdk/agent** | `@browserid-ng/agent` — the Node agent-side SDK (provision, warrants, assertions) |
| **sdk/wallet** | `@browserid-ng/wallet` — an MCP server (run via `npx`) giving an agent a browserid-ng identity; ships the guestbook demo |
| **e2e-tests** | Playwright end-to-end suite (90+ tests) |
| **docs/** | Design plans and the verification quickstart |

## The agent model in one picture

```
DNS  _browserid.acme.com  (Ed25519, DNSSEC)              ← trust root
  └─ acme.com IdP  issues, per device (never seen by the RP):
       • agent device cert   purpose=authentication, subject=agent, identities=[dan+researcher@acme.com]
       • config cert         purpose=authorization                          (signs warrants)

  agent device cert ──mint API──▶ access cert  (fresh key, short-lived)      ← RP-facing
  config cert ──signs──▶ warrant (dan+researcher@acme.com, subject=agent, aud=api.example.com, scopes=[post,read])

  RP receives the four-object bundle:  access_cert ~ assertion ~ warrant ~ config_cert
```

The device certs stay on the device; the RP sees only the **access cert** (a
fresh, IdP-minted key), the **assertion** it signs, the **warrant**, and the
**config cert** that signed the warrant. The RP joins them by
`(identity, subject, audience)`, checks `config_cert.iss == access_cert.iss` (the
warrant was signed by an authorization cert from the identity's own IdP), and
learns the agent's identity, that it acts as `subject=agent`, and the scopes
authorized **for that audience** — rejecting anything outside them. See
[`docs/verify-quickstart.md`](./docs/verify-quickstart.md), the protocol spec, and
the design under [`docs/design`](./docs/design).

## Getting started (run the broker)

### Prerequisites
- Rust 1.70+ (via [rustup](https://rustup.rs/))
- Node.js 18+ (for the e2e tests / JS SDK only)

```bash
git clone https://github.com/vthunder/browserid-ng.git
cd browserid-ng
cargo run -p browserid-broker
```

The broker starts on `http://localhost:3000`. Email verification codes are
printed to the terminal (production wires up a real email sender).

### Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `BROKER_PORT` | `3000` | HTTP port |
| `BROKER_DOMAIN` | `localhost:3000` | Public domain for certificates |
| `BROKER_KEY_FILE` | `broker-key.json` | Ed25519 keypair file |
| `DATABASE_PATH` | `browserid.db` | SQLite database file |

### Human sign-in (the supporting feature)

Any app can accept passwordless email sign-in with the browser shim:

```html
<script src="http://localhost:3000/include.js"></script>
```
```javascript
navigator.id.watch({
  loggedInUser: null,
  onlogin: (assertion) => { /* POST to your server → /verify */ },
  onlogout: () => {},
});
document.getElementById('login').onclick = () => navigator.id.request();
```

In the device-cert model the browser is just **one device among many**: it holds
the user's device certs, mints an **access cert** through the IdP's mint API
(cookie-free, so it survives ITP), and signs its login warrant locally with the
user's **config cert**. The interactive step uses a first-party WinChan popup, not
a hidden cross-origin iframe. What the server verifies is the same four-object
bundle (`access_cert~assertion~warrant~config_cert`) as in the one-call example
above — a human login carries `subject=user`.

## Testing

```bash
cargo test                 # Rust unit/integration tests
cd e2e-tests && npm install && npx playwright test   # end-to-end
cd sdk/js && node --test   # JS verifier client
```

## Protocol notes

### The four-object bundle

An RP receives four tilde-joined objects — the same for humans and agents:

```
<access_cert>~<assertion>~<warrant>~<config_cert>
```
- **Access cert** — IdP-signed, certifies a **fresh** key, short-lived, minted
  online through the mint API. This is what the RP roots on; the durable
  **device cert** that authorized the mint is never presented.
- **Assertion** — signed by that fresh access key, contains `{aud, exp}`.
- **Warrant** — signed by a **config cert** (an `authorization`-purpose device
  cert), binds `(identifier, subject) → audience[+scopes]`. Always present — for
  human logins too. Load-bearing: no warrant, no login.
- **Config cert** — the `authorization` device cert that signed the warrant,
  presented so the RP can verify it. The RP MUST check
  `config_cert.iss == access_cert.iss` (identity's own IdP) and check three
  fail-closed status authorities: access cert → IdP (per device), config cert →
  IdP, warrant → hosted broker.

The RP joins the four by `(identity, subject, audience)`. See
`browserid-core/src/device.rs` and `test-vectors/device-cert-v1.json`.

### DNS-based key discovery (divergence from original BrowserID)

Keys are discovered from **DNS TXT records with DNSSEC validation**, not
`.well-known` HTTP. `.well-known` is still consulted — but only for endpoint
discovery, never as a source of trusted keys (no downgrade).

```
_browserid.example.com TXT "v=browserid1; public-key-algorithm=Ed25519; public-key=<base64url>; host=idp.example.com"
```

| Aspect | Original spec | browserid-ng |
|--------|---------------|--------------|
| Key location | `https://<domain>/.well-known/browserid` | `_browserid.<domain>` TXT record |
| Trust anchor | HTTPS/TLS certificate | DNSSEC |
| No-primary email | (n/a) | Broker / RP-selected fallback IdP |

- DNSSEC-validated `_browserid` record → the domain is its own **primary IdP**.
- No record / no DNSSEC → a **fallback IdP** (the broker, or an RP-selected one) vouches.
- DNSSEC validation failure (BOGUS) → verification rejected.

See `docs/plans/2025-12-28-dns-discovery-design.md` for details.

## License

All source here is available under the [MPL 2.0][] license unless otherwise
indicated. Derived from [Mozilla Persona][], also MPL 2.0.

[MPL 2.0]: https://mozilla.org/MPL/2.0/
[Mozilla Persona]: https://github.com/mozilla/persona
