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

## For app developers: verify in one call

Your users (and their agents) sign in; your backend POSTs the assertion to a
`/verify` service and gets back who signed in — and, for an agent, who it acts
for and what it may do here.

```js
import { createVerifier } from "@browserid/verify";
const verifier = createVerifier();               // hosted verifier, or point at your own

const r = await verifier.verify(assertion, "https://app.example.com");
if (r.ok) {
  session.user = r.email;                         // verified identity
  // r.agent?.parent  → the human an agent acts for
  // r.agent?.scopes  → what that human authorized at this audience
} else {
  reject(r.reason);                               // fail-closed on anything else
}
```

- **JS/TS wrapper:** [`sdk/js`](./sdk/js) (`@browserid/verify`) — thin, typed, fail-closed.
- **Agent side (Node):** [`sdk/agent`](./sdk/agent) (`@browserid/agent`) — provision a
  delegated identity, obtain warrants, mint assertions — for agents integrating in Node/TS.
- **Any language:** [`docs/verify-quickstart.md`](./docs/verify-quickstart.md) — the
  `/verify` HTTP contract with Python / Go / curl examples.
- No registration, no client IDs, no secrets to manage.

**Runnable examples:**
- [`examples/rp-quickstart`](./examples/rp-quickstart) — a complete relying party
  in one file: passwordless human sign-in, verify → session.
- [`examples/mcp-agent-auth`](./examples/mcp-agent-auth) — an MCP server whose
  tools require an agent identity + human-signed warrant, gated per scope.

## Repository layout

| Crate / dir | What it is |
|---|---|
| **browserid-core** | Protocol primitives — Ed25519 keys, JWT/JWS, certificates, assertions, warrants, status lists, DNSSEC-first discovery |
| **browserid-broker** | The identity broker: human auth (passwordless email), certificate issuance, agent-consent + warrant registry, revocation, and the hosted `/verify` endpoint |
| **browserid-registrar** | The user's own delegation authority — consent, warrant issuance, status-list authoring (unbundled from the IdP role) |
| **browserid-agent** | Agent-side library + CLI — provision a delegated identity, request warrants, present assertions |
| **browserid-rp** | Relying-party helpers — fail-closed verification with scope enforcement |
| **sdk/js** | `@browserid/verify` — the zero-dependency hosted-verify client (RP side) |
| **sdk/agent** | `@browserid/agent` — the Node agent-side SDK (provision, warrants, assertions) |
| **sdk/wallet** | `@browserid/wallet` — an MCP server (run via `npx`) giving an agent a browserid-ng identity; ships the guestbook demo |
| **e2e-tests** | Playwright end-to-end suite (90+ tests) |
| **docs/** | Design plans and the verification quickstart |

## The agent model in one picture

```
DNS  _browserid.acme.com  (Ed25519, DNSSEC)          ← trust root
  └─ alice@acme.com        identity cert              ← the human
       └─ warrant: agent=researcher, aud=api.example.com, scopes=[post,read]
            └─ researcher@acme.com  agent cert + assertion   ← what the agent presents
```

A relying party verifying the agent's assertion learns the agent's identity, its
principal (`alice@acme.com`), and the scopes Alice signed **for that audience** —
and rejects anything outside them. See
[`docs/verify-quickstart.md`](./docs/verify-quickstart.md) and the design plans
under [`docs/plans`](./docs/plans).

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

The server verifies the returned `certificate~assertion` exactly as in the
one-call example above.

## Testing

```bash
cargo test                 # Rust unit/integration tests
cd e2e-tests && npm install && npx playwright test   # end-to-end
cd sdk/js && node --test   # JS verifier client
```

## Protocol notes

### Backed assertion format

```
<certificate>~<assertion>[~<warrant>]
```
- **Certificate** — signed by the issuer, binds an email (or agent) to a public key.
- **Assertion** — signed by that key, contains `{aud, exp}`.
- **Warrant** *(agent presentations)* — signed by the delegator's identity key,
  binds `{agent, aud, scopes}`. Load-bearing: an agent cert without a valid
  warrant is rejected.

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
