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

## Start here

| You are… | Go to |
|---|---|
| **An app developer** adding sign-in | Drop-in adapters: [NextAuth](./sdk/nextauth) · [Express](./sdk/express) · [Hono](./sdk/hono) · [Fastify](./sdk/fastify) — or the [one-call verifier](#for-app-developers-verify-in-one-call). |
| **Building an agent / MCP server** | Warrant-gate your tools with [`@browserid-ng/mcp-auth`](./sdk/mcp-auth) (JS) or [`browserid-mcp-auth`](./sdk/python-mcp-auth) (Python). See [For agent authors](#for-agent-authors-give-your-agent-an-identity). |
| **A domain owner** | [Run identity for your domain](#for-domain-owners-run-identity-for-your-domain) with one DNS record — browserid.me issues certs *as your domain*. |
| **Just exploring** | The [live demos & services](#live-demos--services) below. |

## Live demos & services

| | |
|---|---|
| [**browserid.me**](https://browserid.me) | the broker / fallback IdP + hosted verifier |
| [**idp.browserid.me**](https://idp.browserid.me) | the hosted-primary IdP surface a delegating domain points at |
| [**browserid.me/guestbook**](https://browserid.me/guestbook) | a public guestbook only a verified identity can sign |
| [**mcp-demo.browserid.me**](https://mcp-demo.browserid.me) | a warrant-gated MCP server (JS) — "revoke kills the agent" |
| [**python-mcp-demo.browserid.me**](https://python-mcp-demo.browserid.me) | the same, on FastMCP (Python) |
| `npx @browserid-ng/wallet` | the local wallet MCP server — gives an agent its own identity |

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

- **Agent-native, headless.** An agent is just a holder that isn't a browser — a
  program with its own device cert. It mints its own short-lived **access certs**
  through the IdP's mint API — no browser, no user in the loop at mint time. Humans
  and agents ride the identical mint + presentation path.
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
  session.user = r.email;                         // whom the sign-in is attributed to (the grantor)
  // r.grantee         → who actually acted (an agent, for a delegated grant; == r.email for a human login)
  // r.scopes          → what the grantor's warrant authorized at this audience
} else {
  reject(r.reason);                               // fail-closed on anything else
}
```

`bundle` is the four-object presentation the client sends —
`access_cert~assertion~warrant~config_cert` (see [Protocol notes](#protocol-notes)) —
but as a relying party you never parse it: you POST it and read back
`{ email, grantee, scopes, issuer }`.

- **JS/TS wrapper:** [`sdk/js`](./sdk/js) (`@browserid-ng/verify`) — thin, typed, fail-closed.
- **Agent side (Node):** [`sdk/agent`](./sdk/agent) (`@browserid-ng/agent`) — obtain an
  agent device cert, mint access certs headlessly, obtain warrants, present the bundle —
  for agents integrating in Node/TS.
- **Any language:** [`docs/verify-quickstart.md`](./docs/verify-quickstart.md) — the
  `/verify` HTTP contract with Python / Go / curl examples.
- No registration, no client IDs, no secrets to manage.

**Drop-in framework adapters** — "Sign in with BrowserID" for your stack, each a
thin, tested wrapper over the verifier (audience-pinned, fail-closed, humans-only
by default):

| Framework | Package | Shape |
|---|---|---|
| Next.js / [Auth.js](https://authjs.dev) | [`@browserid-ng/nextauth`](./sdk/nextauth) | Credentials provider + client helper |
| [Express](https://expressjs.com) | [`@browserid-ng/express`](./sdk/express) | Passport strategy + middleware |
| [Hono](https://hono.dev) (edge: Workers/Bun/Deno) | [`@browserid-ng/hono`](./sdk/hono) | middleware |
| [Fastify](https://fastify.dev) | [`@browserid-ng/fastify`](./sdk/fastify) | preHandler hook |

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

### Warrant-gate *your* MCP server (no PATs in configs)

Instead of pasting a long-lived API key into an MCP server's config — which the
agent effectively owns, unscoped and unrevocable — wrap your tools so the agent
presents its human's **warrant** and you get scoped, attributed, revocable
authority per call. Riding MCP's own OAuth 2.1 (the RFC 7521 assertion grant),
so hosts speak it unmodified:

| | Package | Runnable server |
|---|---|---|
| **JavaScript** | [`@browserid-ng/mcp-auth`](./sdk/mcp-auth) | [`mcp-demo`](./mcp-demo) → [mcp-demo.browserid.me](https://mcp-demo.browserid.me) |
| **Python / FastMCP** | [`browserid-mcp-auth`](./sdk/python-mcp-auth) | [`python-mcp-demo`](./python-mcp-demo) → [python-mcp-demo.browserid.me](https://python-mcp-demo.browserid.me) |

Every tool call exposes `grantor` (the human) and `grantee` (the agent), enforces
the tool's scopes, and re-checks revocation **fail-closed** — so a revoke at
`browserid.me/account` kills the agent on its *next* call, with no key rotation.

## For domain owners: run identity for your domain

Be your own identity provider without running one. Publish a single DNSSEC
`_browserid` record and browserid.me operates the full IdP surface **as your
domain** — certs are issued with `iss = yourdomain.com`, your users manage
nothing, and every relying party that already accepts browserid.me accepts your
domain with zero config. Your off-ramp is a DNS flip to a self-hosted key.
Onboard at [browserid.me/domains](https://browserid.me/domains); design in
[`docs/plans/2026-08-08-hosted-primary-idp-as-a-service.md`](./docs/plans/2026-08-08-hosted-primary-idp-as-a-service.md).

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
| **sdk/nextauth · express · hono · fastify** | Drop-in "Sign in with BrowserID" RP adapters for [NextAuth](./sdk/nextauth), [Express](./sdk/express), [Hono](./sdk/hono), [Fastify](./sdk/fastify) |
| **sdk/mcp-auth** | `@browserid-ng/mcp-auth` — warrant-gate MCP tools over MCP's OAuth 2.1 (7521 AS + fail-closed per-call status) |
| **sdk/python-mcp-auth** | `browserid-mcp-auth` — the Python / FastMCP port of mcp-auth |
| **mcp-demo · python-mcp-demo** | runnable warrant-gated MCP reference servers (JS + Python) — the "revoke kills the agent" demo |
| **e2e-tests** | Playwright end-to-end suite (90+ tests) |
| **docs/** | Design plans and the verification quickstart |

## The agent model in one picture

```
DNS  _browserid.acme.com  (Ed25519, DNSSEC)              ← trust root
  └─ acme.com IdP  issues, per device (never seen by the RP):
       • auth cert     purpose=authentication, holder=agents.k3n9, identities=[dan+researcher@acme.com]
       • config cert   purpose=authorization                        (signs warrants)

  auth cert ──mint──▶ access cert  (fresh key, short-lived, carries the holder)   ← RP-facing
  config cert ──signs──▶ warrant (grantor=dan@acme.com → grantee=dan+researcher@acme.com,
                                  holder=agents.*, aud=api.example.com, scopes=[post,read])

  RP receives the four-object bundle:  access_cert ~ assertion ~ warrant ~ config_cert
```

The device certs stay on the device; the RP sees only the **access cert** (a
fresh, IdP-minted key), the **assertion** it signs, the **warrant**, and the
**config cert** that signed the warrant. The RP joins them by
`(grantee = access-cert identity, holder ∈ matcher, audience)`, attributes the
action to the **grantor**, and requires each issuer to be authoritative for its own
identity (the access cert for the grantee, the config cert for the grantor). It
learns who acted (the grantee), on whose behalf (the grantor), and the scopes
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
above — humans sign in the same way, and get the same guardrails: a login on a
shared or borrowed machine can hold a scoped, revocable credential instead of
all-powerful account keys.

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
  cert), binds `grantor → grantee` over a holder-matcher, audience, and optional
  scopes. Always present — for human logins too (there grantor == grantee). No
  warrant, no login.
- **Config cert** — the `authorization` device cert that signed the warrant,
  presented so the RP can verify it. The RP MUST require each issuer to be
  authoritative for its own identity (access cert → grantee's IdP, config cert →
  grantor's IdP) and check three fail-closed status authorities: access cert → IdP
  (per device), config cert → IdP, warrant → hosted broker.

The RP joins the four by `(grantee = access-cert identity, holder ∈ matcher,
audience)` and attributes the action to the grantor. See
`browserid-core/src/device.rs`.

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
