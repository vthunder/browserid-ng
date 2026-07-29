# @browserid-ng/wallet-service

The **hosted wallet**: a remote [MCP](https://modelcontextprotocol.io) server
that gives agents which **can't run code** — claude.ai web and mobile — their
own [browserid-ng](https://browserid.me) identity. Same tool surface as the
local [`@browserid-ng/wallet`](../sdk/wallet), but the agent's credentials are
custodied server-side: encrypted at rest, sign-only, audited, revocable.

Design: [`docs/plans/2026-07-29-hosted-wallet-remote-mcp-design.md`](../docs/plans/2026-07-29-hosted-wallet-remote-mcp-design.md).

**Prefer the local wallet when your agent can run code** — there the key never
leaves your machine. This service exists for agents whose only extension point
is a remote connector.

## What it is

- **MCP endpoint** at `/mcp` (streamable HTTP, stateless JSON mode), tools:
  `provision`, `identity`, `authorize`, `get_assertion`, `warrants`,
  `drop_grant`, `forget`, and the guestbook demo pair.
- **OAuth 2.1** AS+RS in one service: PKCE (S256 only), dynamic client
  registration (RFC 7591), discovery (RFC 9728 + RFC 8414), resource binding
  (RFC 8707), `iss` in the authorization response (RFC 9207), rotating refresh
  tokens with reuse detection. The authorize page's sign-in step **is**
  browserid — the wallet is its own relying party.
- **Custody**: per-tenant Ed25519 device keys, AES-256-GCM envelope under a
  KEK held outside the database (`EnvKeyWrapper`; swap for a KMS behind the
  same interface). The wallet holds **authentication-purpose material only**:
  warrants are still signed by the user's config cert in their own browser at
  the broker's consent page — a compromised wallet cannot mint new grants.
- **Audit log**: every mint, assertion, warrant request, and admin action,
  per tenant, 90-day retention, metadata only.

## Add to claude.ai

Settings → Connectors → **Add custom connector**, URL:

```
https://wallet.browserid.me/mcp
```

claude.ai discovers the OAuth endpoints, registers itself, and sends you to
the authorize page — sign in with browserid, approve the connection. Then ask
your agent:

> Provision a browserid-ng identity and sign the guestbook.

Approval links (pairing, warrants) open at browserid.me exactly as with the
local wallet.

## Run locally

```bash
cd wallet-service
npm install
npm start          # http://localhost:3100 (dev: KEK/session secrets generated on first run)
npm test
```

## Configuration

| Variable | Default | Description |
|---|---|---|
| `PORT` | `3100` | HTTP port |
| `WALLET_ORIGIN` | `http://localhost:PORT` | Public origin (OAuth issuer + resource; set in production) |
| `BROWSERID_BROKER` | `https://browserid.me` | Broker for provisioning, warrants, sign-in |
| `VERIFIER_URL` | `<broker>/verify-access` | Hosted verifier for the sign-in step |
| `WALLET_DATABASE_PATH` | `wallet.db` | SQLite file |
| `WALLET_KEK` | dev: generated file | **Required in production.** base64url, 32 bytes — wraps tenant keys |
| `WALLET_SESSION_SECRET` | dev: generated file | **Required in production.** base64url, 32 bytes — signs authorize-page sessions |
| `WALLET_ENV` | – | set `production` to require the secrets + Secure cookies |

Generate secrets: `node -e 'console.log(require("crypto").randomBytes(32).toString("base64url"))'`

## Deploy (dokku)

Separate app, separate host, separate secrets from the broker — deliberately
(design doc §4: broker compromise alone yields no agent device keys; wallet
compromise alone yields no warrant-signing or issuance capability).

The app is **`browserid-wallet`** (the name `wallet` is taken by an unrelated
app on the host). One-time setup, done 2026-07-29:

```bash
# on the host
dokku apps:create browserid-wallet
dokku builder:set browserid-wallet selected dockerfile
dokku domains:set browserid-wallet wallet.browserid.me
dokku storage:mount browserid-wallet /var/lib/dokku/data/storage/browserid-wallet:/data
dokku ports:set browserid-wallet http:80:3100
dokku config:set browserid-wallet WALLET_ENV=production WALLET_ORIGIN=https://wallet.browserid.me \
  WALLET_KEK=<secret> WALLET_SESSION_SECRET=<secret>
dokku letsencrypt:enable browserid-wallet   # after DNS exists
```

Build in CI and deploy by image (the repo's standard pattern — see the
deploy-daemon workflow shape): build `wallet-service/Dockerfile` **from the
repo root** (the `file:` SDK deps), push to GHCR, then
`ssh dokku@HOST git:from-image wallet ghcr.io/<owner>/wallet-service:<sha>`.

## Threat model in one paragraph

The wallet is one more *device* in the protocol's device-cert model — one that
runs in a datacenter. It holds agent device keys (`authentication` purpose
only), so full compromise lets an attacker act as hosted agents **at
already-warranted audiences, attributably, until revoked** — the same blast
radius the spec accepts for any leaked agent device key. It cannot fabricate
authorizations: warrants require the user's config cert, which stays in the
user's browser. Revocation (device cert, config cert, warrant) is unchanged
and fail-closed. See design doc §10.

## License

MPL-2.0
