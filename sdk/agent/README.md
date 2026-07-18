# @browserid-ng/agent

The **agent** side of [browserid-ng](https://browserid.me), for Node. Provision a
delegated agent identity, get human-approved **warrants**, and mint
warrant-backed **assertions** to present to relying parties and MCP servers — so
an agent signs in as *itself*, acting for a human, within scopes the human
approved and can revoke.

A faithful Node port of the Rust `browserid-agent` crate: same wire formats, same
Ed25519/JWS signing (cross-checked byte-for-byte against `browserid-core`). No
Rust, no shelling out.

## Install

```
npm install @browserid-ng/agent
```

Node 18+. Ed25519 via `node:crypto`.

## Use

```js
import { Agent } from "@browserid-ng/agent";

// Load a persisted identity, or provision one from the credential the human
// downloaded at https://browserid.me/agents.
const agent = await Agent.open("agent-credential.json", "agent.identity.json");

const audience = "https://notes.mcp.example";

// Ask the human to authorize this audience + scopes. `approveUrl` is a
// browserid.me consent screen; `approved` resolves once they approve.
const { approveUrl, approved } = await agent.requestWarrant(audience, ["post", "read"]);
if (approveUrl) {
  console.log("Approve here:", approveUrl);   // show the human
  await approved;                              // polls until they do
}

// Mint the four-object bundle (access_cert ~ assertion ~ warrant ~ config_cert)
// for the RP/MCP server. It mints a fresh access cert automatically as needed.
const assertion = await agent.assertionFor(audience);

await agent.save("agent.identity.json");       // persist key + cert + warrants
```

The relying party verifies `assertion` with [`@browserid-ng/verify`](../js) (or a
hosted `/verify`) and learns the agent, its principal, and the granted scopes.

## API

- **`Agent.open(credential, identityPath, opts?)`** — load a saved identity or
  provision + save one. `credential` is a path or parsed object. `opts.name`
  picks a reserved name (multi-name credentials); `opts.http` overrides fetch.
- **`Agent.provision(credential, opts?)`** — provision a fresh identity (no persistence).
- **`agent.identity()`** — `{ names, patterns, default }` — what the credential
  reserves and the identity it provisions as (single name, generated-under-pattern,
  or `null` if ambiguous). Use to tell the human who you'll act as.
- **`agent.requestWarrant(audience, scopes?)`** → `{ approveUrl, approved }` —
  raise a consent request. `approveUrl` is `null` (and `approved` resolves at once)
  if a covering warrant is already held. `approved` rejects on denial/expiry.
- **`agent.obtainWarrant(audience, scopes, onApproveUrl?)`** — convenience: raise
  consent, hand the URL to a callback, and await approval.
- **`agent.assertionFor(audience)`** → a backed presentation string. Throws
  `NoWarrantError` if this agent identity has no warrant for the audience.
- **`agent.warrantedAudiences()` / `agent.warrantCovers(audience, scopes?)`**
- **`agent.save(identityPath)` / `agent.revoke()`**
- **`Credential.load(pathOrObject)`** — `constraint()`, `defaultIdentity()`, domains.

### Typed errors

`NeedCredentialError` (no credential file), `AmbiguousNameError` (several reserved
names — pick one), `WarrantDeniedError`, `WarrantExpiredError`, `NoWarrantError`,
`RequestError` (carries `status` + server `reason`), `InvalidCredentialError`.

## How it maps to the protocol

The agent holds an **agent device cert** (`subject: agent`, `purpose:
authentication`) the IdP issued after the human authorized it. It never presents
that device cert; it mints short-lived **access certs** from it.

- **device cert** — obtained once via the user-authorized device-grant; durable,
  IdP-signed, never sent to an RP.
- **access cert** — `assertionFor` signs an **access request** with the agent
  device key and mints a fresh-key **access cert** at the IdP's mint API. The
  assertion is signed by that fresh access key, not the device key.
- **warrant** — `{broker}/warrant/request` → poll `{broker}/warrant/poll`; on
  approval the human's **config cert** (an `authorization`-purpose device cert)
  signs the warrant at the consent screen, and it's registered in the hosted
  broker. The agent never signs warrants.
- **presentation** — the four-object bundle
  `access_cert ~ assertion ~ warrant ~ config_cert`, joined by
  `(identity, subject, audience)`.
- **revoke** — revoke the agent device cert (its status ref → IdP) or a specific
  warrant (its status ref → hosted broker).

See [`../../examples/mcp-agent-auth`](../../examples/mcp-agent-auth) for a wallet
MCP server built on this SDK.

## License

MPL-2.0
