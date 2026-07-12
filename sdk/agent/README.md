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

// Mint a backed presentation (agent_cert ~ warrant ~ assertion) for the RP/MCP
// server. It refreshes the cert automatically if stale.
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

- **provision / cert refresh** — endorse at `{broker}/provision/endorse`, then
  mint at `{idp}/provision/mint`.
- **warrant** — `{broker}/warrant/request` → poll `{broker}/warrant/poll`; the
  human signs the warrant with their own key at the consent screen (the agent
  never signs warrants).
- **assertion** — signed with the agent's own key; presented as
  `agent_cert ~ warrant ~ assertion`.
- **revoke** — endorse, then `{idp}/provision/revoke`.

See [`../../examples/mcp-agent-auth`](../../examples/mcp-agent-auth) for a wallet
MCP server built on this SDK.

## License

MPL-2.0
