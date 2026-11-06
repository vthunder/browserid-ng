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

The entry points are `requestProvision`, `requestWarrants` and `DeviceAgent`
(below). The pre-0.5 provisioning-cert lane (`Agent`, `Credential`, a
downloaded credential file) was removed in 1.0 — see CHANGELOG.md.

## API

### Paired provisioning (device model)

The device-model entry points (`import { requestProvision, requestWarrants,
DeviceAgent } from "@browserid-ng/agent"`) pair an agent with its human — no
downloaded credential. The human's side is the broker's **agent flows v2**:
an identity step (fingerprint check, then name + address) and, when grants
are bundled, a separate permission screen.

```js
const pending = await requestProvision(broker, {
  handle: "bsky",                       // address tag suggestion
  label: "Bluesky poster",              // display-NAME suggestion (they confirm it)
  message: "I post your daily summary.",// why — quoted to them, unverified
  grants: [{ audience, scopes: ["post"] }],
});
show(pending.verificationUriComplete, pending.fingerprint);
const { credential, grants, grantsDenied } = await pending.wait();
```

- **`grantor`** (both calls) pins who the warrants attribute to: omit (or
  `"*"`) and the human chooses via a dropdown — the agent itself, or an
  identity they own; `"self"` pins the agent itself (`grantor == grantee`);
  a concrete email pins that identity. Pins render as text (approve/deny
  only) and an unsatisfiable pin fails the request immediately.
- **`message`** (both calls) is your one-sentence account of why — always
  shown quoted and marked unverified; send one.
- **`grantsDenied`** on the provisioning pickup means the human approved the
  identity but declined the permissions: the credential is real, ask again
  later with `requestWarrants`.
- **`requestWarrants`** files a signed request: pass the `agent`
  (`DeviceAgent`) — or `deviceCert` + `deviceKey` — and the SDK adds the
  registry `Proof` header the device key signs over the body. The broker
  refuses an unsigned filing (the device cert alone is public).
- A denied `requestWarrants(...).wait()` throws with the broker's reason when
  it has one — `unknown_agent` means this account never met you: run
  `requestProvision` first.

### Typed errors

`WarrantDeniedError`, `WarrantExpiredError`, `NoWarrantError` (no warrant held
for the audience), `RequestError` (carries `status` + server `reason`); all
extend `AgentError`.

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
