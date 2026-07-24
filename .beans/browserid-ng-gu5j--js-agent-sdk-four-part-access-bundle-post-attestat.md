---
# browserid-ng-gu5j
title: 'JS agent SDK: four-part access bundle + post attestations (unblocks the bsky flagship demo)'
status: completed
type: feature
priority: high
created_at: 2026-07-24T21:02:20Z
updated_at: 2026-07-24T21:24:22Z
---

The JS agent SDK is a protocol version behind the Rust one, which blocks the
browserid-bsky flagship demo (bean browserid-bsky-nr8p).

Today, sdk/agent/src/protocol.mjs backedPresentation() builds
`cert~warrant~assertion` — three parts, and there is no notion of an access
cert anywhere in the JS SDK. browserid-core's AccessPresentation (device.rs)
is four: `access_cert ~ assertion ~ warrant ~ config_cert`.

Consequences for any agent driving the JS path (including the wallet MCP in
examples/mcp-agent-auth):
- POST /browserid/provision at the bsky bridge REJECTS the bundle outright —
  it parses AccessPresentation.
- Even if it didn't, /browserid/post needs an ATTESTATION: a signature made
  with the ACCESS key over the exact post content. Without it the post gets
  provenance but fails verification, so the labeler emits NO badge — which is
  the entire point of the demo.

Note examples/mcp-agent-auth/README.md already DESCRIBES the four-object
bundle ("access_cert ~ assertion ~ warrant ~ config_cert"), contradicting the
code it documents. Work out which is stale first.

Scope:
- Access certs in the JS SDK (mint/refresh/hold the access key).
- Four-part backedPresentation.
- An attestation API: sign {content_hash, nonce, iat} with the access key,
  matching pds-bridge/src/attestation.rs (content_hash over the post record).
- Surface both through the wallet MCP so an agent can run the whole flow.
- Cross-check against the Rust implementation with a shared test vector.

Decided with Dan 2026-07-24: the JS+MCP path is the one to invest in (vs
shipping the Rust smoke tool as a binary), because the demo one-liner is
"tell your agent to set up an account at bsky.browserid.me" — that only works
if the agent can install its tooling without a compiler.

## Done 2026-07-24

The gap was bigger than "add access certs": the JS SDK implemented the LEGACY
provisioning-cert flow, whose endpoints the broker no longer serves. Verified
live: POST https://browserid.me/provision/endorse -> 404, while
/agent-provision/request and /access/mint -> 422 (exist, reject empty body).
So the JS path was not merely behind, it was dead.

Added sdk/agent/src/device.mjs — the current protocol, mirroring the Rust
browserid-agent crate:
- requestProvision() -> /agent-provision/request, returning the approval URL,
  user code and key fingerprint; pending.wait() polls /agent-provision/poll
  (pending/denied/expired/failed/completed, 410 = gone, single delivery).
- requestWarrants() -> /warrant/request + /warrant/poll for a second consent
  round once provisioned (note: that flow says "approved", not "completed").
- DeviceAgent: identity + holder read from the SIGNED device cert; mint()
  posts a device-key-signed access request to /access/mint for a FRESH access
  key; assertionFor() returns the four-part
  access_cert~assertion~warrant~config_cert with the assertion signed by the
  ACCESS key; assertionWithAccessKey() hands back that key so a caller can
  sign an external payload (the bsky post attestation).
- addGrant accepts the `warrant~config_cert` pair the poll returns, and
  enforces what Rust enforces (this agent must be the grantee; holder must
  match).

sdk/wallet (the npx MCP server) ported to DeviceAgent, keeping its
non-blocking approval UX. Credential + warrants now persist in one file.

sdk/agent/index.mjs exports the new API first and marks the legacy Agent as
what it is. KeyPair/PublicKey are exported so consumers can sign/verify.

Tests: sdk/agent/device.test.mjs — 8 tests against a mock broker/IdP that
PARSES what the SDK sends (verifies the access request is signed by the
device key, pinned to the IdP, holder copied from the cert, access key
fresh). 17 JS tests green overall.

Cross-implementation vector for the attestation lives in
pds-bridge/src/attestation.rs (canonical_json_and_content_hash_are_stable)
and agent-cli/bsky.test.mjs — same record, same canonical string, same hash,
so the two implementations cannot drift silently.

Unblocks browserid-bsky-nr8p.
