---
# browserid-ng-74u1
title: Standardize agent identity provisioning (device-grant pairing flow)
status: todo
type: feature
priority: high
created_at: 2026-07-12T11:42:42Z
updated_at: 2026-07-12T11:42:42Z
---

Today the initial agent-credential handoff has no protocol: the user goes to browserid.me/agents, downloads a credential JSON (containing the provisioning PRIVATE key), and the wallet polls ~/Downloads to pick it up. Standardize it as a device-authorization-style pairing flow, mirroring the warrant consent flow (request -> verification_uri -> poll -> pickup).

## Recommended design (agent-generates-key; zero secret handoff)
1. Agent generates a provisioning keypair locally. POST {broker}/agent-provision/request { provisioning_pubkey, requested_handles? } -> { code, verification_uri, interval, expires_in }.
2. Agent surfaces verification_uri to the human (like a consent URL).
3. Human opens it (authenticated session), picks the delegating identity, reviews/edits handles, decides reissue vs new; their identity key signs the delegation (P_cert) over the AGENT-supplied provisioning public key; handles reserved (session-authenticated). Delegation stored against code.
4. Agent polls {broker}/agent-provision/poll { code } -> { delegation (U_cert~P_cert), broker, idp, names, patterns } when done; assembles the credential locally with its held private key.

Key property: the provisioning private key is born in the agent and NEVER transits browserid.me or a file. Browser + broker only ever see public keys + signed certs. Strictly better than the download flow (no private key in a file to move around) and true to no-keys-in-the-middle.

## Notes / decisions
- Reservation moves to a session-authenticated step at the verification page (preserves create-time handle locking without a provisioning-key-signed request). Fold the reissue/add/reuse UX (see analysis in-session) here.
- Reuse consent-flow machinery (code + verification_uri + poll + expiry/interval).
- The download-JSON path stays as an ADVANCED escape hatch, hidden from the normal flow.
- Alternative (rejected): browser generates the provisioning key and encrypts it to an agent-supplied ephemeral pubkey for relay. Works but reintroduces a key that leaves the browser; agent-generates is cleaner.

## Surfaces to build
- Broker: /agent-provision/request + /agent-provision/poll endpoints; store pending provisions keyed by code; session-authenticated reserve.
- A /agent-provision/<code> page (or fold into /agents): review + sign delegation over the supplied pubkey.
- @browserid/agent: bootstrap()/provisionInteractive() -> { verificationUri, ready: Promise<Agent> }.
- wallet MCP server: a provision tool (deletes the Downloads-discovery hack).
- Docs.

Design doc first (docs/plans), then implement. Relates to 0phq (agent domain).
