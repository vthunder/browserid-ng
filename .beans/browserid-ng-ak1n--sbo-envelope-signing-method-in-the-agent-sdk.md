---
# browserid-ng-ak1n
title: SBO-envelope signing method in the agent SDK
status: todo
type: task
priority: normal
created_at: 2026-07-14T16:51:27Z
updated_at: 2026-07-14T16:51:27Z
---

Enabling gap for delegated server-side SBO posting (see mingo-poster agent
delegation design). The browserid agent SDK (sdk/agent, browserid-agent) has
the full warrant/consent/delegation machinery and a generic sign(bytes)
primitive, and sbo:// audiences already flow through warrants in tests. What's
missing is a first-class SBO-envelope signing method.

## What exists (from research)
- browserid-agent/src/lib.rs: Agent holds its key; sign(bytes) signs arbitrary
  bytes; assertionFor() bundles agent_cert~warrant~assertion.
- SBO core (~/src/sbo) fully implements Agent Warrant on-chain: agent cert
  (parent=user) + user-signed Auth-Warrant (aud=chain, scopes, as:<user>) →
  object attributed on-chain to the user, verifiable, revocable.
- Design docs: docs/plans/2026-06-24-typed-signing-extension-design.md,
  docs/plans/2026-07-09-agent-delegation-chain-design.md.

## Work
- [ ] Add an SBO-envelope signer to the agent SDK: given a canonical SBO
      envelope (SBO-Version header, canonical header order per sbo-core
      envelope.rs), produce the Ed25519 signature over canonical_signing_content
      with the agent key, with correct domain separation.
- [ ] Emit the Auth-Cert (agent cert) and Auth-Warrant into the wire envelope
      so the daemon's L2 attribution gate verifies "agent acting for <user>".
- [ ] Confirm the browserid store / cert issuance can support one shared agent
      email with per-user parent claims, OR settle on per-user agent emails
      under a shared display name (store binds agent email -> single parent
      today; see agent.rs set_parent_email).
- [ ] Tests against sbo-core attribution + daemon L2 (warrant happy path).

Blocks the mingo-poster delegated-signing feature.
