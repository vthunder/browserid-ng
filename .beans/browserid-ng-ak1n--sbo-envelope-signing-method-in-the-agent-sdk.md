---
# browserid-ng-ak1n
title: SBO-envelope signing method in the agent SDK
status: in-progress
type: task
priority: normal
created_at: 2026-07-14T16:51:27Z
updated_at: 2026-07-14T17:02:19Z
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
- [x] SBO-envelope agent-write signer: added `Message::sign_as_agent(key,
      agent_cert, warrant, auth_evidence)` in sbo-core (branch
      feat/agent-write-signing-primitive) — attaches Auth-Cert/Auth-Warrant/
      Auth-Evidence + signs atomically. Test proves signature validity + daemon
      authorization end-to-end. NOTE: the full mechanism was already implemented
      + tested in sbo-core (attribution/warrant/authorize + tests/agent_write.rs
      + examples/agent_write_smoke.rs consumes a real browserid-agent identity
      file). No new crypto needed; this is the reusable builder.
- [ ] Emit the Auth-Cert (agent cert) and Auth-Warrant into the wire envelope
      so the daemon's L2 attribution gate verifies "agent acting for <user>".
- [ ] Confirm the browserid store / cert issuance can support one shared agent
      email with per-user parent claims, OR settle on per-user agent emails
      under a shared display name (store binds agent email -> single parent
      today; see agent.rs set_parent_email).
- [ ] Tests against sbo-core attribution + daemon L2 (warrant happy path).

Blocks the mingo-poster delegated-signing feature.

## Progress note

The signing half is essentially DONE — proven end-to-end in sbo-core with real `browserid_core` types and even a live smoke test against real DNSSEC + the daemon L2 gate. The reusable `Message::sign_as_agent` primitive is added (sbo feat/agent-write-signing-primitive, uncommitted-to-main / not pushed).

Remaining under this bean is small: confirm the shared-agent-email-vs-per-user-parent store/cert question, and expose the primitive through the JS agent SDK if mingo's backend is JS (if it's the Rust mingo-idp, it can call sbo-core directly). The BULK of the feature is now plumbing tracked in mingo-3f3i (provision mingo-poster, consent redirect, backend signer service, mingo-web switch to submit-unsigned).
