# Roadmap directions (next ~year)

**Date:** 2026-08-02
**Status:** discussion notes, written for later reference — not commitments.
Context: written the week handle identities (`me@<handle>`, epic
browserid-ng-tsqk) shipped end to end, proving the pattern this roadmap
builds on: one identity string, portable authority, agent delegation a human
can kill from a web page.

## The two anchor bets

**Bet 1 — generalize the proof-method pattern.** The claim-time authority
hierarchy is an extension point: anything that proves control of a name can
slot in with zero verifier changes, because `iss = browserid.me` means RPs
never learn or care how ownership was proven. Each new proof method is a
community that suddenly "already has a browserid."

**Bet 2 — deepen the agent story.** Scoped, revocable, *attributable* agent
authority working end to end is the moat. Every improvement multiplies why
people would bother claiming an identity at all.

These compound each other; most of the year should serve one or both.

## Theme 1: proof methods (Bet 1)

- **OIDC bridge** — the headline item; design plan in
  `2026-08-02-oidc-bridge-design.md`. BigTent, done right this time.
- **Fediverse handles** (webfinger + `rel=me`), **GitHub-proven
  identities**, possibly **did:web** — each follows the atproto template:
  a proof specialist runs the ceremony, the broker issues.
- **Self-serve primaries** (the counterweight): a `_browserid` record
  generator, DNSSEC checker, hosted primary kit. The BigTent lesson says a
  good fallback reduces primary pressure — the deliberate answer is making
  the primary upgrade legible and trivial, not making the fallback worse.

## Theme 2: agents (Bet 2)

- **Warrant chains / sub-delegation** — an agent provably re-delegating a
  subset of its authority to a sub-agent, the whole chain in one
  presentation. Cross-issuer warrants (browserid-ng-yhcx) is the opening
  move.
- **MCP-native identity** — the wallet MCP server exists; push toward
  "browserid is the identity layer your MCP host already speaks":
  per-tool-call attribution, warrant-gated tools.
- **Attributed actions as a product** — generalize the sbo/labeler pattern
  ("this action was taken by agent X under authority Y, verifiable
  offline") beyond Bluesky posts. Every platform is about to ask what to do
  with agent traffic; this is an answer.
- Finish the **holder model** (ykjk) and **browser-as-first-agent** (oup3)
  epics — substrate for all of the above.

## Theme 3: decentralize the middle (answer Persona's critique)

- **A second independent fallback broker** (separate infra and keys), then
  a story for community brokers. The spec's per-RP accepted-fallback lists
  (§8.1) already carry this.
- **Issuance transparency** — a CT-style log of fallback-issued certs.
  Cheap to start; changes the trust conversation from "trust us" to
  "audit us."
- Write down the **identifiers-changing-hands** policy (the question
  browserid-ng-jaa1 is one instance of) — a multi-broker world needs it on
  paper.

## Theme 4: spec + credibility

- Publish the spec from the zettel library; extract a conformance suite
  from the existing tests. Prerequisite for anyone implementing a primary
  or second broker without reading our Rust.
- An independent security review + writeup.

## Theme 5: product surface (steady background)

- Security-audit backlog (M1/M6/M7 are cheap), atproto-lane e2e (rau4).
- Drop-in RP adapters: Discourse, WordPress, NextAuth.
- **Passkey-backed device keys** — WebAuthn-resident keys signing device
  certs: unphishable, and a great headline.
- FedCM tracking as browsers ship; mobile polish.

## Explicit non-goals (gravity wells)

No general OAuth-provider product, no enterprise SSO chase, no DID-method
maximalism beyond what bridges need. All of these pull away from the
agent-attribution story that makes this project distinctive.
