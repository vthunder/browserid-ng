# Roadmap directions (next ~year) + the OIDC bridge design sketch

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

- **OIDC bridge** — the headline item; full sketch below. BigTent, done
  right this time.
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

---

# The OIDC bridge, fleshed out

**One line:** prove mailbox ownership with the provider's own sign-in
instead of a mailed code — "claim `foo@gmail.com` by signing in with
Google," no code to copy, nothing to wait for.

This is BigTent (Mozilla's 2012 Persona bridge to Yahoo/Hotmail/Gmail via
OpenID/OAuth), rebuilt on machinery we now have that BigTent lacked: the
claim-time authority hierarchy, the proof-method record on the identity,
and a dialog claim-hop that already handles "navigate out, prove, come
back" (built for atproto, reused verbatim here).

## Where it sits in the hierarchy — and where it doesn't

**OIDC is not a new hierarchy step.** The hierarchy decides *which
authority* a no-primary domain has: handle binding → mailbox (MX) →
nothing. OIDC doesn't change the authority — a gmail.com identity is still
mailbox-rooted — it upgrades the *ceremony* that proves the mailbox. So:

1. DNSSEC `_browserid` → primary (unchanged)
2. resolved handle binding → atproto OAuth (unchanged)
3. MX → mailbox authority, proven by **OIDC when the domain has a known
   issuer, else the SMTP loop** (this is the change)
4. otherwise → refuse (unchanged)

Consequences of that placement:

- **Scope is per-mailbox, exactly like SMTP.** An OIDC proof covers one
  address, never the domain. `proof = "oidc"` behaves like `"smtp"` for
  every scope decision; only atproto is domain-wide. Getting this wrong is
  the escalation the design note warns about.
- **No pinning, same as everywhere**: the ceremony is chosen per claim from
  current state. SMTP remains available as a fallback ceremony for the same
  domain (equivalent strength — both bottom out in the provider's
  infrastructure), so an OIDC outage degrades to today's behavior instead
  of locking anyone out.

## Architecture: in-broker, not a separate bridge

The atproto specialist is a separate service because atproto drags heavy,
peculiar deps (DoH resolution, PDS discovery, DPoP, pins). OIDC is none of
that: standard authorization-code flow, JWKS verification (`jsonwebtoken`
is already in-tree), a redirect endpoint, and per-provider client
credentials. Recommendation: **a broker module** (`browserid-broker/src/
oidc/`), not a new deployment.

That choice deletes the attestation layer entirely: the OIDC callback lands
*on the broker*, which attaches the identity to the session directly — the
attestation existed only to carry proof across a service boundary. (If we
ever want the bridge shape anyway — e.g. to keep Google client secrets off
the broker — the `HandleAttestation` pattern generalizes: a new typ
`browserid-mailbox-attestation-v1` with `{email, oidc_iss, oidc_sub}`
claims. Keep it in the back pocket; don't start there.)

## Provider → domain mapping

**Phase 1 (static):** a config table.

| domains | issuer |
|---|---|
| gmail.com, googlemail.com | `https://accounts.google.com` |
| outlook.com, hotmail.com, live.com, msn.com | Microsoft (consumers tenant) |
| yahoo.com, ymail.com | `https://api.login.yahoo.com` |
| icloud.com, me.com | Apple (Sign in with Apple) |

**Phase 2 (MX-inferred, the BigTent+ move):** a domain whose MX points at
Google (`aspmx.l.google.com`) is Google-hosted — offer Google OIDC for
*any* Workspace custom domain, validating the `hd` claim equals the email
domain. Same for Microsoft-hosted MX. This turns "every company on
Workspace/365" into password-free browserid claims. The MX probe already
exists (authority hierarchy); this reuses its answer.

**Phase 3 (open-web):** OIDC issuer discovery from an email via WebFinger
(RFC 7033 — this exact use case is in the OIDC Discovery spec). Almost
nobody deploys it, but supporting it makes the mapping table escapable by
any self-hoster, which is the right protocol posture.

## Flow (mirrors the atproto claim hop)

1. `address_info` for a no-primary, no-handle, MX-bearing domain with a
   known issuer answers `proof: "oidc"` plus a claim URL on the broker
   (e.g. `/oidc/claim`). The dialog branch built for `proof: "atproto"`
   generalizes: same navigate-out/resume machinery, different lane tag.
2. `/oidc/claim` starts the authorization-code flow (PKCE + nonce + state,
   `login_hint=<typed address>`, `prompt=select_account` when the hint
   mismatches an existing provider session).
3. Callback verifies the ID token: signature against provider JWKS,
   `iss`/`aud`/`nonce`/`exp`, **`email_verified == true`**, and the email
   claim **exactly equals** the address being claimed (post-normalization —
   see gotchas). Google-specific: treat `sub` as the stable subject, never
   the email.
4. Attach: same semantics as `complete_handle_claim` —
   session present → add to that account; cold claim of a known identity →
   sign in **only if the stored `proof_subject` (issuer+`sub`) matches**;
   mismatch → the mailbox changed hands → identity moves to a fresh
   account. Store `proof = "oidc"`, `proof_subject = "<iss>#<sub>"`.
5. `issueDevicePair` → `/device/issue` unchanged, as always.

`stage_*` gates need no change (the domain's authority is still the
mailbox); the dialog simply stops *offering* the code ceremony when OIDC is
available, with "email me a code instead" as the escape hatch.

## Security gotchas (each one bit somebody historically)

- **`email_verified` is mandatory**, and absent means false. Some IdPs
  (older Azure AD paths) emit unverified or mutable email claims — the
  Phase-1 provider list is short *because* each entry needs this vetted.
- **Email reassignment**: providers recycle addresses (Yahoo famously).
  The `proof_subject` sub-match on cold re-claims is the defense — same
  design as the atproto DID match, and the reason to store `iss#sub`, not
  just the method.
- **Gmail normalization**: dots and `+tags` alias the same mailbox at
  Google but are distinct strings to us. Normalize Google addresses
  (strip dots, strip `+…`) before compare/attach, or two claims of
  "different" addresses land on one mailbox. Decide once, document it.
- **`hd` claim** (Phase 2): must equal the email's domain — an ID token
  for `foo@evil.com` with a Workspace session must never satisfy a claim
  of `foo@customer.com`.
- **Apple relay addresses**: Sign in with Apple can mint
  `@privaterelay.appleid.com` addresses — only accept when the returned
  email equals the claimed one; never let the provider substitute.
- **Client secrets**: per-provider registered credentials live in broker
  config (env), same custody story as SMTP credentials today.

## What it buys

The SMTP loop is the single worst step of every demo: wait for a code, dig
through spam, copy it, ~90 seconds of drop-off. OIDC replaces it for —
realistically — the large majority of addresses anyone types, with a
ceremony people already trust. It also makes **re-verification** (the
periodic `EmailVerificationExpired` re-proof) a one-click bounce instead of
another mailed code, which matters more as identities age.

Strategic note, same trade as handle identities: making gmail.com this
smooth further reduces Google's incentive to ever run a primary. Accepted
for the same reason as before — a fallback nobody enjoys using generates no
adoption pressure at all — and the counterweight is Theme 1's self-serve
primary work, not a worse fallback.

## Phasing

- **P1**: Google only, static mapping, in-broker module, dialog lane
  generalized from atproto (`proof: "oidc"`), full test story incl. a mock
  issuer for e2e. Ships value immediately (gmail is the plurality of typed
  addresses).
- **P2**: Microsoft, Yahoo, Apple — each after a claims-behavior review.
- **P3**: MX-inferred Workspace/365 domains with `hd` validation.
- **P4**: WebFinger issuer discovery for self-hosters.
