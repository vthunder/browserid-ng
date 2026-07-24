---
# browserid-ng-s8lv
title: Protocol-level agent marker in the cert ("this identity is an agent of X")
status: todo
type: feature
priority: high
created_at: 2026-07-24T22:57:05Z
updated_at: 2026-07-24T22:57:05Z
---

Dan 2026-07-25, refining shape 2 of browserid-ng-8v6c.

The ask is NOT an attribution change. It is: mint danmills+agent@sandmill.org
as a standalone identity that only accesses its own resources (grantor ==
grantee, shape 3), but with a VERIFIABLE, protocol-level claim that this
identity is an AGENT OWNED BY danmills@sandmill.org.

Today the only signal is the `+tag` pattern. That is RFC 5233 subaddressing —
real at the email layer, but browserid says nothing about it and every
consumer treats it as convention. A relying party cannot check it; it can only
guess by string-munging, and a `+tag` proves nothing about who controls the
base address.

Note the regression: the LEGACY model had an explicit agent cert type
(`browserid-agent-cert-v1`; sdk/agent/src/protocol.mjs still exposes
`isAgent` from it). The device-cert model dropped that distinction and put
nothing in its place — a device cert carries typ/iss/iat/exp/purpose/holder/
identities/public-key and no notion of "agent", let alone whose.

## Shape

An IdP-signed claim on the device cert, propagated into the access cert (RPs
verify against the ACCESS cert, so a marker only on the device cert is
invisible to them). Something like:

    "agent": { "of": "danmills@sandmill.org" }

Signed by the IdP, which controls both identities, so it can assert ownership
truthfully — this is exactly the kind of statement an IdP is for.

## Why it matters

- An RP can say "an agent of danmills@sandmill.org posted this" even when
  grantor == grantee, which is what shape 2 was reaching for.
- It gives shapes 2 and 3 a crisp difference: shape 3 = its own identity, link
  NOT machine-readable (pseudonymous); shape 2 = its own identity, ownership
  DISCLOSED and verifiable. That is a real user choice, and the UI in 8v6c
  should offer it as such rather than as two spellings of the same thing.
- It removes the incentive to read meaning out of `+tags`.

## Open questions

- Does the marker belong on the identity or the cert? A cert expires and is
  re-minted, so per-cert is easy; but "is this identity an agent" feels like a
  property of the identity, and a re-mint could silently drop or add it.
- Should `of` be a single identity or a chain (agent of an agent)?
- Interaction with the `namespace` hint (agents/services), which is currently
  described as cosmetic and holder-scoped. Possibly the same concept, promoted
  to something signed.
- The bsky verifier/labeler could surface it ("acting as itself, an agent of
  X"); decide whether that is a new label value or receipt detail only.
- Privacy: this is deliberate disclosure. Make sure shape 3 remains available
  for users who do NOT want the link legible.

Related: browserid-ng-8v6c (the four delegation shapes + the UI that offers
them), browserid-ng-ga3w (spec rewrite to the holder/grantor-grantee model).
