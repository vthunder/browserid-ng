# Design — Typed signing extension (assertions + SBO envelopes)

**Date:** 2026-06-24
**Status:** Design draft for review (no code yet)
**Author context:** Driven by the SBO "Mingo" demo (`~/src/sbo`,
`docs/plans/2026-06-24-phase7-mingo-client-plan.md`), but proposed as a
**principled, general capability** for browserid-ng — not an SBO-specific bolt-on.

## Summary

browserid-ng's in-browser agent today generates a per-email keypair in the
**broker/IdP origin**, gets the public half certified by the IdP (`cert_key`), and
signs **assertions** with the private key — which never leaves that origin. RPs
talk to the agent over the cross-origin channel and can request exactly one thing:
an assertion.

This design adds a **second, domain-separated, gated signing capability**: the
same certified key can sign a **typed payload** — initially an *SBO envelope* —
that is structurally distinct from an assertion. The motivation: a self-owned
data protocol (SBO) needs the cert-bound key to sign its writes, and the key
browserid already manages for that email is the right key, in the right place. The
alternative (a second, duplicate isolated keystore in the consuming app) wastes
the isolation browserid already provides and creates a second thing to secure.

Framed generally: **browserid-ng grows a typed signing API** — the certified key
may sign one of several *domain-separated message types* (assertions today; SBO
envelopes next; others later), each one **additive, origin-gated, and
consent-gated**. The existing federated-login (assertion) contract for ordinary
RPs is **unchanged**.

## What exists today (grounding)

- Keygen in the browser, broker origin: `static/common/js/lib/jwcrypto-compat.js`
  (`generateKeypair` → `crypto.subtle.generateKey`, Ed25519).
- Pubkey certified by the IdP: `static/common/js/user.js` `certifyEmailKeypair` →
  `network.certKey(email, pubkey, …)` → broker `/wsapi/cert_key`.
- Per-email `(keypair, cert)` persisted in broker-origin storage:
  `user.js` `persistEmailKeypair` (currently exports the **private** key to JWK in
  `localStorage` — see Hardening).
- Assertions signed in-agent: `browserid-core/src/assertion.rs`
  (`Assertion::create` / `encode_and_sign`), JWS over the user key.
- RP ↔ agent transport: the cross-origin dialog/iframe channel
  (`winchan.js`, `lib/jschannel.js`, `communication_iframe.html`, `dialog.js`).

So the cert-bound key for `alice@mingo.place` **already lives in the agent** once
that identity is provisioned. This design exposes a *new operation* over it.

## The extension

### A typed signing channel operation

Add a channel message type alongside the existing assertion request:

```
request:  { type: "sign", payload_type: "sbo-envelope", canonical: <bytes>, email: <addr> }
response: { signature: <base64url>, cert: <Auth-Cert JWT>, pubkey: <jwk> }
```

- `payload_type` selects the typed signer. `"assertion"` remains the existing
  path; `"sbo-envelope"` is the new one. Unknown types are rejected.
- `canonical` is the **caller-built** canonical signing bytes (for SBO, produced
  by `sbo-wasm` — the single source of truth for SBO's signing-byte layout). The
  agent does **not** trust these blindly — see Validation.
- The agent signs with the `(key, cert)` it holds for `email` and returns the
  signature **plus the cert** (which is the SBO `Auth-Cert`).

Keeping SBO's serialization in `sbo-wasm` (not in the agent) avoids coupling
browserid-ng to SBO's wire format; the agent only needs a **validator** (below).

### Validation (the agent never signs opaque bytes)

Before signing a `sbo-envelope`, the agent MUST:

1. **Parse it as an SBO envelope** and reject anything that is not well-formed
   (must begin with the `SBO-Version:` header block; required headers present;
   canonical header order). This is what makes the capability safe: the agent
   signs only things demonstrably of the declared type.
2. **Bind to the agent's identity:** the envelope's `Owner` MUST equal `email`
   (the identity whose cert will be attached) and its `Public-Key` MUST equal this
   key's public key. This stops a caller from getting the agent to sign a write
   that claims a *different* owner or key.
3. (Optional, stricter) recompute the canonical bytes from the parsed fields and
   require equality with `canonical`, so a caller can't smuggle extra trailing
   bytes past the parser.

### Domain separation — by construction, not by tag

SBO's signature must be over **exactly** sbo-core's canonical bytes (its verifier
re-derives them), so the agent cannot prepend its own domain tag. Separation
instead comes from **structurally disjoint preimages**, enforced by the parsers:

- An **assertion** preimage is a JWS signing input: `<base64url>.<base64url>`
  (ASCII, dot-separated). The assertion signer only ever produces/sigs this shape.
- An **SBO envelope** canonical content begins with the literal `SBO-Version:`
  header block — never a valid JWS signing input.

Because each typed signer **parses and only accepts its own shape**, the agent can
never be coerced to emit an SBO signature through the assertion API (or vice
versa). The `SBO-Version:` prefix is the recognizable discriminator; a JWS preimage
can't start with it, and an SBO canonical content can't be a meaningful assertion.
(If we later add a payload type whose shape *could* overlap, that type must carry
an explicit in-preimage domain tag.)

### Gating: origin + consent

- **Origin allowlist / user consent:** the `sbo-envelope` capability is offered
  **only** to origins the user has authorized (a one-time per-app grant —
  "Mingo may post to SBO as you"), not to all RPs. The assertion capability's
  general availability is unchanged; the new capability is opt-in per origin.
- **Session-scoped, not per-write:** consent is per app/session (social apps sign
  constantly; per-write prompts are unusable). The grant is revocable and bounded
  by cert lifetime.
- **No raw-key access, ever:** the response returns a signature + cert, never the
  private key (as with assertions today).

### Custody hardening (improves browserid-ng regardless)

Switch the agent's key handling from **extractable JWK in `localStorage`** to a
**non-extractable `CryptoKey`** (`generateKey(..., extractable: false)`), persisted
via IndexedDB `CryptoKey` storage. Then even broker-origin XSS cannot exfiltrate
the raw key — it can only request signatures while resident. This benefits
assertions too; the typed-signing extension simply assumes it.

## Threat model

| Threat | Mitigation |
|---|---|
| Malicious RP coaxes the agent to sign arbitrary/dangerous bytes | Agent signs **only parsed, well-formed** payloads of a declared type; never opaque bytes. |
| Cross-type confusion (SBO sig usable as assertion or vice versa) | **Structurally disjoint preimages**, enforced by each typed parser; `SBO-Version:` discriminator. |
| Caller forges a write as a different owner/key | Agent enforces `Owner == email` and `Public-Key == agent key` before signing. |
| Unauthorized origin uses the capability | **Origin allowlist + explicit user grant** per app; capability not offered to arbitrary RPs. |
| Raw private key theft (XSS) | **Non-extractable `CryptoKey`**; key never serialized to storage or returned. |
| Authorized app abuses the grant (posts as user while active) | Inherent to any signing delegation; bounded by per-app grant (revocable) + cert TTL; this is the residual, accepted risk. |
| Replay across origins | Each grant is origin-scoped; signatures are over content that includes SBO-side anti-replay (the envelope is the write itself; ordering/inclusion handled by SBO). |

## Why not the alternatives

- **Separate isolated signing agent in the consuming app (duplicate keystore).**
  Re-implements browserid's origin isolation + key management + a second cert for a
  key browserid already holds — more security-critical surface, duplicated. The
  thing this design avoids.
- **Reuse the *assertion* signer for envelopes (sign raw bytes).** The original
  unease: turns the agent into an arbitrary-bytes oracle. Rejected — the typed,
  parse-then-sign design is the safe version of "use the existing key."
- **Hold the SBO key in the app origin (extractable).** XSS steals it → persistent
  forgery. Rejected.

## Open questions

1. **Channel API shape** — extend the existing dialog/`jschannel` protocol, or a
   dedicated lighter postMessage surface for typed signing? (Lean: extend the
   existing channel for one transport.)
2. **Consent UX** — one-time per-app grant screen; where stored/revoked.
3. **Validator location** — a minimal SBO-envelope validator in the agent (JS), or
   reuse `sbo-wasm` inside the agent for parse + canonical recompute? (Lean:
   `sbo-wasm` for exact parity, if bundle size is acceptable.)
4. **Generality** — define the typed-signer registry now (assertion, sbo-envelope)
   or hard-code the two? (Lean: a small registry so future types are additive.)
5. **Spec note** — record in the SBO Authorization spec that first-party writes
   require an IdP that runs `cert_key` over the writer's key; assertion-only
   third-party IdPs (T0) support login but not first-party writes (→ T1).

## Next steps

1. Review this design + threat model.
2. Prototype the validator + one typed sign op against a throwaway SBO envelope
   (ties into SBO Phase 7.0 `sbo-wasm` spike: build canonical bytes → agent signs →
   `sbo-core` verifies).
3. Then: channel API, consent UX, non-extractable key migration.
