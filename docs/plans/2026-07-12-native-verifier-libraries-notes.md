# Native verifier libraries — implementation notes (exj6)

Status: **the hosted `/verify` path + a thin JS wrapper are shipped** (see
`docs/verify-quickstart.md` and `sdk/js/`). This note captures what an
**in-process** (no-hosted-call) verifier in JS/Python/Go must do, distilled from
the Rust reference (`browserid-broker/src/verifier.rs`,
`browserid-core/src/{assertion,certificate,warrant}.rs`).

> **Sequencing.** Native ports should follow spec v0.4 stabilizing the delegation
> chain format (bean 5zdh). Building them against today's format risks rework in
> the warrant/chain parsing. The hosted path already gives RPs any-language
> verification, so native libs are an optimization (no third-party trust, offline
> verification), not a blocker.

## Algorithm (must match the Rust reference exactly — fail closed at every step)

Input: `assertion` (`certificate~assertion`, optionally `~warrant`), `audience`,
`accepted_fallbacks` (default `{trusted broker domain}`).

1. **Parse** the backed assertion. Require ≥1 certificate + 1 assertion. An agent
   certificate WITHOUT a warrant is rejected at parse time.
2. Extract `issuer` (cert issuer), `email` (cert subject), `email_domain`,
   `expires` (assertion `exp`).
3. **Discover `email_domain` via DNSSEC-first resolution.** This is the crux and
   the hard part of a native port:
   - Look up the `_browserid` DNS record with DNSSEC validation. A domain is a
     **primary IdP** only if it publishes an authenticated record. `.well-known`
     is consulted for **endpoint discovery only — never as a source of trusted
     keys** (browserid-ng-28uc: no well-known key trust, no downgrade).
4. **Authorize the issuer + pick the key document:**
   - **Primary** (`email_disc.is_primary`): require `issuer == email_domain`
     (only a domain's own primary may vouch for it — no fallback override). Use
     that domain's DNSSEC key doc.
   - **No primary**: require `issuer ∈ accepted_fallbacks`, else fail. Resolve the
     issuer's identity key via **the issuer's OWN DNSSEC record** (reuse the doc
     if `issuer == authoritative_domain`, else discover `issuer`).
5. **Verify signatures + claims** (`verify_signatures_with_doc`):
   - `assertion.audience == audience` (exact string).
   - assertion not expired; certificate not expired.
   - assertion signature verifies under the **certificate's** public key (Ed25519).
   - certificate signature verifies under the **issuer's** DNSSEC key (Ed25519).
6. **Agent presentation** (`cert.is_agent()`): a warrant is load-bearing.
   `warrant.verify_for(cert, audience, issuer_key)` must succeed — it checks the
   warrant is signed by the delegator's identity key (same IdP as the agent — the
   identity-domain rule), bound to this `audience`, for this agent — and yields
   the granted `scopes`. Surface `{ parent, scopes }`.
7. **Revocation** (status lists, core §6.4): collect `status` refs from certs +
   warrant. For refs whose `uri` is a list you can authoritatively resolve, check
   the revoked bit. In the broker this is a DB lookup; a native lib fetches the
   signed status list over HTTPS and checks the bit (with caching). No federated
   IdP issues status claims today, so only the trusted broker's list matters in
   practice — but a general lib must fetch+verify the signed list.

## Per-language notes

- **Ed25519**: JS `crypto.subtle` (Node 18+ / modern browsers) supports `Ed25519`;
  Python `cryptography` (`Ed25519PublicKey`); Go `crypto/ed25519`.
- **DNSSEC** is the real work:
  - JS/Node: no batteries-included validating resolver; either shell to a
    validating resolver, use a DNS-over-HTTPS provider that sets the AD bit **and
    is itself trusted**, or port a DNSSEC validator. Do NOT trust an unvalidated
    resolver — that defeats the entire trust root.
  - Python: `dnspython` can fetch DNSKEY/RRSIG; validation must be implemented
    or delegated to a validating resolver.
  - Go: `github.com/miekg/dns` for records + manual DNSSEC chain validation.
  - Given this cost, the first "native" lib may still lean on a trusted validating
    resolver for the DNSSEC step while doing crypto locally — document that trust
    boundary clearly.
- **JWT/JWS**: base64url segments, `EdDSA`; reuse the exact canonicalization the
  Rust core uses (header/payload joined with `.`, raw Ed25519 over the UTF-8
  bytes). Cross-check vectors against `browserid-core` tests.

## Fail-closed defaults every port MUST bake in (from the bean)

- Reject unrecognized certificate `typ`.
- Require a warrant in the chain for agent certs.
- Enforce `aud`.
- Surface (don't silently drop) agent scopes.
- Status-list check with cache.

## Test strategy

Generate golden vectors from the Rust core (valid human assertion, valid agent
assertion+warrant, expired, wrong-audience, wrong-issuer, revoked) and assert
byte-for-byte identical verdicts across all ports and the hosted endpoint.
