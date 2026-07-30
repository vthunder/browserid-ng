---
# browserid-ng-77mw
title: 'Broker: accept handle attestation, issue as fallback'
status: completed
type: feature
priority: normal
created_at: 2026-07-30T20:35:08Z
updated_at: 2026-07-30T22:31:54Z
parent: browserid-ng-tsqk
blocked_by:
    - browserid-ng-031k
---

- [x] POST /wsapi/complete_handle_claim: parses/verifies the attestation (trusted-attestor check, DNSSEC-discovered key, aud=broker domain, expiry, jti replay guard), attaches the identity verified
- [x] Proof method stored: emails.proof ('smtp' default via migration v22, grandfathering all existing rows) + proof_subject (the DID) — set to atproto+DID on claim
- [x] Scope asymmetry: the claim route accepts ANY label at exactly the attested handle (domain-wide proof, by construction); SMTP lane still verifies only the mailed address (unchanged, structural). Cold re-claims: same stored DID → signs into the owning account; different DID (handle changed hands) → identity moves to a fresh account, old account NOT inherited
- [x] Device certs: nothing changed — the attached identity is an ordinary verified secondary, issuance runs the existing fallback path with iss=browserid.me
- [x] Verifier: untouched (no diff under src/verifier.rs); RP-side rule runs verbatim

## Summary of Changes

- `browserid-core/src/attestation.rs` (new): `HandleAttestation` (EdDSA JWS, typ browserid-handle-attestation-v1, 300s expiry, aud-bound, jti) with create/parse/verify + tests.
- `browserid-broker/src/routes/handle_claim.rs` (new): the route; trusted attestor from `handle_attestor` (derived from ATPROTO_BRIDGE_URL host in main.rs), key via DNSSEC primary discovery (test override field), in-memory jti replay guard.
- Store: migration v22 adds emails.proof + emails.proof_subject; `set_email_proof` on UserStore (sqlite/memory/Arc).
- Tests: `tests/handle_claim_test.rs` — cold claim creates account+session, any-label/wrong-domain, forged/misdirected/untrusted attestations, single redemption, same-DID re-claim signs back in, new-DID claim does not inherit the old account, CSRF on signed-in claims, unconfigured refusal.

Dialog integration (navigating out to the bridge and posting the attestation back) is bean xcy6.
