---
# browserid-ng-k3rg
title: 'On-chain / SBO verifier: already DNSSEC-conformant — add chain-validation test coverage + conformance note'
status: todo
type: feature
priority: normal
created_at: 2026-08-09T15:33:33Z
updated_at: 2026-08-10T02:55:31Z
parent: browserid-ng-g5qt
---

Deferred sibling of browserid-ng-0p5f. The SBO/on-chain attribution verifier resolves an issuer's signing key to check attributed actions ("action X by agent Y under authority Z, verifiable offline/on-chain"). It must root trust the same way as the other verifiers: resolve the key from the authenticated _browserid DNSSEC record (+ support host=), NEVER from .well-known — otherwise it breaks for hosted-primary tenants and violates the spec (§3: DNSSEC is the sole root of trust).

## To do
- [ ] Locate the SBO/on-chain verifier (likely in ~/src/mingo sbo-core / poster path, or an on-chain module) and how it currently resolves issuer keys.
- [ ] If it reads keys from .well-known or a pinned config, switch it to the shared browserid-dnssec resolver (resolve_idp_key), or — where an on-chain context can't do live DNS — pin a DNSSEC-obtained key with a documented refresh, never a .well-known-fetched one.
- [ ] For truly offline/on-chain verification, define how a DNSSEC proof (detached) accompanies the attribution so a verifier without live DNS can still root trust (relates to core §6.2 detached-DNSSEC proofs).
- [ ] Tests + conformance note.

## Context
Shared resolver landed in browserid-ng-0p5f (crate browserid-dnssec). mingo's login verifier + browserid-rp were fixed there. This bean is the third verifier the user flagged. On-chain adds the wrinkle that live DNS may be unavailable at verify time, so detached DNSSEC proofs may be needed.

## Review findings (2026-08-10): already DNSSEC-conformant

Verified the SBO/on-chain verifier directly (lives in ~/src/sbo, crate sbo-core). It is ALREADY conformant — no .well-known key-fetch bug. Trust chain:
- sbo-daemon validate.rs:182 (on-chain replay) → message_attribution → verify_device_attribution (device_attribution.rs:97).
- Per-issuer key comes from extract_provider_key (attribution.rs:164): verify_rr_stream validates the RFC 9102 detached DNSSEC proof to the pinned IANA root, then the key is read from the `_browserid.<iss>` TXT record's public-key= (DnsRecord::parse). NEVER .well-known, never pinned/genesis.
- device_attribution.rs: RRSIG windows enforced at inclusion_time (block-deterministic, not wall-clock) :186-195; authority domain==iss || is_broker for BOTH grantor and grantee :202-213; join resolves each cert key ONLY from the proven set :218-230; SBO envelope key bound to access_cert.access_key :232-240; result window = intersection of cert + all proof windows.
- Detached proofs: produced by sbo-capture capture_evidence (RFC 9102), posted self-authorizing to /sys/dnssec/<domain>, refreshed lazily via GET /v1/dnssec (http.rs:535-568; mingo poster.rs margin 3600s).
- Hosted-primary tenant (key in DNS + host=, no key at own .well-known) VERIFIES CORRECTLY — key comes from _browserid DNS; host= only affects .well-known discovery, which the verifier never calls. danmills@sandmill.org would verify on-chain.
- Only .well-known touch in the SBO stack: sbo-capture discover() (lib.rs:90) — MINT/capture flow, returns a SupportDocument (endpoints), never a signing key. Not a verifier path.

## Residual (not a live bug) — rescoped
- [ ] Test coverage: the DNSSEC-chain validation (verify_rr_stream) is covered only by an #[ignore]d live test; dnssec-prover hardcodes the IANA root and TrustAnchors.root_ksk is informational (can't inject a test root). Window/authority/join are unit-tested offline. Add a fixture-based RFC 9102 proof so the chain-validation path runs in CI.
- [ ] Conformance note: document that on-chain verification is DNSSEC-rooted + offline via detached proofs, and that is_broker(iss) must be correctly configured for fallback attribution.
- Note: the original "fix a .well-known key-fetch" concern does NOT apply here — the code already resolves from _browserid DNSSEC.
