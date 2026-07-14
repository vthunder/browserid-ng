---
# browserid-ng-7ck6
title: 'Optional: offline pinned-fallback verify for Rust RPs'
status: draft
type: feature
priority: low
created_at: 2026-07-12T20:15:22Z
updated_at: 2026-07-12T20:15:22Z
---

Offline Rust verifiers (browserid_core::assertion::verify, browserid_rp::Verifier)
are primary-only — they enforce issuer == email-domain (assertion.rs ~336,
rp/lib.rs ~116). So fallback identities (human or agent, incl. the new
sub-addressed agents from 0phq) can only be verified via the DNS-aware hosted
/verify. Scoped OUT of 0phq deliberately.

If we want Rust RPs to verify fallback identities offline with pinned keys, add an
additive `trust_fallback_issuer(domain, key)` on rp::Verifier + a
`verify_with_fallback` core method that accepts a trusted fallback issuer for
emails whose domain isn't independently pinned (mirrors the DNS verifier's
accepted_fallbacks, but offline). Non-breaking; existing primary verify() intact.
Then the consent_flow/e2e/rp_flow tests could exercise fallback offline instead of
using a primary human as a stand-in.
