---
# browserid-ng-cd6r
title: '[Audit 2026-11] D9: accounts and lookup verify the possession proof and replay before any network fetch'
status: todo
type: bug
priority: normal
created_at: 2026-11-02T22:43:20Z
updated_at: 2026-11-02T22:43:20Z
parent: browserid-ng-ag1l
---

Findings: D9 (partial). Severity: Low. Decision: none needed (I2: no network before the cheap local checks).

Where: browserid-registrar/src/account.rs:86-108: on accounts and accounts/lookup, verify_device_cert (DNSSEC discovery + status fetch via browserid-broker/src/registrar_glue.rs:1057-1112) runs before the possession proof p.verify and before the header-proof replay check. The cert signature genuinely needs the issuer key, so the fetch cannot precede it entirely; the possession proof, jti replay, htu and bh checks can and should run first. Unauthenticated amplification only (the discovery client itself is the W6-5 bean).

Change: reorder carried_certs: parse cert -> parse and verify the proof under claims.public_key -> check_claims -> replay -> then verify_device_cert.

Acceptance (un-ignore): browserid-broker/tests/authz_matrix_test.rs: lookup_checks_the_possession_proof_before_any_fetch (currently ignored because it reaches the network on the existing-account path; after the reorder it must pass without network). D10 (possession proofs not replay-cached) was refuted and needs nothing.

Reports: ws5 §1. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.
