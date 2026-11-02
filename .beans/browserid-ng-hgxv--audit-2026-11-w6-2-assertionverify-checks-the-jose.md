---
# browserid-ng-hgxv
title: '[Audit 2026-11] W6-2: Assertion::verify checks the JOSE header like every other object'
status: todo
type: bug
priority: normal
created_at: 2026-11-02T22:43:20Z
updated_at: 2026-11-02T22:43:20Z
parent: browserid-ng-ag1l
---

Findings: W6-2. Severity: Low / informational (not exploitable: Ed25519 still has to verify under the access key; it is the one typed-signing inconsistency left). Decision: none needed.

Where: browserid-core/src/assertion.rs:570-582: Assertion::verify never reads the JOSE header; every other object pins alg == EdDSA in jws_verify.

Change: verify assertions through jws_verify (or pin alg/typ in Assertion::verify) so the header is checked like every other object. W4-40 (assertions carry no iat, Q19) touches the same object; land together if Q19 is (a).

Acceptance: the passing test w6_2_assertion_without_a_valid_ed25519_signature_rejects_regardless_of_header stays green; add a test that an assertion with alg != EdDSA is rejected even with a valid Ed25519 signature.

Reports: ws6 §2. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.
