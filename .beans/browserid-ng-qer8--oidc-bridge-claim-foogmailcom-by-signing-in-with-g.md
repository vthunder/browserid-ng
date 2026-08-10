---
# browserid-ng-qer8
title: 'OIDC bridge: claim foo@gmail.com by signing in with Google (in-broker proof method)'
status: draft
type: feature
priority: high
created_at: 2026-08-10T04:30:45Z
updated_at: 2026-08-10T04:30:45Z
---

Claim a mailbox by signing in with its provider (Google first) instead of a mailed code. An in-broker OIDC proof method that UPGRADES the mailbox ceremony for a no-primary MX domain with a known OIDC issuer — per-mailbox scope (behaves exactly like smtp), SMTP stays as the equal-strength fallback ceremony.

Build spec: docs/plans/2026-08-10-oidc-bridge-build-spec.md (how). Design: docs/plans/2026-08-02-oidc-bridge-design.md (why).

Reuse: the atproto claim-hop verbatim (routes/handle_claim.rs attach match table + cold-reclaim sub-match; dialog navigate-out/resume; set_email_proof; address_info proof/claim surfacing).
Build new: ProofMethod::Oidc; browserid-broker/src/oidc/ (auth-code client + PKCE + nonce/state); provider->issuer config (Google); JWKS fetch/cache + RS256 ID-token verification (first real jsonwebtoken use — everything else is hand-rolled EdDSA); Gmail normalization + exact-email equality; email_verified mandatory; callback attaches directly (attestation layer deleted).

Decisions pending (in the spec): providers for v1 (Google only recommended); Workspace/custom-domain detection (static consumer-domain allowlist for v1 recommended); provider secrets in broker env / id.env.age.
