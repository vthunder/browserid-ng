---
# browserid-ng-qer8
title: 'OIDC bridge: claim foo@gmail.com by signing in with Google (in-broker proof method)'
status: in-progress
type: feature
priority: high
created_at: 2026-08-10T04:30:45Z
updated_at: 2026-08-11T21:36:26Z
---

Claim a mailbox by signing in with its provider (Google first) instead of a mailed code. An in-broker OIDC proof method that UPGRADES the mailbox ceremony for a no-primary MX domain with a known OIDC issuer — per-mailbox scope (behaves exactly like smtp), SMTP stays as the equal-strength fallback ceremony.

Build spec: docs/plans/2026-08-10-oidc-bridge-build-spec.md (how). Design: docs/plans/2026-08-02-oidc-bridge-design.md (why).

Reuse: the atproto claim-hop verbatim (routes/handle_claim.rs attach match table + cold-reclaim sub-match; dialog navigate-out/resume; set_email_proof; address_info proof/claim surfacing).
Build new: ProofMethod::Oidc; browserid-broker/src/oidc/ (auth-code client + PKCE + nonce/state); provider->issuer config (Google); JWKS fetch/cache + RS256 ID-token verification (first real jsonwebtoken use — everything else is hand-rolled EdDSA); Gmail normalization + exact-email equality; email_verified mandatory; callback attaches directly (attestation layer deleted).

Decisions pending (in the spec): providers for v1 (Google only recommended); Workspace/custom-domain detection (static consumer-domain allowlist for v1 recommended); provider secrets in broker env / id.env.age.

## Decisions settled (2026-08-10): Google only; Workspace detection YES via MX (offer Google for any no-primary domain whose MX is *.google.com; scope stays per-mailbox — hd/email_verified, exact-email equality, never widen to domain); provider secrets in broker env / id.env.age.

## Core BUILT + committed, INERT (2026-08-10, commit a2d2bc4)
browserid-broker/src/oidc/ = the tested security-critical engine (provider config, Google detection incl. Workspace-via-MX, PKCE, auth URL, flow store, JWKS, RS256 ID-token verification with all claim checks incl. Workspace hd guard) + ProofMethod::Oidc. 12 unit tests green; full broker suite green; NOT wired into the login path (unconfigured = no effect).

REMAINING (SUPERVISED — needs Google client creds + review of production login routing):
- routes: /oidc/claim (build auth URL, begin flow) + /oidc/callback (exchange code at Google token endpoint, fetch+cache JWKS, verify_id_token, then attach via the same match table as complete_handle_claim minus attestation: get_email/transfer_email/add_email_with_type/create_user_no_password + verify_email + set_email_proof(email, Oidc, Some(<iss>#<sub>)) + session create/cookie).
- authority.rs: expose the resolved MX host so a Google-domain check can layer on the Smtp answer; address_info emits proof:"oidc" + claim="/oidc/claim?..." for Google domains (SMTP escape hatch intact).
- dialog.js: a proof==='oidc' lane parallel to the atproto one (reuse CLAIM_RESUME_* navigate-out/resume); redeem collapses to a session_context status check (callback already attached).
- config/main.rs: OIDC_GOOGLE_CLIENT_ID/SECRET (-> sandmill-infra id.env.age), build the provider + wire OidcFlows into AppState.

## Wiring plan (2026-08-11, creds live on id + in id.env.age)

- [x] dnssec: lookup_mx returns the preferred MX exchange host (Option<String>)
- [x] authority.rs: cache + expose mx host; google_oidc_domain() layered on Smtp
- [x] oidc/mod.rs: JwksCache, exchange_code, OidcRuntime; flow-binding notes
- [x] state.rs: oidc: Option<OidcRuntime>
- [x] routes/oidc.rs: GET /oidc/claim + GET /oidc/callback (flow cookie binds browser — login-CSRF guard), mount
- [x] email.rs: address_info proof:"oidc" + claim URL for Google domains (SMTP hatch intact)
- [x] main.rs: OIDC_GOOGLE_CLIENT_ID/SECRET -> OidcRuntime
- [x] dialog.js: oidc lane (popup + redirect + resume=oidc_claim)
- [x] tests: oidc_claim_test.rs (10 tests: mock token endpoint + JWKS, full callback attach, reclaim semantics, csrf-bind guard); authority google detection
- [x] full broker suite green (5a07031); deployed to prod 2026-08-11, verified: OIDC enabled in logs, address_info advertises oidc, /oidc/claim 303s to Google with PKCE + flow cookie
- [ ] live gmail claim test through the dialog (user, in progress)
