---
# browserid-ng-shyj
title: Provenance-aware, session-level credential minting
status: todo
type: epic
priority: high
created_at: 2026-08-19T13:33:35Z
updated_at: 2026-08-19T14:13:26Z
---

Redesign broker credential issuance so sessions carry a level (lightweight vs full) and every mint decision consults how an email was verified (proof method / email type). Motivated by audit finding M1 (browserid-ng-7ww7), related to audit epic browserid-ng-wre6, but broader.

## Problem (verified 2026-08-19)
- Session.auth_level hard-coded to "password" for every session (session.rs:69-80); Session row has no level field. An OIDC cold-claim session (no password, oidc.rs:386-392) is indistinguishable from a password login.
- No issuance path reads Email.proof. /device/issue owned_verified_email (device.rs:60-76) checks only verified==true, so it mints broker-signed auth + wildcard-config certs for ANY verified email regardless of type/provenance. Only /fedcm/assertion looks at email_type (Secondary), and even it ignores proof.
- Password reset (reset.rs:136-150) revokes nothing and unverifies nothing; unverify_email exists in the store trait but has NO production caller.

## Email classes
- E1: domain-vouched (primary IdP), EmailType::Primary
- E2: browserid.me-vouched via bridge (OIDC/Google/bsky), Secondary + proof Oidc/Atproto
- E3: browserid.me-vouched via SMTP loop, Secondary + proof Smtp

## Target model (agreed with owner 2026-08-19)
Session levels (SAME 30d TTL for both; level gates capability, not lifetime):
- Lightweight: established ONLY by E1/E2 proof (primary presentation / live bridge), no password. Can list all emails; can mint E1/E2 (delegated to voucher). Selecting an E3 prompts for password.
- Full: established by the account password. Additionally mints E3 certs for the account's verified addresses.

E3 / password rules:
- E3 addresses always live on password-backed accounts: adding the FIRST E3 to an account forces the user to set a password. No passwordless E3 accounts, no cookie-only no-account cert issuance.
- Minting/using an E3 cert requires a full session. Fresh SMTP proof of an E3 does NOT silently mint its cert; the user enters the password (or, if forgotten, uses reset).
- Inbox control remains a legitimate authenticator, but for a password-backed account its channel is the reset flow, not a silent mint.

Invariants:
1. Adding/using E1 or E2 establishes a lightweight session, no password.
2. Lightweight session: dialog lists all emails; selecting an E3 prompts for the password.
3. E1/E2 minting is NEVER authorized by the broker session alone — always delegated to primary/bridge, which verifies (its own choice of how, may reuse a live OAuth session) and decides cert TTL (E2 default ~1wk, may vary per-address, may use OAuth hints). Even though browserid.me signs E2 certs, issuance requires a live bridge proof.
4. Password reset = an SMTP challenge on any one of the account's SMTP addresses -> sets a new password (full session); that address is thereby verified, and every OTHER E3 address is marked for re-verification. So control of one E3 inbox + a reset cannot pivot to minting a different E3 address.
5. Rollout forces re-auth: existing live sessions do not silently become full sessions.

## Design-for-no-regression
- Single mint chokepoint authorize_mint(email, session_level) with an EXHAUSTIVE match on (EmailType x ProofMethod) so new proof methods/routes cannot silently skip the check.
- Table-driven test matrix (email_type x proof x session_level) -> expected decision, asserted against every issuance route.
- Test asserting no issuance route mints without going through the chokepoint.

## Children
Session levels; mint chokepoint; bridge-verified E1/E2 minting + voucher-decided TTL; reset re-verification + force-set/enter password; fold /auth/device_cert (7ww7) into the chokepoint.

## Also under this epic
- browserid-ng-iudv (bug): passwordless set-password regression — costs a second SMTP code because in-session /wsapi/set_password was removed. Blocks kgb9 (set-on-add, single roundtrip).
