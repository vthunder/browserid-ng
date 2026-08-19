---
# browserid-ng-dw35
title: '[M7] Unauthenticated account enumeration across lifecycle endpoints'
status: todo
type: bug
priority: normal
created_at: 2026-07-28T23:54:23Z
updated_at: 2026-08-17T09:23:36Z
parent: browserid-ng-wre6
---

docs/security-audit-2026-07-29.md (M7). Oracles: stage_reset 404-vs-200 (reset.rs:48), user_creation_status (account.rs:277), email_addition_status (email.rs:556), address_info (email.rs:521), stage_user 409. Feeds C1/M6.
- [ ] Normalize responses/timing where feasible

## Re-verification 2026-08-17 — STILL VALID, none normalized, new oracles

- stage_reset (reset.rs:45-48): get_user_by_email → EmailNotFound 404 vs 200 (error.rs:160). New SMTP/throttle checks (reset.rs:54/57) sit AFTER the existence check, so they don't mask it.
- user_creation_status (account.rs:277, branch :296-302): "complete" for existing user vs pending/unknown.
- email_addition_status (moved to email.rs:768, oracle :777-795).
- address_info (moved to email.rs:594) — WORSE than boolean: returns `state` derived from has_password(user_id) (email.rs:728-737), leaking existence AND whether account is password-backed. Also now returns `proof`/`claim` (email.rs:703-725) leaking atproto-vs-Google-hosted domain classification, and triggers attacker-controlled DNS resolution per query (email.rs:636-641).
- stage_user 409 EmailAlreadyExists (account.rs ~:70-72, error.rs:161).

Authenticated-only (not new unauth oracles): hosted_idp tenant_create (hosted_idp.rs:772/:819-829) requires session+CSRF; OIDC claim/callback have no existence-distinct responses.

Decision needed: how much to normalize vs "no such account" UX. Sharpest new leak is address_info — recommend stripping password-backed/Google-hosted classification and gating it behind a session as the minimum.
