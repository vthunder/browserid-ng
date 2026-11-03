---
# browserid-ng-cn3f
title: '[Audit 2026-11] W4-31/W4-32: /idp session cookie re-reads must_change (password epoch) and carries a typ tag'
status: completed
type: bug
priority: high
created_at: 2026-11-02T22:43:20Z
updated_at: 2026-11-03T08:27:25Z
parent: browserid-ng-ag1l
---

Findings: W4-31 and W4-32 (both in the stateless /idp session cookie). Severity: Medium for W4-31 (WS4 rated it Low-Medium; the ledger takes Medium because it is the July H2 class: an admin password reset does not stop an open session from issuing 90-day certs for up to 2 h). W4-32 is Low (July L3 shape recurring: raw root-key signature over an untagged payload; not exploitable today because every other root-key signature is a JWS with a dot in the signing input). Decision: none needed.

Where: browserid-broker/src/routes/hosted_idp.rs:113-158 (cookie mint/verify: b64(json{email,exp,mc}).b64(sig) under the root key), :355-362 (/idp/device_cert reads must_change from the cookie, not the roster), :1190-1196 (roster_password sets must_change in the roster only). Roster Disabled is re-read (pinned); the reset is not.

Change: carry a password epoch (or the roster password hash prefix) in the cookie and re-read must_change and the epoch from the roster at issuance; add "typ":"idp-session" to the signed payload (or HMAC under a key derived from the root key for cookies only).

Acceptance (un-ignore) in browserid-broker/tests/audit_2026_11_ws4.rs: w4_31_admin_password_reset_stops_an_open_idp_session_from_issuing, w4_32_idp_session_cookie_payload_carries_a_type_tag. Pins pin_roster_disable_stops_an_open_idp_session_from_issuing and pin_idp_session_cookie_payload_is_signature_bound keep passing.

Reports: ws4 §2 and §4 (L3 row). Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.



## Summary of Changes

- routes/hosted_idp.rs: the `/idp` session cookie payload is now `{typ:"idp-session", email, exp, mc, pe}`; `idp_session` refuses any payload without `typ == "idp-session"` (W4-32), so no other root-key signature can be confused with it. `pe` is the password epoch — a 16-char prefix of sha256(roster password hash), never the hash — recorded at login and after a self-service password change.
- New `idp_session_live`: re-reads the roster at use (tenant active, entry active, epoch unchanged) and returns `must_change` from the roster, not the cookie. `/idp/device_cert` issues only for a live session (403 `session no longer valid; sign in again` after an admin reset, 401 with no cookie, 403 `password change required` from the roster flag); `/idp/whoami` reports the live state so the page re-prompts.
- Tests: un-ignored `w4_31_admin_password_reset_stops_an_open_idp_session_from_issuing` and `w4_32_idp_session_cookie_payload_carries_a_type_tag`; pins `pin_roster_disable_stops_an_open_idp_session_from_issuing` and `pin_idp_session_cookie_payload_is_signature_bound` still pass (audit_2026_11_ws4 16 passed; hosted_primary_test 20 passed).
- Deploy note: existing /idp cookies (no `typ`) stop validating; tenant users sign in again.
