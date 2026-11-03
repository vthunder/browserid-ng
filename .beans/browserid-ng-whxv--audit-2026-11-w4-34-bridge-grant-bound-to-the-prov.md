---
# browserid-ng-whxv
title: '[Audit 2026-11] W4-34: bridge grant bound to the proving session'
status: completed
type: bug
priority: normal
created_at: 2026-11-02T22:43:20Z
updated_at: 2026-11-03T08:37:00Z
parent: browserid-ng-ag1l
---

Findings: W4-34. Severity: Low. Decision: Q18 settled 2026-11-02: (a) bind the bridge grant to the proving session; it also matters for Q6, where agent-provision will redeem grants.

Where: browserid-broker/src/state.rs:253-284, routes/device.rs:112: a bridge grant is per (account, email), not per session; any Full session of the account redeems it at /device/issue within 10 min, so a second session (e.g. enrolled with a leaked password) mints certs for the E2 address the moment the user re-proves it elsewhere, never seeing Google. fb §3.2 says "a live bridge grant" without saying whose.

Change under (a): store the session id in the grant and require it at redemption (/device/issue and, after the W5-7 bean, agent-provision/complete). Spec edit: fb §3.2 names the owner.

Acceptance (un-ignore): browserid-broker/tests/audit_2026_11_ws4.rs: w4_34_bridge_grant_is_redeemable_only_by_the_proving_session (pin pin_bridge_grant_is_single_use keeps passing).

Reports: ws4 §2. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.



## Summary of Changes

- state.rs: `BridgeMintGrant` gains `session_id: Option<String>`. New `record_bridge_grant_for_session(user_id, email, ttl, session_id)` and `take_bridge_grant_for_session(user_id, email, session_id)`; the existing `record_bridge_grant` / `take_bridge_grant` keep their signatures and now mean the UNBOUND form (a grant nobody's session owns; `take_bridge_grant` redeems only those — a session-owned grant stays put), so the registrar agent's agent-provision caller still compiles and gets fail-closed behaviour.
- routes/oidc.rs and routes/handle_claim.rs: both bridge legs record the grant for the session that ran the ceremony — the cookie session, or the Lightweight session a cold claim opens (the grant is now recorded after that session is created).
- routes/device.rs: `mintable_email` takes `grant_session: Option<&str>`; the cookie-session form passes its session id and redeems with `take_bridge_grant_for_session`; the registry-login-key form passes `None` (it ran no ceremony, so it only ever sees unbound grants).
- Tests: un-ignored `w4_34_bridge_grant_is_redeemable_only_by_the_proving_session`; `pin_bridge_grant_is_single_use` still passes.
- Spec: fb §3.2 "a live bridge grant" should name the owner (the session that proved); not edited here — flagged for the spec owner.
