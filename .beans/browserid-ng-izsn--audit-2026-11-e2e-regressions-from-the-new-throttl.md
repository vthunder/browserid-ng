---
# browserid-ng-izsn
title: '[Audit 2026-11] e2e regressions from the new throttles: login_required counted as a failure; successful code completions counted against the per-IP cap'
status: completed
type: bug
priority: high
created_at: 2026-11-06T15:10:45Z
updated_at: 2026-11-06T15:12:37Z
parent: browserid-ng-ag1l
---

Found by the pre-deploy Playwright run on 2026-11-06 (CI does not run e2e). Two per-source throttles introduced by the audit locked a shared address out under ordinary use:

- registry `POST /api/v1/login` (bean 4r2j, D8/W5-9): the expected `403 login_required` first answer of every page login was counted as a failure, so 20 sign-ins from one address in 5 minutes answered 429 to everyone behind it (office NAT, carrier NAT, the e2e suite).
- `/wsapi/complete_signin_code` and `/wsapi/complete_email_addition` (bean eetq, July C1 residual): right answers counted against the 30-per-15-minutes per-IP cap, so 30 ordinary sign-ins from one address locked it out.

Also: the e2e specs still used the removed `Agent.bootstrap` lane (W4-44) and sent refresh without `client_id` (W4-11).

- [x] registrar marks the login_required answer; the throttle skips it (test api_v1_login_required_is_not_a_failure)
- [x] completion cap counts only wrong guesses (test successful_completions_are_not_throttled)
- [x] e2e: helpers/agent-bootstrap, guestbook signs the filing with the agent, refresh sends client_id
- [x] full Playwright run green on a warm broker

## Summary of Changes

- browserid-registrar/src/api.rs: `LoginRequiredAnswer` response extension on the `403 login_required` answer.
- browserid-broker/src/routes/rate_limit.rs: the per-source and per-account login failure buckets skip a `login_required` answer.
- browserid-broker/src/routes/code_guard.rs: `complete_from_ip` replaces `completion_ip_allowed`; it refuses at the cap, then counts only `InvalidVerificationCode` against the source (the answer already reveals right/wrong, so this adds no oracle). Callers in signin_code.rs and email.rs.
- Tests: `api_v1_login_required_is_not_a_failure` (authz_matrix_test), `successful_completions_are_not_throttled` (signin_code_test).
- e2e: `tests/helpers/agent-bootstrap.ts` stands in for the removed `Agent.bootstrap`; guestbook passes the agent to `requestWarrants` (D4 signed filing); connection-sharing sends `client_id` on refresh (W4-11) and keeps it with the tokens.
- Full Playwright run on a warm broker: 131 passed, 0 failed, 15 skipped (2026-11-06). The suite exhausts the registrar per-origin record-request limiter after ~10 runs; restart the broker between repeated runs.

Observed once in ~10 reconnects: a DoT transport hiccup to 8.8.8.8 now surfaces as `discovery failed: DNSSEC validation failed` (D14 hard reject, decided Q2 (b)). Each reconnect issues ~29 live DoT queries for the NXDOMAIN `example.test`; a short negative cache would shrink the exposure. Follow-up, not fixed here.
