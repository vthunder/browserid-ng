---
# browserid-ng-5bic
title: 'Reservation hardening: expiry/GC + rate limits (anti-squatting)'
status: todo
type: task
priority: normal
created_at: 2026-07-12T12:33:51Z
updated_at: 2026-07-12T12:33:51Z
---

The agent-handle reservation model has two gaps that make namespace squatting sticky:

1. No reservation expiry/GC: a reserved handle is created verified immediately (agent.rs ensure_agent_identity) and NEVER expires, so within quota a squatter holds good handles (bot, assistant, ...) forever without ever minting. Add use-it-or-lose-it: unminted reservations expire (e.g. 30-90d) and are GC'd. Distinguish 'reserved but never activated/minted' from 'active' for expiry.
2. No rate limiting on reserve/provision endpoints, nor visible per-IP limits on account creation. Quota (max_agent_identities_per_user) bounds per-account, but nothing slows Sybil beyond email-verification cost. Add rate limits on /provision/reserve, /agent-provision/request (pending-record creation, unauthenticated), account creation.

Context: reserve IS authenticated (delegation-chain or session) and quota-bounded, so no unauthenticated mass-reservation hole. Residual is Sybil squatting + sticky reservations. Relates to 0phq (global-vs-scoped namespace) and 74u1 (paired provisioning adds a session-authed reserve + unauthenticated request endpoint).
