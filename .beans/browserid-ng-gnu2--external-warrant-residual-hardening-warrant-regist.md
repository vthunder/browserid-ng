---
# browserid-ng-gnu2
title: 'External-warrant residual hardening: warrant-registry external flag + discovery rate-limit'
status: todo
type: task
priority: normal
created_at: 2026-07-14T21:41:16Z
updated_at: 2026-07-14T21:41:16Z
---

Follow-ups from the mingo-poster external-warrant review (browserid-ng-yhcx). Non-blocking; the shipped code is safe with the applied mitigations.

## Two residual items

1. **account.html classifies 'External services' client-side** by set-difference (a warrant whose agent_email isn't in the account's current agent set). If a user deletes an own agent but its warrant row survives, that warrant flips into the 'External services' card — a false trust signal. Honest fix: persist externality (and ideally the agent's issuer domain) on WarrantRecord at approval time and expose it via /wsapi/warrants (the registrar knows it authoritatively — WarrantRequestRecord.external — but drops it when recording the warrant). Needs a warrants-table column + broker migration v12 + registrar model/glue plumbing.

2. **Discovery-rate residual**: request_external now refuses (with zero outbound calls) any request whose delegator isn't a local verified email, and enforces the per-delegator pending cap BEFORE discovery — so amplification requires naming a real local victim, and per-victim allocation is bounded per 15-min window. Not fully bounded over time (indices are monotonic; an attacker targeting one victim can allocate up to 5x8 per window). A deeper fix defers status-index allocation to consent/approval time for external requests (the manual path already has /wsapi/allocate_warrant_status), and/or adds a discovery-attempt rate limiter. Also: the pending-count check is non-atomic (TOCTOU) — under concurrency slightly more than 5 rows can be parked; a transactional insert-with-cap in the store would close it.
