---
# browserid-ng-bt3i
title: Consent auto-return + external services as clickable accounts on /account
status: completed
type: task
priority: normal
created_at: 2026-07-15T18:52:54Z
updated_at: 2026-07-15T18:57:08Z
---

Post-mingo-hlka polish (dan): (1) consent page: after Approve, auto history.back() with a short announced delay when there is history to return through — manual button stays as fallback; denials never auto-navigate. (2) /account: the External services card should list distinct external service accounts like the Agents card (one row per service, badge + acting-for sub-line), and clicking one opens the detail view listing that service's warrants with Revoke/Forget (no Copy/Reissue — the service holds its own warrant).

## Summary of Changes

consent.html: on Approve (not Deny), auto history.back() after 1.8s with a visible note, only when history.length > 1; manual button remains. account.html: External services card now lists one row per external service (grant-count badge, acting-for sub-line) mirroring Agents; clicking opens the shared detail view (external badge, per-grant delegator line, Revoke/Forget only — no Copy/Reissue). showDetail/showDetailNoPush unified; popstate restores external details. CSP hashes updated for both pages (guard test green).
