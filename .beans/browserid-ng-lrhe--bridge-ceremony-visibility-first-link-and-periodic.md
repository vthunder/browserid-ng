---
# browserid-ng-lrhe
title: 'Bridge ceremony visibility: first link and periodic re-verification are visible; routine renewals silent'
status: completed
type: feature
priority: normal
created_at: 2026-08-19T22:12:35Z
updated_at: 2026-08-19T22:25:17Z
---

Owner requirement (2026-08-20): the FIRST connection of a bridge (Google) to an address must be visible, and occasional re-verification must be visible; routine renewals stay silent. Google auto-approves openid+email with login_hint and no prompt — no consent screen even on first auth, no Connections entry — so visibility must be broker-enforced, not delegated to Google.

Design:
- /oidc/claim decides the prompt per the address's record:
  - no record, or record not yet Oidc-proven (first link / E3→E2 class change) → prompt=consent (the full "browserid.me wants to…" authorize framing)
  - Oidc record whose last INTERACTIVE proof is older than REVERIFY_INTERVAL (90d), or never stamped (legacy rows) → prompt=select_account (visible confirm, one click)
  - otherwise → no prompt (silent reuse allowed — epic invariant 3 unchanged)
- The flow record carries forced_visible; on successful attach the callback stamps emails.last_interactive_proof_at (migration v31, nullable TEXT).
- Legacy Oidc rows (NULL stamp, e.g. the owner's gmail) get exactly one visible confirm at their next re-proof, then join the cadence.
- Atproto: the external bsky bridge owns its own interaction; out of scope here.

Tests: prompt selection per record state (none/smtp/oidc-fresh/oidc-stale/legacy-null); callback stamps only when forced; sqlite migration + store round-trip for the new column.

## Summary of Changes (2026-08-20)

Implemented as designed:
- build_auth_url gains an optional prompt param; FlowState/ConsumedFlow carry forced_visible.
- /oidc/claim policy: no record or non-Oidc record → prompt=consent (first link / class change, the full authorize framing); Oidc record with stale (>90d, INTERACTIVE_REVERIFY_DAYS) or absent interactive stamp → prompt=select_account; otherwise no prompt (silent renewal).
- Callback stamps emails.last_interactive_proof_at (migration v31, nullable) when the flow forced visibility and the attach succeeded.
- Store: set_email_interactive_proof_now / email_interactive_proof_at (sqlite narrow column ops + memory side-map; Email model untouched).
- Legacy Oidc rows (NULL stamp — incl. the owner's gmail) get exactly one visible select_account at their next re-proof, then join the 90d cadence.
- v30 migration test fixture gained a minimal emails table (v31 alters it).

Tests: claim_prompt_follows_the_visibility_policy (consent for unknown + smtp records; stamp set by a completed visible claim; silent when fresh; select_account for never-stamped Oidc rows); sqlite round-trip for the new column. Workspace 59 suites green (CARGO_TERM_COLOR=never, positive count); e2e 105/105.
