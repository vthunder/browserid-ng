---
# browserid-ng-lrhe
title: 'Bridge ceremony visibility: first link and periodic re-verification are visible; routine renewals silent'
status: completed
type: feature
priority: normal
created_at: 2026-08-19T22:12:35Z
updated_at: 2026-08-20T06:33:48Z
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

## Correction (2026-08-20, owner challenge)

The claim 'Google auto-approves basic scopes with no consent screen even on FIRST authorization' was an unsupported inference and is WRONG. Google's OIDC docs (developers.google.com/identity/openid-connect): with no prompt value, 'the user is shown a consent screen' when they have 'not previously authorized access' — i.e. Google DOES show UI on the genuinely-first grant, then never again for that (Google account × client).

The feature survives on the corrected, documented grounds: Google's one-grant-ever is keyed to the CLIENT, while the broker's first-link events are per ADDRESS — any prior grant (an earlier address, an abandoned dev-test flow) silences the exact linking ceremony the owner wants visible, and periodic re-verification is silent forever without a prompt param. prompt=consent on a genuinely-first-ever grant is redundant with Google's own screen (harmless; pins the framing). Code comments corrected to cite the documented behavior.

Owner-history reassessment under the documented model: the Aug 19 record upgrade completing silently implies a PRIOR grant — most plausibly clicked during the Aug 11 qer8 live gmail test (bean note 'live gmail claim test through the dialog (user, in progress)'; device certs issued that evening), which registered the grant at Google even though the browserid callback never attached. The absent myaccount.google.com/connections entry remains UNEXPLAINED — candidates: the separate 'Sign in with Google' section of that page, a different Google profile checked, the console app name not being recognizable, or Testing publishing status (whose grants expire ~7 days, which would instead imply one quickly-dismissed screen on Aug 19). Not resolvable without the owner's Google account / Cloud Console.
