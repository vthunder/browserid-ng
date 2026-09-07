---
# browserid-ng-ptag
title: 'registry-api-v1: mixed_accounts precheck vs with-session transfer; bare attach with mixed identities (review A7)'
status: completed
type: task
priority: normal
created_at: 2026-09-06T11:08:58Z
updated_at: 2026-09-07T12:42:57Z
parent: browserid-ng-0c49
---

From the 2026-09-06 adversarial review (coherence 1–2, security M8). Dan: "I don't understand this one, file and discuss separately."

WHAT IT WAS: §5.6.1's precheck said "the session's account and every account already owning one of the call's identities must be one and the same" — which refused the very row below it ("on another account B, write on any → leaves B and joins A"), so the take-an-identity flow was unreachable. Separately, a bare attach carrying one identity owned by B plus one unowned identity was undefined and could land the unowned one on B without write consent. Core also allows `*` glob identities in certs, never addressed.

r5 draft (2026-09-06) provisionally reworded: the precheck applies among the CALL's identities only (all unowned, or all on one account); the session's account may differ (that is the transfer); globs refused (`422 invalid_cert/glob_identity`); invariant 7 restated as "which account, and its contents, are never observable" since bare-attach status codes already reveal "used before" (now explicit as prior_use).
- [ ] Walk through with Dan; confirm or revise

## Summary of Changes

Moot after the explicit-account change (2026-09-07): the door admits one identity per call and the session names its account, so `mixed_accounts` no longer exists. Glob identities are still refused at attach (`glob_identity`). Invariant 7 restated.
