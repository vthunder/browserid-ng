---
# browserid-ng-d51o
title: 'Warrant forget-without-revoke: guard the footgun or keep it sharp'
status: todo
type: task
priority: normal
created_at: 2026-08-27T14:14:54Z
updated_at: 2026-09-07T19:14:28Z
---

From registry-api-v1 §5.2 review (Dan, 2026-08-28): POST /api/v1/warrants/forget (and legacy /wsapi/forget_warrant) deletes the registry row WITHOUT revoking — the signed warrant stays valid to expiry. Footgun when used on an active, revocable warrant.

Legitimate uses identified so far: (a) warrants with no status ref (nothing to revoke — e.g. prototype-era login warrants); (b) expired warrants (revocation moot; forget is cleanup); (c) warrants whose status list belongs to a foreign authority this registry cannot flip (incl. lost-account cases per Dan); (d) development hygiene.

Options to discuss: keep as-is + wallet-UI guard (require revoke first when unexpired and revocable); server-side guard (409 conflict unless already revoked/expired/unrevocable, with an explicit force field); or fold into revoke-then-forget. Decide, then update spec §5.2 and keep the legacy lane consistent.

2026-09-07: registry-api-v1 r5 renamed forget → `unlist` and added the guard-rail this bean asked for: an unexpired indexed warrant is refused (409 conflict/live_warrant) unless confirm_unrevoked:true (§5.4). Close when implemented (0c49 step 7).
