---
# browserid-ng-8eld
title: 'External services: free re-categorization (per-holder ''filed under'' override)'
status: todo
type: feature
priority: low
created_at: 2026-07-23T21:10:04Z
updated_at: 2026-07-23T21:10:04Z
parent: browserid-ng-atge
---

A delegated external service (e.g. mingo-poster@mingo.place) has a holder bound to its warrant + the access cert its own issuer mints — so it can't be MOVED between namespaces the way an owned device can (moving = new holder id = revoke, with nothing to re-issue). Today it defaults under 'Services' (holder-prefix adoption) and 'move' is hidden for it (browserid-ng account card + move_holder refusal).

To let users freely re-categorize external services WITHOUT revoking, decouple the DISPLAY namespace from the holder prefix: a per-holder 'filed under' override (cosmetic label/namespace tag stored on the holder record) that the Devices & services grouping checks before falling back to the prefix. A small 'recategorize' endpoint sets it; never touches the warrant/holder.

Scope: browser store (holder→namespace override), holders.rs grouping, account.html UI (offer recategorize for external holders). Low priority — external services default to Services correctly; this is just free re-filing.

Parent: browserid-ng-atge (model A delegated attribution).
