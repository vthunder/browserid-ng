---
# browserid-ng-8cow
title: Poster approval fails silently on identity mismatch — make it legible
status: completed
type: bug
priority: high
created_at: 2026-07-23T13:32:55Z
updated_at: 2026-07-23T21:10:21Z
parent: browserid-ng-atge
---

When the account approval mints a different identity than the poster requested, mingo's /poster/poll (mingo-idp/src/poster.rs:377) clears the pending row and returns a 500; the mingo-web poll loop (app.js:382-383) swallows it and spins until timeout. The user sees "stuck waiting for approval" with no reason.

Concrete case observed (2026-07-22/23): poster requests as-you dan@mingo.place; account page (account.html:1112) DEFAULTS to named-handle mode; approving without flipping the radio mints dan+mingo@mingo.place (tag "mingo" derived from the label at account.html:1105-1108); poll identity-match fails.

## Fix (independent of the model-A rework)
- [x] mingo /poster/poll: returns terminal { status: mismatch, requested, approved } (mingo 47a-pending commit). No more opaque 500.
- [x] mingo-web: pollPoster returns { ok, reason }; pickupPoster + modal show the mismatch reason (modal.fail state). node --check + cargo build/test green.
- [~] account-page prevention folded into point 2 (identity pinning) — legibility above already ends the silent dead-end; interim account.html change would be throwaway once the approval respects pins. NOT deployed yet.

Note: under model A the poster will pin a DIVERGENT grantee (mingo-poster@mingo.place), so the "default to As-me" idea is NOT the fix here — the durable fix is (a) legible failure + (b) the request pinning identities (point 2). This bean is just the legibility half so the current deployed flow stops dead-ending.

## Closed (2026-07-23)
Legible failure shipped + deployed (mingo poll returns a structured {status:mismatch,...} the SPA explains). And superseded structurally: model A pins the grantee (mingo-poster@mingo.place), so the dan+mingo@ drift can't happen. Account-page prevention folded into the delegated approval (point 2) which shipped in browserid-ng-nrwd.
