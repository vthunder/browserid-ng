---
# browserid-ng-6u70
title: Silent session sync v2 under the device model (watch onlogin/onlogout/onmatch contract)
status: draft
type: feature
priority: high
created_at: 2026-08-05T00:52:12Z
updated_at: 2026-08-05T00:52:12Z
---

DEDICATED SESSION: investigate + decide, then implement (user call 2026-08-05).

CAPABILITY GAP, found via failing e2e (browserid-ng-dk6d): d9a6baf (2026-07-20) deleted the hidden communication_iframe and the watch() silent-reconciliation contract went with it — include.js today NEVER calls observers.match (assigned, never invoked), fires onlogout only on explicit logout(), and the only silent behavior is trySilentFedCM() (opt-in, Chrome-only, login-only). FedCM is NOT a replacement. RPs currently get no silent session continuity.

The old contract (what 12 currently-failing tests specify): on page load, reconcile actual browserid state vs the RP's claimed loggedInUser and fire exactly ONE of onlogin (with a freshly silently-minted assertion) / onlogout / onmatch; onready after; works from cross-origin RPs.

Design options sketched 2026-08-03:
1. RP-origin persistence: include.js persists the presentation received at login (RP-origin storage), silently re-presents/re-mints until expiry — cross-browser onlogin/onmatch with zero broker contact; onlogout becomes best-effort (no broker-side visibility).
2. Broker session probe (CORS endpoint): blocked by third-party cookie partitioning in the RP context — same wall that killed the iframe; only useful combined with 1.
3. Login Status API + FedCM as the progressive layer (right direction, wrong sole mechanism).
Leaning 1+3 with explicitly re-specced onlogout semantics — but that is the decision this session must make, incl. what 'logout everywhere' should mean for RP-persisted presentations (ties to device-cert revocation checks: a presentation re-mint hits /access/mint, which IS a broker touchpoint that can observe revocation — maybe onlogout = failed silent re-mint?).

The 12 tests (silent-assertion ×7, include-api ×3, cross-origin-rp silent ×2) are marked test.fixme pointing here — they are the acceptance spec for v2; do NOT delete them.
