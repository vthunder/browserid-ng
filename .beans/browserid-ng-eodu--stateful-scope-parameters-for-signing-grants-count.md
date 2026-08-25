---
# browserid-ng-eodu
title: Stateful scope parameters for signing grants (counts, rate caps, spend limits)
status: draft
type: feature
priority: low
created_at: 2026-08-24T19:32:54Z
updated_at: 2026-08-24T19:32:54Z
---

From the 2026-08-24 authorization-language comparison (IAM conditions, RAR payment authorization): quantitative/contextual caveats like 'at most 20 posts per day' or 'up to €500' render perfectly on a consent card but are excluded from the warrant format today because enforcement is stateful and network verifiers are deliberately stateless.

The wallet, however, IS stateful (it already keeps signedCount). If/when this is wanted, it enters as a wallet-enforced scope parameter in the inline entry form — {scope, mode, max_per_day: 20} — with stricter-wins semantics, per the growth-path rule in docs/warrant-use-cases.md (Known limits). Not a new claim, not a verifier feature.

Blocked conceptually on signing grants landing first (bean browserid-ng-ttn3).
