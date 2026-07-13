---
# browserid-ng-1sy5
title: Silent assertion (communication_iframe) is dead for cross-origin RPs — third-party storage partitioning
status: todo
type: bug
priority: normal
created_at: 2026-07-13T08:37:49Z
updated_at: 2026-07-13T08:38:21Z
parent: browserid-ng-8u60
---

Discovered during the origin-split spike (browserid-ng-93z2), but this is INDEPENDENT of the split.

The silent-assertion path (navigator.id.watch firing onlogin without a popup, via the hidden /communication_iframe) only works when the RP page is SAME-ORIGIN as the broker. For any real external RP (cross-origin), modern browsers partition the embedded iframe's storage into a separate third-party bucket, so the comm iframe cannot see the keystore (IndexedDB browserid-keys) or localStorage siteInfo that the dialog wrote in the first-party context. Result: watch() fires onlogout even when the broker session cookie is live and valid.

Verified in e2e-tests/tests/cross-origin-rp.spec.ts: cross-origin (and same-site rp.localhost) RP => onlogout; same-origin => onlogin. The broker's own top-level tab still shows authenticated:true, confirming it's client-side storage partitioning, not session loss.

This matches the historical reason Persona's silent/auto-login degraded as browsers tightened third-party storage. Options to investigate:
- Accept it: RPs must use the popup request() flow (works cross-origin, verified). Document that silent SSO is best-effort/same-origin-only.
- Storage Access API: comm iframe calls document.requestStorageAccess() (needs a prior user gesture/interaction on the broker origin; UX cost).
- FedCM: migrate the silent/auto-reauthenticate path to the browser's FedCM API, which is the modern replacement for exactly this third-party-iframe SSO pattern.
- Top-level flow only for re-auth.

Not urgent (popup flow works), but it means 'seamless SSO across sites' is currently unavailable for real RPs.
