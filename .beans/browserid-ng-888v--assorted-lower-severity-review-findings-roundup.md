---
# browserid-ng-888v
title: Assorted lower-severity review findings (roundup)
status: todo
type: task
priority: normal
created_at: 2026-07-08T06:14:02Z
updated_at: 2026-07-10T23:46:55Z
parent: browserid-ng-8u60
---

Lower-severity items from the 2026-07-08 review, grouped so none are lost.

- [ ] core vs broker cert-chain mismatch: BackedAssertion::verify uses LAST cert as user cert (assertion.rs:228); broker verifier uses .first() and ignores multi-cert chains (verifier.rs:171,252,298). Also core multi-cert branch never checks certificates[0] (root) expiry.
- [ ] No clock-skew tolerance: is_expired() is bare now>exp (assertion.rs:66, certificate.rs:117); 2-5min assertions fail on minor clock drift. Add small leeway.
- [ ] No assertion max-lifetime bound: verifier accepts any exp if unexpired; Persona capped it. Add a max-assertion-lifetime check. (Assertions also carry no iat/iss.)
- [x] All-zero placeholder pubkey in SupportDocument::delegate()/disabled() (discovery.rs:62,73) — make it Option or a distinct variant. (Done via fix/discovery-cleanup a6e9573, merged: public_key is Option, fail-closed on None.)
- [ ] dialog.js accepts origin from URL query param (params.get('origin') -> state.origin -> assertion aud + sendResponse targetOrigin). Remove/reconcile with the opener's real origin.
- [ ] targetOrigin '*' hygiene on comm-iframe->RP and WinChan ready posts (start.js:22, include.js:844/903) — safe today but least-privilege.
- [ ] domain_key_creation_time hardcoded to 0 (session.rs:55): frontend cert-freshness-vs-key-rotation check is a no-op; wire real key creation time before ever rotating the broker key.
- [x] auth_with_assertion cold-start bug: uses get_fallback_fetcher() (non-initializing) so primary login can fail with 'DNS discovery not configured' if /verify wasn't hit yet (primary.rs:44-46). (Fixed 2026-07-11: main.rs warms the fetcher at startup — route + tests keep non-initializing semantics.)
