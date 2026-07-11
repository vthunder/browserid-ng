
## Build progress (2026-07-11)

- [x] Phase 4 spec — protocol §8.1 (RP-selected fallbacks), §6.1 (enforcement), §7 (the argument)
- [x] Phase 3 enforcement — **already built**: browserid-rp `Verifier.trust_issuer` / `trust_issuer_from_well_known` reject an untrusted issuer (tested: `exchange_rejects_wrong_audience_and_untrusted_issuer`). RPs accept a fallback by trusting its issuer. No new verifier code.
- [x] Phase 1 client API — include.js `acceptedFallbacks` option threaded to the dialog
- [x] Phase 2 dialog — gate on BOTH entry paths (authenticated chooser + signed-out email-form submit; they're separate code paths); cached-cert reuse gated by issuer; session_context returns the broker's own domain so the dialog knows its fallback identity
- [x] Tests — e2e accepted-fallbacks.spec.ts (blocks when RP excludes this broker; proceeds under default). Workspace 366 + e2e 86 green.
- [x] Deploy + live smoke — deployed to browserid.me (9dab82e); the gate e2e passes against LIVE (real browser, real session_context)

Gotcha found: the dialog has two parallel email-handling paths — `handleEmailChosen` (chooser) and the `#email-form` submit handler (typed email, signed-out). The gate must live in both; the transition_to_primary state is exempt (it routes to a primary, not the broker).


## Summary of Changes (2026-07-11) — SHIPPED

An RP can now adopt browserid without being forced to trust browserid.me as an identity authority: it passes `acceptedFallbacks` (issuer domains) when invoking login; the broker/dialog fails fast if it isn't listed; the RP's verifier enforces (already built). FedCM-shaped argument, no RP well-known.

- **Spec** protocol §8.1 (RP-selected fallbacks), §6.1 (verifier enforcement is authoritative), §7 (the argument).
- **Enforcement already existed** — browserid-rp `Verifier.trust_issuer`/`trust_issuer_from_well_known`; the argument is only a routing hint.
- **include.js** threads `acceptedFallbacks`; **dialog.js** gates both entry paths (chooser + signed-out email form), gates cached-cert reuse by issuer; **session_context** returns the broker's own domain.
- **Tests**: e2e accepted-fallbacks.spec.ts (blocks when excluded; proceeds under default) — green locally AND against live browserid.me. Workspace 366, e2e 86.

Default = {browserid.me} (backward compatible, no new trust); explicit [] = primaries only; primaries always accepted.

v1 caveat (as designed): only browserid.me is deployed as a fallback, so the concrete effect today is that an RP may *decline* it; the protocol lets anyone stand up another fallback with no further change. Sibling broker-choice work is browserid-ng-0efn (blocked on spike dcgm).