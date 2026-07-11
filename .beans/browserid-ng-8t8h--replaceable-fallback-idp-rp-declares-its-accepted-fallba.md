
## Build progress (2026-07-11)

- [x] Phase 4 spec — protocol §8.1 (RP-selected fallbacks), §6.1 (enforcement), §7 (the argument)
- [x] Phase 3 enforcement — **already built**: browserid-rp `Verifier.trust_issuer` / `trust_issuer_from_well_known` reject an untrusted issuer (tested: `exchange_rejects_wrong_audience_and_untrusted_issuer`). RPs accept a fallback by trusting its issuer. No new verifier code.
- [x] Phase 1 client API — include.js `acceptedFallbacks` option threaded to the dialog
- [x] Phase 2 dialog — gate on BOTH entry paths (authenticated chooser + signed-out email-form submit; they're separate code paths); cached-cert reuse gated by issuer; session_context returns the broker's own domain so the dialog knows its fallback identity
- [x] Tests — e2e accepted-fallbacks.spec.ts (blocks when RP excludes this broker; proceeds under default). Workspace 366 + e2e 86 green.
- [ ] Deploy + live smoke (in progress)

Gotcha found: the dialog has two parallel email-handling paths — `handleEmailChosen` (chooser) and the `#email-form` submit handler (typed email, signed-out). The gate must live in both; the transition_to_primary state is exempt (it routes to a primary, not the broker).
