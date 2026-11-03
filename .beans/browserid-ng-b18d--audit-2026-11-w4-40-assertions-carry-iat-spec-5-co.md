---
# browserid-ng-b18d
title: '[Audit 2026-11] W4-40: assertions carry iat (spec §5, core, agents, SDKs)'
status: completed
type: bug
priority: normal
created_at: 2026-11-02T22:43:20Z
updated_at: 2026-11-03T09:16:32Z
parent: browserid-ng-ag1l
blocked_by:
    - browserid-ng-gdo0
---

Findings: W4-40 (spec gap). Severity: Low. Decision: Q19 settled 2026-11-02: (a) add iat to assertions (spec §5, core, Rust agent, JS SDK); one rule for every object. (b) would scope §6.1's lower bound to objects that carry iat.

Where: docs/specs/browserid-ng-protocol.md §5 assertion table lists only aud/exp/req_origin while the amended §6.1 time-bounds paragraph (S6) rejects every checked object unless iat <= exp; sdk/agent/src/protocol.mjs:45-48, browserid-core/src/assertion.rs:14-28 and the JS SDK emit no iat, so no implementation can satisfy §6.1 as written.

Change under (a): add iat to AssertionClaims (core), the Rust agent, sdk/js and sdk/agent signers, and the dialog; verifiers check it through the clock-rule helper (the clock bean) with iat optional during a transition window, then required. Under (b): spec edit only.

Acceptance: the pin "W4-40 (pin): the assertion ... carries no iat" in sdk/agent/audit_2026_11_ws4.test.mjs flips; add P-TIME vectors for assertions (future iat, iat > exp) to the WS2 generator and regenerate.

Reports: ws4 §2, ws6 §1.6. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.


## Summary of Changes

Q19 (a) landed: the assertion carries `iat` and is judged by the one clock rule like every other object.

- Spec: §5 assertion table gains `iat` (signers MUST set it; §6.1 time bounds apply); §6.1's time-bounds paragraph names the assertion's transition window.
- browserid-core: `AssertionClaims.iat: Option<i64>` (serde default / skip-if-none); `Assertion::create` sets `iat = now`; new deterministic `Assertion::create_at(aud, req_origin, iat, exp, key)` for fixed-clock fixtures; new `Assertion::check_window_at(at)` routes through `time::check_window("assertion", …, CLOCK_SKEW_SECONDS)`; `AccessPresentation::verify_at` calls it in place of the bare expiry check. `Assertion::verify` stays signature-only (documented) — the clock question is `verify_at`'s. browserid-verifier, the hosted /verify, FedCM and the Rust agent (`browserid-agent`) all sign/verify through core, so they picked it up unchanged.
- Signers: `sdk/agent` (`protocol.mjs` `assertion()` → `{iat, exp, aud}`; `sdk/wallet` and `wallet-service` sign through `DeviceAgent.assertionFor`, so covered), broker dialog (`static/dialog.js`, external file — no CSP hash change). The JS verify SDK, mcp-auth, gate and python-mcp-auth delegate to the hosted verifier and re-implement no checks; they consume the recorded hosted responses.
- **Backward compatibility (decided here):** an assertion WITHOUT `iat` is still accepted on `exp` alone until the sunset `browserid_core::assertion::IAT_SUNSET` = 1_801_526_400 (2027-02-01T00:00:00Z); at or after that instant a missing `iat` rejects ("no iat (required since 2027-02-01)"). No debug log in core (no log facade there); the sunset is a compile-time constant checked against the verification instant `at`, so deterministic replayers behave identically. Spec says MUST on signers now. Follow-up at the sunset: flip WS2 `P-TIME-13` from accept to `reject("shape")`, drop the `None` arm in `check_window_at`, make `iat` non-optional.
- WS2 vectors (generator `audit_2026_11_ws2_generate.rs`, regenerated with WS2_REGEN=1; hosted responses re-recorded): every accept vector's assertion now carries `iat`; new `P-TIME-11` (assertion post-dated → `future_iat`), `P-TIME-12` (assertion `iat > exp` → `iat_after_exp`), `P-TIME-13` (no `iat`, pre-sunset → accept). 188 vectors.
- Tests: WS4 pin `W4-40 (pin)` flipped to `W4-40 (fixed)` (asserts `iat` set and `exp − iat == 300`); `conformance_test` expects 3 claims; fixed-clock fixtures (device/tests.rs, ws3 proptest, ws6, ws8_d1, fuzz/src/lib.rs) build assertions with `create_at(IAT, …)` so they stay valid after 2027-01-15; the stale-assertion test issues `iat < exp` (an `iat > exp` assertion now rejects at every instant, as it should).
- Runners: rust-core 177 pass / 3 xfail / 0 unexpected; hosted 159 / 3 / 18 skipped; sdk/js 118 / 2 / 61 skipped; python-mcp-auth 118 / 2 / 61; mcp-auth 159 / 5 / 18; gate 168 / 5 / 23. `cargo test --workspace` all green (40 suites); sdk/agent 21/21; python 25/25.
- Not in this repo: browserid-bsky's signer (separate repo) — emits no `iat` until updated; accepted under the sunset window.
