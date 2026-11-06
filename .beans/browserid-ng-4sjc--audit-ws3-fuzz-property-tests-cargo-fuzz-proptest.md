---
# browserid-ng-4sjc
title: 'Audit WS3: fuzz + property tests (cargo-fuzz, proptest)'
status: completed
type: task
priority: normal
created_at: 2026-11-01T12:40:56Z
updated_at: 2026-11-02T22:16:57Z
parent: browserid-ng-ag1l
blocked_by:
    - browserid-ng-7k3p
---

No fuzz/proptest exists today. Targets: JWS/cert parsing in browserid-core, scope grammar parser, DNS TXT parsing (July M5 class), status-list decoding, request-kind JSON. proptest invariants: sign->verify round trip, canonicalize idempotent, delegation chain never widens root scope. Harnesses live in repo; run via ssh localtest.

## From WS1
Properties from I12-I14 plus S6/D16 (iat unbounded: exp-iat negative passes max-ttl; cap.window rolls from a future iat). D1 (identity_matches subaddress widening in core device.rs:96-111) is a one-line proptest: auth-cert identity_matches must be exact.


## Checklist
- [x] proptest suite browserid-core (round trips, canonicalization, I12 strictness order, I13, I14, iat/exp, scope grammar, DNS TXT, status list)
- [x] status-list allocation-bound property (counting allocator binary)
- [x] registrar proptest: request-kind differential vs schema / scope grammar
- [x] fuzz/ standalone crate with targets: jws_parse, claims_json, scope_parse, identity, dns_txt, status_list, request_kind_json
- [x] run each target 60-120 s on localtest nightly; triage crashes; corpus seeds + reproducers committed
- [x] make fuzz-smoke + scripts/fuzz-smoke.sh + how-to-run-longer doc
- [x] report docs/security-audit-2026-11-ws3-fuzz-proptest.md


## Summary of Changes
- proptest suites: core 34 pass + 4 ignored-failing (D1 auth-exact, W3-1 max-ttl overflow, S6 iat bound, W3-2 status freshness overflow); core counting-allocator binary 1 pass + 1 ignored (W6-3 randomized); registrar 3 pass + 1 ignored (W3-3 scope grammar not enforced at request time).
- fuzz/ standalone cargo-fuzz workspace (7 targets, seeds, gen_seeds, README), scripts/fuzz-smoke.sh, make fuzz-smoke. 90 s/target run on localtest nightly: 0 crashes, ~24M execs total.
- Report docs/security-audit-2026-11-ws3-fuzz-proptest.md: W3-1 Low, W3-2 Low, W3-3 Medium, W3-4 Low; 3 decisions for Dan.
- No production code changed; dev-deps only (proptest, regex) + one #[cfg(test)] mod line in consent.rs. Dockerfile unaffected (fuzz/ is not a root workspace member).
