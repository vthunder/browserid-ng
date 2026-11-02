<!-- This Source Code Form is subject to the terms of the Mozilla Public
   - License, v. 2.0. If a copy of the MPL was not distributed with this
   - file, You can obtain one at http://mozilla.org/MPL/2.0/. -->

# Security audit 2026-11 — WS3: property tests and fuzzing

**Status:** complete, 2026-11-02. Epic `browserid-ng-ag1l`, bean
`browserid-ng-4sjc`. Scope: the Rust wire parsers and the chain-narrowing
logic in `browserid-core`, the DNS TXT parser the `browserid-dnssec`
resolver feeds, and the registrar's request-time shape checks. Oracle:
`docs/design/threat-model.md` I12–I14 plus S6/D16; decision D1
(`docs/security-audit-2026-11-decisions.md`: spec §4.6 stands — an
authentication cert for `user@d` must not authorize `user+tag@d`; config
certs keep subaddressing).

**Method.** Two instruments, both dev-only, no production code changed:

1. **proptest** suites (256 cases each, ~1 s per crate, CI-safe) encoding
   the invariants as randomized properties. A property that FAILS today is
   `#[ignore]`d with an `// AUDIT-2026-11 Wx-n: fails today` comment and is
   the acceptance test for the fix; the ignored set was run with
   `-- --ignored` to confirm each fails for the stated reason (minimal
   failing inputs recorded under each finding).
2. **cargo-fuzz** (libFuzzer + ASAN, nightly) targets in a standalone
   `fuzz/` workspace, seeded from valid objects, each run for a bounded
   budget on the dev box. Any panic, assertion, timeout or RSS blow-up is a
   finding.

WS6 (`docs/security-audit-2026-11-ws6-core-verifier.md`) holds the point
tests for S3/S5/S6/D1/D16/W6-3; this workstream generalises them and does
not repeat them. Where a property is the randomized form of a WS6 test it
says so.

## 1. Property tests

| Crate | File | Pass | Ignored (fail today) |
|---|---|---|---|
| browserid-core | `browserid-core/tests/audit_2026_11_ws3_proptest.rs` | 34 | 4 |
| browserid-core | `browserid-core/tests/audit_2026_11_ws3_status_alloc.rs` (counting allocator) | 1 | 1 |
| browserid-registrar | `browserid-registrar/src/consent/audit_2026_11_ws3_proptest.rs` (`#[cfg(test)]` module; the checks are `pub(crate)`) | 3 | 1 |

Run: `cargo test -p browserid-core --test audit_2026_11_ws3_proptest --test audit_2026_11_ws3_status_alloc`,
`cargo test -p browserid-registrar --lib audit_2026_11_ws3`; add `-- --ignored` for the failing set.
Dev-dependencies added: `proptest`, `regex` (core); `proptest` (registrar).

### 1.1 Properties by invariant

| Invariant | Property (test name) | Status |
|---|---|---|
| sign→verify round trip | `device_cert_round_trips`, `access_cert_round_trips`, `access_request_round_trips`, `assertion_round_trips`, `warrant_v2_round_trips`, `status_list_token_round_trips`, `presentation_round_trips_and_verifies`, `record_bundle_round_trips` — random claims sign, parse to equal claims, verify under the signing key and reject every other key; a random bundle verifies with the expected `VerifiedAccess` and survives `encode`/`parse` byte-exact | pass |
| canonicalization idempotent | `domain_normalization_is_idempotent` (any Unicode), `identity_eq_is_an_equivalence_on_well_formed_emails`, `claims_json_serialization_is_stable`, `status_list_encoding_is_idempotent` | pass |
| I12 stricter-wins never loosens | `strictness_is_reflexive`, `tightening_is_at_least_as_strict_and_transitive` (a→b→c derived by tightening), `strictness_never_loosens_any_parameter` (if `a ≥ b` then cap amount ≤, window ≤, `max_duration` ≤, `min_reputation` score ≥ at the same indexer, counterparties ⊆, `mode` prompt sticks), `malformed_cap_is_never_stricter` (fail-closed in either position), `scopes_constraint_passes_iff_subset` (§4.7 allowlist ≡ ⊆), `money_and_duration_parsers_are_total` | pass |
| I13 subaddressing (config) | `config_cert_subaddressing_is_plus_only_same_domain` — `l@d` covers `l@d`, `l+t@d`, `l+t+x@d`; never `l@d2`, `l+t@d2`, `l<ext>@d` (no `+`), `l2@d`; a cert for `l+t@d` covers neither `l@d` nor `l+tx@d` / `l+xt@d`; `config_cert_non_subaddress_matching_is_exact`; `glob_is_local_part_only_and_domain_anchored`; `grantee_matchers_cover_exactly_their_domain` | pass |
| I13 / D1 auth-exact | `auth_cert_identity_is_exact` — an authentication cert for `l@d` must not authorize `l+t@d`. Minimal failing input `l="a", t="0", d="a.com"`. | **ignored — fails today** (D1, `device.rs:96-111`) |
| I14 holder | `access_cert_holder_is_the_device_holder_and_the_verifier_binds_to_it` — `AccessCert::create` carries the device cert's holder verbatim through parse, and `verify_at` accepts iff the warrant's matcher covers that holder, returning it unchanged; `holder_matcher_semantics_are_exact`, `holder_length_bounds` | pass (core half; the mint-side equality check is `browserid-broker/src/routes/device.rs:495`, WS5's surface) |
| iat/exp: honest windows | `max_ttl_is_exact_for_honest_windows`, `expiry_comparison_is_total` (strict `at > exp`, no arithmetic, whole i64 range) | pass |
| iat/exp: `exp − iat` overflow | `max_ttl_check_never_overflows` | **ignored — W3-1** |
| iat/exp: future / inverted iat | `warrant_iat_is_bounded_by_exp_and_now` (randomized S6) | **ignored — S6** (WS6 point tests) |
| iat/exp: status freshness overflow | `status_list_freshness_never_overflows` | **ignored — W3-2** |
| parsers total | `jws_parsers_are_total` (ten parsers on arbitrary text, dotted fragments, and three-part JWS with arbitrary payloads), `payload_tampering_is_detected`, `status_list_reads_are_total`, `scope_entry_json_is_total_and_rejects_unknown_params` | pass |
| DNS TXT never upgrades | `dns_txt_parser_is_total_and_never_upgrades` — total on arbitrary (lossy-decoded) bytes; `Ok` ⇒ `v=browserid1`, `Ed25519`, key byte-equal to the last `public-key=` field; every required-field drop and every other version/algorithm rejects; `host=` round-trips | pass |
| scope grammar | `scope_grammar_reference_matches_the_spec_regex` (reference predicate ≡ `^[a-z0-9_:.\-/*@+]{1,128}$`; records that core's `ScopeEntry` is grammar-agnostic by design); registrar `grant_shape_is_total_and_bounds_sizes`, `scope_params_well_formed_pass_and_malformed_reject`, `request_kind_bodies_decode_totally` | pass |
| scope grammar at request time | registrar `grant_shape_accepts_exactly_the_scope_grammar` — minimal failing input: the empty scope `""` is accepted | **ignored — W3-3** |
| status-list decode allocation ≤ cap | `decode_allocation_is_bounded_under_the_cap` (0–3 MiB inflates, noise) | pass |
| status-list decode allocation ≤ cap, any input | `decode_allocation_is_bounded_for_any_input` (0–64 MiB inflates) — randomized form of WS6 `w6_3_oversized_status_list_is_rejected_without_inflating_it` | **ignored — W6-3** |

What this workstream could not express as a Rust property, and why:

- **S ∩ S′ composition (I12, spec §6.5).** No Rust code conjoins a policy
  record with a connection record; admission conjunction lives in the gate
  (`sdk/gate`) and the Python `mcp-auth`, which WS4 covers. The Rust-side
  I12 surface is the stricter-wins order and the §4.7 allowlist, both above.
  `browserid-rp`'s `grant_scopes` (warrant ∩ RP vocabulary) is private and
  has a unit test; not re-encoded.
- **Cap window rolling from a future `iat`.** The window is custodian-
  enforced (browserid-pay); core only parses it. Covered indirectly by the
  S6 property (a future-`iat` warrant must not verify at all).
- **I14 mint-side.** The equality check between the requested holder and
  the device cert's holder is in the broker handler and needs broker state;
  WS5's authorization matrix owns that endpoint.

## 2. Fuzz targets

Standalone workspace `fuzz/` (`fuzz/README.md`); `make fuzz-smoke` runs
every target for `FUZZ_SECS` (default 60) via `scripts/fuzz-smoke.sh`.
Toolchain: nightly + cargo-fuzz 0.13 on the dev box (installed 2026-11-02:
`rustup toolchain install nightly --profile minimal && cargo install cargo-fuzz`).
Not wired into CI or the Dockerfile: the root workspace member list is
unchanged, so the Docker dependency-caching stage is unaffected.

| Target | Exercises | Seeds | Budget | Execs | Corpus | Crashes |
|---|---|---|---|---|---|---|
| `jws_parse` | all 8 compact-serialization parsers + `DnsRecord` + `StatusList::decode`, then `verify_at` / `validate` on whatever parses; `encode∘parse = id` | 7 | 90 s | 4,216,727 | 1,965 | 0 |
| `claims_json` | arbitrary JSON claim sets signed under fixture keys for device/access/request/warrant/status objects → typed parse, `validate_claims`, binding/scope deserialization, verifier | 6 | 90 s | 5,188,418 | 1,596 | 0 |
| `scope_parse` | `ScopeEntry`/`Cap` JSON, money + duration parsers, stricter-wins reflexivity and antisymmetry on projections | 4 | 90 s | 6,681,945 | 1,920 | 0 |
| `identity` | `identity_eq`, `grantee_covers`, `normalize_domain` idempotence, `HolderMatcher::matches`, `identity_matches` vs a reference re-implementation, never cross-domain | 4 | 90 s | 1,089,548 | 2,031 | 0 |
| `dns_txt` | `DnsRecord::parse` on lossy bytes; `Ok` ⇒ key from the `public-key=` field | 4 | 90 s | 2,986,642 | 715 | 0 |
| `status_list` | `StatusList::decode`/`encode`/`is_revoked`; carries a 32 MiB-inflating seed | 2 | 90 s | 125,472 | 418 | 0 |
| `request_kind_json` | the five request-kind schemas via `jsonschema`, registrar body structs, warrant.json ↔ `WarrantRequestBody` differential | 7 | 90 s | 3,411,857 | 1,976 | 0 (2 harness bugs fixed, see §3 observations) |

Run 2026-11-02 on the dev box (`FUZZ_SECS=90 scripts/fuzz-smoke.sh`, one
worker each, ASAN, `-rss_limit_mb=2048 -timeout=20 -max_len=16384`): no
crash, timeout or RSS limit hit on any target; the counts above are the
`Done N runs` totals and the resulting corpus sizes. Execs/s are low on
`status_list` because every input that decodes is re-encoded (zlib) and the
32 MiB seed is inflated on every mutation of it.

Two call sites are guarded inside the targets so a run keeps exploring
past the known W3-1 / W3-2 overflows (comments in `fuzz_targets/jws_parse.rs`
and `claims_json.rs`); remove the guards with the fixes.

## 3. Findings

Severity scale as in WS6: High = authorization/attribution boundary
crossed; Medium = a stated guarantee silently weaker; Low = hygiene with a
plausible but indirect path.

### W3-1 — `max-ttl` arithmetic overflows on an attacker-chosen `iat` (Low; D16 class)

- **Where:** `browserid-core/src/device.rs:315` (`Constraints::check`, `warrant.exp - warrant.iat > max`).
- **What:** the warrant is holder-signed, so `iat`/`exp` are attacker-chosen.
  With `iat` near `i64::MIN` the subtraction overflows: a debug build
  panics (`attempt to subtract with overflow`, reproduced by
  `w3_1_max_ttl_overflow_reproducer`), a release build wraps to a negative
  width that passes any `max-ttl`. The bypass itself is D16 (an inverted
  window already passes); the new facts are the panic and that D16's fix
  must use checked arithmetic, not just an `iat <= exp` guard.
- **Test:** `max_ttl_check_never_overflows` (ignored). Minimal failing
  input `iat = -5137354651442195772, exp = 4086017385412580036, max = 0`.
- **Fix shape:** reject `iat > exp` on every object (S6) and compute the
  width with `checked_sub`, treating `None` as a violation.

### W3-2 — status-list freshness arithmetic overflows on issuer-chosen `iat`/`ttl` (Low)

- **Where:** `browserid-core/src/status.rs:190` (`is_fresh`) and `:198` (`is_fresh_capped`): `iat + ttl + grace`.
- **What:** a foreign issuer publishes the list. `ttl` is capped by `min`
  but a negative `ttl` passes the cap, and `iat` is unbounded. Debug builds
  panic; release builds wrap. The wrapped sum can land on a huge positive
  value, so a crafted `(iat, ttl)` pair reads as fresh for ever under
  `is_fresh_capped` — the audit-M3 ceiling is defeated for that list. Low
  because the party crafting the list is the issuer whose revocations the
  ceiling exists to honour; it matters only in the compromised-then-
  recovered-issuer story.
- **Test:** `status_list_freshness_never_overflows` (ignored). Minimal
  failing input `iat = -3379531234735100752, ttl = -5843840802119675057`.
- **Fix shape:** reject `ttl < 0` and `iat` outside `[now − max_ttl − skew, now + skew]`
  at parse/verify, and use `checked_add`.

### W3-3 — the registrar does not enforce the one scope grammar (Medium)

- **Where:** `browserid-registrar/src/consent.rs:868-889` (`validate_grant_shape`): `scopes.len() > 32 || s.scope().len() > 128` is the whole check.
- **What:** registry-api-v1 §3 and `request-kinds/warrant.json` pin scope
  strings to `^[a-z0-9_:.\-/*@+]{1,128}$` ("the one scope grammar, which
  core §5, request-kinds, wallets, and SDKs reference rather than restate").
  The wallet enforces it (`wallet/src/request.js:22`); the registrar, which
  signs the request into a warrant and renders it on the consent card,
  accepts any ≤128-byte string: empty, uppercase, whitespace, control and
  bidi characters, non-ASCII. Consequences: (a) a filed `warrant` request
  from an agent can put arbitrary text into the scope line of the consent
  card (the card strips control/bidi per the request-kinds README, so this
  is a card-rendering dependency rather than a confirmed injection); (b)
  consumers that assume the grammar (fingerprints, status subjects, SDK
  scope matching) see values outside their contract; (c) an empty scope
  string is accepted and signed.
- **Test:** registrar `grant_shape_accepts_exactly_the_scope_grammar`
  (ignored); minimal failing input is the empty scope.
- **Fix shape:** one `scope_grammar(&str) -> bool` in core (`identity.rs`
  is the analogous home) used by `validate_grant_shape`, `warrant_to_record`
  and the admission `AuthoringGrantItem` path; reject with `400 invalid_request`.

### W3-4 — `StatusList::from_revoked` / `set` allocate on an unbounded index (Low, issuer-side)

- **Where:** `browserid-core/src/status.rs:66-81`.
- **What:** `from_revoked(_, capacity)` computes `(capacity as usize + 8) / 8 + 1`
  (overflow at the top of `usize`) and `set(idx)` resizes the bitmap to
  `idx / 8 + 1` bytes — an index of 2^40 allocates 128 GiB. Both are
  publisher-side (the registrar allocates indices sequentially), so no
  remote path reaches them; recorded so the fix for W6-3 bounds the
  encoder too. Not fuzzed (would only OOM the harness).
- **Test:** none added (allocation-only); the fuzz target bounds `raw` to 4 MiB.

### Observations (no finding)

- `jws_decode` never reads the header; `jws_verify` pins `alg` (WS6 W6-2
  covers `Assertion`). The fuzzers confirm no parser panics on any header.
- `ScopeEntry::Bare` is grammar-agnostic by design (verifiers compare
  identities byte-exact); the grammar is a request-time rule. Recorded in
  `scope_grammar_reference_matches_the_spec_regex`.
- `identity_matches` byte-exact domain comparison in the exact/subaddress
  branches (WS6 W6-1) is visible to the `identity` fuzz target's reference
  implementation, which mirrors it on purpose; the property suite generates
  lowercase domains so it tests I13, not W6-1.
- warrant.json's filed form lacks `device_cert`/`identity`, which the
  registrar requires; the fuzz differential adds them before comparing.
  Whether the schema should carry them is a spec-tidiness question for
  WS1, not a security gap.
- **Schema ↔ registrar divergence on scope parameters (found by
  `request_kind_json` on its first run).** warrant.json declares scope
  parameter objects `additionalProperties: true` and types only `scope` and
  `mode`; the registrar's `ScopeParams` and `Cap` deny unknown fields. So
  the schema accepts `{"scope":"pay:send","cap":{"outnam":"1","currency":"USD"}}`
  and the registrar rejects it. The registrar is the fail-closed side, which
  is what the schema's prose asks for ("refuses a parameter it cannot
  classify"), so this is not a gap — but the schema cannot serve as the
  wire contract for the `pay:`/`contract:` family until it pins `cap`,
  `counterparties`, `max_duration`, `min_reputation` (or `$ref`s a family
  schema). The differential in the target is now restricted to the
  schema's core subset. Also: provision.json `$ref`s warrant.json by `$id`,
  so any validator must preload both; the first harness run failed on that.

## 4. Decisions needed

1. **W3-3 severity and owner.** Medium as recorded (the card is the
   mitigation, and it is JS); if Dan reads the consent card's
   control/bidi stripping as sufficient, Low. Either way the grammar
   check belongs in core and the registrar should call it.
2. **Time-bound fix shape (S6 / D16 / W3-1 / W3-2 together).** One
   normative clock rule for every object (`iat <= exp`, `iat <= now + skew`,
   checked arithmetic, `ttl >= 0`) rather than four local patches; the WS1
   spec edits already made the time bounds normative, so this is a code
   task. Ignored tests across WS3 and WS6 are the acceptance set.
3. **Fuzzing cadence.** The smoke target is manual. A weekly 15-minute-per-
   target run on the dev box via the existing launchd pattern, or nothing
   until the parsers change — Dan's call; CI is deliberately untouched.

## 5. Files

- `browserid-core/tests/audit_2026_11_ws3_proptest.rs`, `audit_2026_11_ws3_status_alloc.rs`
- `browserid-registrar/src/consent/audit_2026_11_ws3_proptest.rs` (+ one `#[cfg(test)] mod` line at the end of `consent.rs`)
- `fuzz/` (manifest, `src/lib.rs` fixtures, `src/bin/gen_seeds.rs`, seven `fuzz_targets/*.rs`, `seeds/`, `README.md`)
- `scripts/fuzz-smoke.sh`, `Makefile` (`fuzz-smoke`)
- Dev-dependency additions in `browserid-core/Cargo.toml`, `browserid-registrar/Cargo.toml`, `Cargo.lock`
