<!-- This Source Code Form is subject to the terms of the Mozilla Public
   - License, v. 2.0. If a copy of the MPL was not distributed with this
   - file, You can obtain one at http://mozilla.org/MPL/2.0/. -->

# Security audit 2026-11 — WS6: crypto core, verifier, DNSSEC re-verification

**Status:** skeptic pass complete, 2026-11-02. Epic `browserid-ng-ag1l`, bean
`browserid-ng-p5vc`. Scope: `browserid-core` (jws, keys, assertion,
attestation, admission, device certs, status, identity, discovery, dns),
`browserid-verifier`, `browserid-dnssec`, plus the `browserid-rp` status path
WS1 routed here (D15). Oracle: `docs/design/threat-model.md` I1–I11, I13, I14;
spec `docs/specs/browserid-ng-protocol.md` §3, §4.6, §4.7, §5, §6.1, §6.3,
§6.4, §8.

**Method.** Reviewer pass over every file in scope, then a skeptic pass that
tried to refute each finding by writing a Rust test. Every verdict below is
backed by a test that runs today. Tests encoding an invariant that FAILS today
are `#[ignore]`d with an `// AUDIT-2026-11 Dx: fails today` comment and are
the acceptance test for the fix; everything else passes today and pins what
the audit re-verified. No production code was changed.

| Crate | Test file | Pass | Ignored (fail today) |
|---|---|---|---|
| browserid-core | `browserid-core/tests/audit_2026_11_ws6.rs` | 17 | 9 |
| browserid-verifier | `browserid-verifier/tests/audit_2026_11_ws6.rs` | 6 | 2 |
| browserid-dnssec | `browserid-dnssec/tests/audit_2026_11_ws6.rs` | 0 | 2 |
| browserid-rp | `browserid-rp/tests/audit_2026_11_ws6.rs` | 0 | 2 |

Run the failing set with `cargo test -p <crate> --test audit_2026_11_ws6 -- --ignored`.
Only dev-dependencies changed (`browserid-verifier/Cargo.toml`: chrono, serde_json).

## 1. Verdicts on the WS1 candidates

| ID | Verdict | Severity | Where | Test |
|---|---|---|---|---|
| D1 | **CONFIRMED** | High | `browserid-core/src/device.rs:96-111` (`identity_matches`, subaddress branch); gates both mints: `browserid-broker/src/routes/device.rs:455`, `routes/hosted_idp.rs:536` via `DeviceCert::authorizes_identity` | `d1_authentication_cert_for_base_identity_does_not_authorize_subaddress` |
| D7 | **CONFIRMED** | Medium | `browserid-verifier/src/verify.rs:122` (`AccessVerificationResult.scopes: Vec<String>`), `:487`, `:602`, `:689` | `d7_verify_response_carries_scope_parameters`, `d7_validate_record_response_carries_scope_parameters` |
| D14 | **CONFIRMED** | Medium | `browserid-dnssec/src/dns.rs:139-184` (`lookup`: connect error, send error, no response, bad name → `insecure()`), `:273-276` and `lib.rs:268` (`Insecure → NotPrimary`); `dns.rs:545-548` (`Refused`/other rcodes → insecure) | `d14_transport_failure_is_not_an_insecure_answer`, `d14_resolve_idp_key_does_not_report_not_primary_on_transport_failure` |
| D15 | **CONFIRMED** (pinned-table path only) | Medium | `browserid-rp/src/lib.rs:272-290` (`refresh_status`: `reqwest::get`, no host==iss), `:723` (`StatusCache::refresh`), `:779` (`verdict`: `is_fresh(600)` uncapped) | `d15_pinned_status_refresh_refuses_redirects_and_private_hosts`, `d15_pinned_status_cache_caps_the_issuer_declared_ttl` |
| D16 / S6 | **CONFIRMED** | Medium | `device.rs:61` (`expired_at` only), `:314-317` (`exp - iat` unsigned), `admission.rs` `validate` (no iat), `status.rs:1007/1015` (`is_fresh*`: no iat bound) | `s6_*` (3), `d16_future_iat_defeats_max_ttl`, `d16_status_list_with_future_iat_is_not_fresh` |
| S3 | **CONFIRMED open** (decision: drop v1) | Medium | accept paths listed in §1.3 | `s3_v1_warrant_rejects_in_presentation`, `s3_v1_record_rejects_in_admission` |
| S5 | **REFUTED for the Rust path** — core already fails closed on unknown keys and enforces `aud`/`scopes`/`max-ttl`; one corner flagged | — | `device.rs:287-320` | `s5_*` (4, all passing) |

### 1.1 D1 — subaddress widening at the mint (High)

`identity_matches` has three branches: exact, single-`*` glob, and an
unconditional "base identity authorizes `base+anything@domain`" rule. The
rule is purpose-blind: `DeviceCert::authorizes_identity` applies it to
`authentication` certs, and both access-cert mints use nothing else to decide
whether the presented device cert may mint for `access_request.identity`.
Spec §4.6 says the opposite: subaddressing applies to **authorization only**;
an auth cert for `user@d` mints for `user@d` exactly (I13).

What the attacker gets: any browser device cert (the user's own, or a stolen
one) mints access certs for every `user+tag@d` agent identity of that user,
so the per-agent cert and its revocation axis are bypassed; the minted access
cert carries the browser's holder, so a warrant whose matcher covers the
browser namespace (the common `br.*` login warrant does not, an `*` matcher
would) joins. The existing unit test
`device::tests::base_identity_authorizes_subaddresses` encodes the widening
as intended behaviour and the July audit listed it as a "verified non-issue"
for the config-cert case only; that reasoning does not transfer to the auth
cert, which is the mint credential.

Remediation: split the predicate. `authorizes_identity` keeps the exact and
glob branches; the subaddress rule moves to a separate
`authorizes_grantor` used only by the two config-cert checks
(`AccessPresentation::verify_at` step 5 and `RecordBundle::validate` step 1b).
Then un-ignore the D1 test and invert the expectations in
`base_identity_authorizes_subaddresses` for the auth purpose. WS8's PoC
against `/access/mint` should be re-run after the change.

### 1.2 D7 — scope parameters dropped at the HTTP verifier (Medium)

Core preserves parameters (`VerifiedAccess.scope_entries`, pinned by
`core_verified_access_preserves_scope_parameters`). The hosted response
structs project them to strings; a `pay:usd` entry with `cap 20.00 USD / P1D`
arrives at every SDK consumer of `/verify` and `/validate-record` as the bare
string `pay:usd`. Under the S7 decision (relays pass entries through
verbatim) this is a straight conformance gap, and until browserid-pay's
custodian reads parameters from somewhere other than the hosted verifier,
every attenuation is void downstream of it.

Remediation: change `scopes` on both result structs to `Vec<ScopeEntry>`
(serde already emits a bare string for a parameterless entry, so the wire
shape is unchanged for today's records), or add a `scope_entries` field and
deprecate `scopes`. `browserid-rp::VerifiedIdentity.scopes` has the same
projection and should follow.

### 1.3 S3 — every accept path for `browserid-warrant-v1`

All paths funnel through one gate: `Warrant::validate_claims`, arm
`TYP_WARRANT` at `device.rs:1304`. Callers that therefore accept v1 today:

- `Warrant::parse` → `AccessPresentation::parse` → `verify`/`verify_at` (core);
- `RecordBundle::parse` → `validate` (core admission);
- `verify_access_core` / `verify_access_with_dns` and
  `validate_record_with_dns` (hosted `/verify`, `/validate-record`,
  `browserid-rp::Verifier::verify_dnssec`) — via the two core parsers above;
- `browserid-rp::Verifier::verify` (pinned path) — via `AccessPresentation::parse`;
- `Warrant::create` still *emits* v1 (`device.rs:1231`), and a v1 record may
  omit `status` (I10, confirmed: the test signs one and it verifies).

Dropping v1 is a one-arm change in `validate_claims` plus deleting
`Warrant::create`, `WarrantClaims::holder`, and the v1 fixtures in
`device/tests.rs`, `admission.rs` tests, and `test-vectors/device-cert-v1.json`
(regenerate). The JS signers listed in the WS1 §5 decision must move first.

### 1.4 D14 — DoT transport failure demotes primaries (Medium)

`DnsFetcher::lookup` returns `DnsLookupResult::insecure()` on: an unparsable
name, a failed TLS connect, a send error, an empty response stream, and any
rcode other than `NoError`/`NXDomain`/`ServFail` (so `Refused` too — the
existing unit test `test_refused_is_insecure_not_bogus` pins the wrong
answer). `FallbackFetcher::discover` then takes the `Insecure` arm and
resolves the **fallback** key, and `resolve_conformant_key` accepts any
`iss` in the RP's accepted set for that domain. Spec §3 defines "insecure" as
an AD-unset *answer*; a transport failure carries no DNSSEC signal and the
module's own docstring admits the downgrade.

What the attacker gets: with port 853 blocked (A7), a domain that runs a
primary is treated as no-primary for the duration. To exploit it the attacker
still needs a fallback-issued cert for an identity in that domain, which
requires the fallback (browserid.me) to have issued one — the fallback checks
the same DNS, so an attacker who can block the verifier's resolver path but
not the broker's gets nothing, and one who can block both still needs to pass
the broker's mailbox proof. Bounded, but it is exactly the B1 boundary the
spec says holds unconditionally, and the fallback itself (`fallback_to_broker`)
already treats its own `Insecure` as a hard error, so the asymmetry is
accidental.

Remediation: return a distinct transport-failure variant (or `bogus()`) from
every non-answer path in `lookup`, map `Refused`/unexpected rcodes to it, and
have `discover` surface it as `VerifierError::Discovery` rather than falling
back. Then flip `test_refused_is_insecure_not_bogus` and un-ignore the two
D14 tests. Consider retrying the DoT connect once before failing, since the
change turns resolver blips into login failures.

### 1.5 D15 — browserid-rp pinned-table status path (Medium)

Confirmed on the pinned path only. `Verifier::verify_dnssec` delegates to the
hosted verifier's fetch (no redirects, https only, non-global addresses
rejected before any request, list `iss` must equal the URI host, `ttl` capped
at 300 s) — pinned by `i9_foreign_status_on_a_private_or_plain_http_host_is_never_fetched`.
The pinned path does none of it: the test serves a 302 from a loopback `http`
URI to a second loopback server and `StatusCache::refresh` accepts and caches
the list; a list declaring `ttl` of ten years stays `Valid` a year after its
`iat`. `refresh_status` requires the list's `iss` to be a trusted issuer but
never ties it to the URI host.

The RP operator chooses which URIs to refresh, so the SSRF is operator-steered
rather than attacker-steered, which is why this is Medium not High. The ttl
cap is the July M3 class, closed on the hosted path only.

Remediation: build the client with `redirect::Policy::none()`, require
`https`, reuse `browserid_verifier::verify::validate_status_url`, check URI
host == `iss` (or the discovered `host=`), and switch `verdict` to
`is_fresh_capped(grace, 300)`. Or deprecate `refresh`/`refresh_status` in
favour of `fetch_foreign_status_list`.

### 1.6 D16 / S6 — no lower bound on `iat` (Medium)

No object in core compares `iat` to anything: `verify_at` and
`RecordBundle::validate` check `exp` only, `Constraints::check` computes
`exp - iat` and compares a possibly negative number to `max-ttl`, and the
status-list freshness tests are `now <= iat + ttl` with `iat` unbounded, so a
future-dated list is fresh forever and the M3 cap is bypassed by the one
field it does not cap. A signer able to write `iat` (any config key for
warrants; an IdP for certs and lists) defeats `max-ttl` and the foreign-list
ceiling. `HandleAttestation::verify` is the one object that already bounds
`iat` (`now + 60`), which is the pattern to copy.

Remediation, per the accepted S6 wording: in `verify_at`,
`RecordBundle::validate`, and `recheck_live` reject any object with
`iat > exp` or `iat > at + skew` (skew 60–300 s); in `is_fresh*` treat
`iat > now + skew` as stale. Five ignored tests cover these.

### 1.7 S5 — constraints

Refuted as a code gap for the Rust path: unknown keys reject on either cert
in presentation and in admission (`s5_unknown_constraint_key_*`), and the
three implemented keys are enforced (`s5_implemented_constraint_keys_are_enforced`).
Spec §4.7 still says "not yet implemented", so the S5 sentence should name
`browserid-core` (and everything built on it) as implementing `aud`, `scopes`,
`max-ttl`. One corner for Dan: a `scopes` allowlist is vacuous against a
scope-less login warrant (`s5_scope_allowlist_is_vacuous_for_a_scope_less_login_warrant`
passes today). The WS1 note "define that an allowlist applies to logins as
`[]`" can be read either way; the test documents the current reading.

## 2. New findings

| ID | Verdict | Severity | Where | Test |
|---|---|---|---|---|
| W6-1 | PARTIAL (stricter than spec) | Low | `device.rs:73-74`, `:107` — exact and subaddress branches of `identity_matches` compare the domain byte-exact, not under §5 | `w6_1_grantor_match_uses_spec_domain_comparison` (ignored, fails today) |
| W6-2 | Informational | Low | `assertion.rs:570-582` — `Assertion::verify` never reads the JOSE header; every other object pins `alg == EdDSA` in `jws_verify` | `w6_2_assertion_without_a_valid_ed25519_signature_rejects_regardless_of_header` (passes) |
| W6-3 | Informational | Low | `status.rs:914-926` — `StatusList::decode` reads the whole inflate output before applying the 4 MiB cap, so a crafted list allocates up to the transport cap × compression ratio before rejecting | none (hosted path bounds the body at 4 MiB; a zlib bomb within that still inflates fully) |

W6-1 is fail-closed: a config cert for `user@example.com` does not cover a
grantor written `user@EXAMPLE.com`, where §5 says it should. Unreachable in
practice because issuers emit lowercase A-labels, but it is the same
parser-differential class as July L1. Fix by routing the exact branch through
`identity::identity_eq` and the subaddress branch through `domain_eq`. W6-2
is not exploitable (Ed25519 still has to verify under the access key) but is
the one typed-signing inconsistency left. W6-3: wrap the decoder in
`.take(4 MiB + 1)`.

## 3. Invariants re-verified (passing tests)

- **I1** bundle shape, unknown `typ`, unknown `purpose`, unknown binding
  `kind`, object-in-wrong-slot all reject at parse
  (`i1_bundle_shape_and_unknown_typ_or_purpose_reject`).
- **I2** the resolver is called once per distinct `iss` and nothing else;
  after a failed access-cert signature the config issuer is never resolved
  (`i2_resolver_is_consulted_for_issuers_only_and_crypto_gates_the_rest`).
  Step-1 structural reads of unverified warrant claims (binding shape,
  matcher grantee) precede crypto, as §6.1 orders them; the only network
  before a signature check is DNSSEC discovery of the two `iss` values, which
  the spec requires. Status fetches run after the full join.
- **I3** fallback-issued cert for a primary domain rejects; issuer outside
  the accepted set rejects; grantor and grantee issuers checked independently
  so a primary cannot vouch for another domain's grantor (`i3_*`, verifier).
- **I4** assertion `aud`, warrant `audience`, and the expected audience are
  byte-exact: trailing slash, case, explicit `:443`, scheme, path all reject
  (`i4_audience_has_no_slack`).
- **I5** grantee ↔ access identity: domain case-insensitive, local part
  byte-exact, subaddress distinct (`i5_grantee_join_uses_spec_comparison`).
  The grantor side is W6-1.
- **I8** see S5.
- **I9** uncheckable own-list ref rejects; a foreign ref on `http`, loopback,
  link-local, or `::1` is refused before any request is sent (verifier
  `i9_*`). Note the hosted verifier binds the *list's* `iss` to the URI host
  (the S4 decision's rule) and does not check a *cert's* `status.uri` host
  against the cert's `iss`; I9's last clause is therefore stricter than the
  decided spec and is not implemented anywhere. Recommend aligning I9 to S4.
- **I10** confirmed as stated (status-less v1 verifies today); resolved by S3.
- **I13** the authorization half holds
  (`i13_authorization_cert_for_base_identity_covers_subaddressed_grantor`);
  the authentication half is D1.
- **I14** holder is copied at the mint and the warrant matcher is checked
  against the access cert's holder; namespace boundary is exact
  (`holder_matcher_namespace_boundary_is_exact`; existing
  `holder_passthrough_copy_and_isolation`).
- **Key and signature pins**: 32-byte keys, 64-byte signatures, 32-byte
  seeds (`key_and_signature_lengths_are_pinned`); `alg` pinned to `EdDSA` on
  device cert, warrant, access cert, status list even when the signature over
  the tampered header is valid (`alg_header_is_pinned_to_eddsa_on_typed_objects`).
- **Admission (§6.4)**: `matches_login` fails closed on connection entries,
  requester entries, and holder-less logins against a non-`*` matcher
  (existing `admission::tests`, re-read; not re-encoded).

## 4. July 2026 findings touching these crates, re-verified

| July | Then | Now |
|---|---|---|
| H1 blind SSRF in foreign status fetch | fixed in hosted verifier | **Holds** on `verify_access_core` / `fetch_foreign_status_list` (`i9_foreign_status_on_a_private_or_plain_http_host_is_never_fetched`). **Still open** on the `browserid-rp` pinned path — D15. The TOCTOU note in `validate_status_url` (resolve-then-connect) is unchanged. |
| M3 uncapped foreign `ttl` | fixed via `is_fresh_capped` | **Holds** on the hosted path; **open** on `browserid-rp::StatusCache` (D15) and bypassable everywhere by a future `iat` (D16). |
| M4 unbounded cache / body / no negative cache | fixed | **Holds**: 1024-entry caps, 4 MiB `read_capped`, 30 s negative cache (read; not re-encoded). |
| M5 malformed-but-signed record demotes primary | fixed | **Holds** (existing dnssec unit tests). The sibling demotion on transport failure is D14. |
| L1 parser differential | fixed with `identity::email_parts` | **Holds** for grantee/grantor well-formedness and the glob branch; the exact/subaddress branches of `identity_matches` still bypass `domain_eq` (W6-1). |
| L4 cross-issuer safety as caller precondition | documented | **Holds**: `verify_access_core` resolves both issuers under their own domains (`i3_grantor_and_grantee_issuers_are_checked_independently`). |
| L5 unanchored glob | fixed | **Holds** (`identity_glob_is_domain_anchored` existing; `subaddress_never_widens_upward_or_sideways`). |
| L6 RP static primaries | documented | Unchanged by design on `Verifier::verify`; `verify_dnssec` is the conformant path. |
| L11 rustls 0.21 EOL | upgrade tracked | Not re-checked here (dependency audit is outside WS6). |
| "Verified non-issue": config-cert `+*` widening is redundant | accepted | **Still true for config certs**, but the same rule on auth certs is D1 — the July reasoning did not cover the mint. |

## 5. What needs Dan's decision

1. **D1 severity and ordering.** It is the one High in this workstream and a
   two-line core change plus a flipped unit test; WS8 should PoC it against
   the live mint first so the fix is measured.
2. **S5 login corner.** Should a non-empty `scopes` allowlist refuse a
   scope-less login warrant, or is a login always inside every allowlist?
   The test pins the latter today.
3. **I9 wording.** Align the threat model's "a cert `status.uri` host equals
   its `iss`" to the S4 decision (list `iss` == URI host, signed by that
   host's DNSSEC key), or ask for the stricter cert-side check too; nothing
   implements the stricter one.
4. **D14 remediation shape.** Hard reject on transport failure makes resolver
   outages into login failures; decide whether `lookup` retries once first.
5. **D15 scope.** Fix the pinned path or deprecate `refresh`/`refresh_status`
   and point RPs at `verify_dnssec` only.
