<!-- This Source Code Form is subject to the terms of the Mozilla Public
   - License, v. 2.0. If a copy of the MPL was not distributed with this
   - file, You can obtain one at http://mozilla.org/MPL/2.0/. -->

# Security audit 2026-11 — WS2: conformance vectors across every verifier

**Status:** complete, 2026-11-02. Epic `browserid-ng-ag1l`, bean
`browserid-ng-p1ao`. Oracle: `docs/design/threat-model.md` I1–I11 (plus
I12/I13 where a chain vector was cheap) and spec
`docs/specs/browserid-ng-protocol.md` §4–§6 as amended on this branch (v1
retired, any `constraints` rejects, `iat` bounds, the one identity rule,
scope entries verbatim). Where spec and code disagree the spec wins and the
code shows up as an expected-fail entry below. No production code changed.

**Method.** A deterministic Rust generator signs every object as a raw JWS
over a JSON claim set from fixed seeds, so malformed objects are as easy to
produce as valid ones and the suite is byte-for-byte regenerable
(`WS2_REGEN=1`). One runner per verifier loads the suite and judges each
vector; every runner carries an `EXPECTED_FAIL` table of vectors that
verifier gets wrong today, each tagged `AUDIT-2026-11 <finding>`. A runner
fails on any other disagreement **and** on a listed vector that starts
agreeing, so deleting an entry is the acceptance test for the fix (same
convention as WS5/WS6). The three SDKs that delegate to the hosted service
replay the responses the in-process hosted runner records per vector, through
their injectable fetch, with the request checked for an intact bundle and
audience — so an SDK that alters what it sends is caught as `request
diverged`.

| Artefact | Path |
|---|---|
| Vector suite (177 vectors, environment, keys) | `test-vectors/conformance-2026-11.json` |
| Recorded hosted responses per vector | `test-vectors/conformance-2026-11.hosted.json` |
| Generator + drift check | `browserid-core/tests/audit_2026_11_ws2_generate.rs` |
| Rust core runner | `browserid-core/tests/audit_2026_11_ws2_runner.rs` |
| Hosted `/verify` + `/validate-record` runner (in-process, records responses) | `browserid-verifier/tests/audit_2026_11_ws2_runner.rs` |
| `@browserid-ng/verify` runner | `sdk/js/conformance.test.mjs` |
| `browserid-mcp-auth` (python) runner | `sdk/python-mcp-auth/tests/test_conformance_vectors.py` |
| `@browserid-ng/mcp-auth` runner (P and A, incl. its own subject match) | `sdk/mcp-auth/test/conformance-vectors.test.mjs` |
| `@browserid-ng/gate` runner (mount over real HTTP, fake child) | `sdk/gate/test/conformance-vectors.test.mjs` |
| CI | `.github/workflows/test.yml` (generate + core + hosted), `sdk-tests.yml` (js, mcp-auth, gate, python) |

The wallet (`wallet/`, `sdk/wallet`) has no verifier — it signs and stores —
so there is no wallet runner; D12's unverified-stored-grant signing is WS4's.

## 1. Results per verifier

| Runner | Vectors judged | Pass | Expected-fail | Skipped | Unexpected |
|---|---|---|---|---|---|
| Rust core (`verify_at` + `validate` + `matches_login` + `DnsRecord::parse`, with the resolver and status obligations core documents) | 177 | 163 | 14 | 0 | 0 |
| Hosted (in-process; op A stops at record validation) | 159 | 143 | 16 | 18 (op T: the TXT parser is core's) | 0 |
| sdk/js | 116 (P only) + 1 entries probe | 104 | 13 | 61 (no record API, no parser) | 0 |
| python-mcp-auth | 116 (P only) + 1 entries probe | 103 | 14 | 61 (no record API, no parser) | 0 |
| mcp-auth | 159 + 2 entries probes | 137 | 24 | 18 (op T) | 0 |
| gate | 116 P + 11 allowlist case probes + 38 op-A records in policy mode | 119 | 46 | 23 (op A without a login subject, op T) | 0 |

Two probe kinds were added at WS4's request (2026-11-02): `<id>/entries`
replays the hosted response a D7-fixed verifier would return (scope entries
as objects) through sdk/js, python and mcp-auth; and the gate runner feeds
every op-A vector that has a login subject into a policy-mode mount
(`owners` + `policyStore` holding the vector's record, the subject arriving
as a jwt-bearer whose synthetic `/verify` answer names it), so the gate's own
admission path — not mcp-auth's — is what admits or refuses.

Every runner is green in CI today with its expected-fail table; the tables
are the open-findings ledger.

## 2. Findings

Severity follows the WS6 scale. "Confirmed" means the vector reproduces the
WS1 candidate; W2-n are new or newly pinned.

| ID | Verdict | Severity | Where | Vectors |
|---|---|---|---|---|
| **W2-1** | NEW | Low | `sdk/python-mcp-auth/browserid_mcp_auth/__init__.py:135` (`resource.rstrip("/")`), `sdk/mcp-auth/index.mjs:159` (`replace(/\/+$/, "")`), `sdk/gate/src/mount.mjs:55` (same) — the audience sent to `/verify` is not the audience the record names | P-OK-07 |
| **W2-2** (= D5) | **CONFIRMED** | Medium | `sdk/mcp-auth/index.mjs:1040,1051` — admission matches a subject with `granteeCovers` alone; `requester`, `connection` and `holder` entries are never evaluated. Gate inherits it (`gateway.mjs:121`, `mount.mjs:82`) | A-REJ-01…05 |
| **W2-3** (= D17, mcp-auth half) | **CONFIRMED** | Low | `sdk/mcp-auth/index.mjs:71-94` — `splitEmail` splits on the *last* `@`; `granteeCovers("*", s)` is `s.includes("@")` | A-REJ-07, -08, -09 |
| **W2-4** (= D17, gate half) | **CONFIRMED** | Low | `sdk/gate/src/mount.mjs:61,318` — allowlist and verified grantor both lowercased before comparison | every `P-OK-nn/case` probe |
| **W2-5** | NEW (conformance) | Low | `sdk/js/index.mjs:116-125` — the result omits `holder` and `grantee_issuer` that §6.1 step 9 requires a verifier to return | P-OK-01 (field absent, not compared) |
| W4-14 | **CONFIRMED** | Low | `sdk/python-mcp-auth/browserid_mcp_auth/__init__.py:235` — an object scope entry raises `TypeError` in `" ".join(scopes)`; sdk/js and mcp-auth carry the objects through | P-OK-08/entries |
| D6 | **CONFIRMED** (single-server mount) | Medium | `sdk/gate/src/mount.mjs:76-85` — the default entitlement reads policy rows with `granteeCovers` only and never validates the record: expired, revoked, mis-signed, wrong-issuer, constraint-violating, v1, status-less and unknown-parameter records all admit | A-REJ-13, -20…-31 (gate) |
| **W2-6** | NEW | Low | `browserid-core/src/dns.rs:30-45` — `DnsRecord::parse` keeps the last of duplicated fields, so a `_browserid` record naming two `public-key` values resolves to the second | T-REJ-11 |
| D7 | **CONFIRMED** across the whole SDK tree | Medium | hosted `verify.rs:122,487` flattens entries; every SDK relays strings | P-OK-07, P-OK-08, A-OK-08 |
| D16 / S6 | CONFIRMED everywhere | Medium | no `iat` bound in core → every verifier | P-TIME-05…09, A-REJ-21 |
| S3 | CONFIRMED everywhere | Medium | v1 arm in `device.rs:1304` → every verifier | P-TYP-01, -02, A-REJ-13 |
| S5 | spec/code divergence, everywhere | — (decision) | core enforces `aud`/`scopes`/`max-ttl` while §4.7 says no reference verifier implements constraints | P-CONS-01, -06 |
| W6-1 | CONFIRMED everywhere | Low | grantor domain byte-exact in `identity_matches` | P-OK-12 |
| W6-4 | CONFIRMED everywhere | Medium | cert `status.uri` host never tied to `iss` | P-STAT-06 |

### W2-1 — SDKs rewrite the audience before verification

`McpAuth(resource=…)`, `createMcpAuth({resource})` and `createMount({resource})`
strip trailing slashes from the resource and send the stripped string as
`audience`. Spec §5 makes `audience` an exact string, and the shipped
signing-grant audience `sbo+raw://avail:turing:506/` ends in a slash, so a
record for such an audience can never verify through these three SDKs: the
hosted verifier is asked about a different audience (the runner shows
`audience sent "sbo+raw://avail:turing:506"`). Fail-closed, so availability
rather than escalation; it is the same class as the WS1 §3 note on python.
`@browserid-ng/verify` passes the audience verbatim. Fix: drop the
normalization (OAuth resource identifiers are supplied by the operator; if a
canonical form is wanted, apply it once at configuration and document it).

### W2-2 — admission ignores every binding entry (D5)

`conjoinPolicy` filters policy rows with `granteeCovers(r.grantee, subject)`
and accepts the first row that validates. The record's binding set is never
read. Hence, with a record the hosted validator returns as `okay`:

- a `requester` entry — unsatisfiable in op A by §5's table — admits
  (A-REJ-01);
- a `connection`-bound policy row admits a *login* subject (A-REJ-02);
- a `holder` matcher pinned to `svc.one` admits a subject whose login holder
  is `svc.two`, a different namespace, or no holder at all (A-REJ-03…05).

Core's `matches_login` rejects all five. The grantor's narrowing of a policy
row to one holder is therefore not enforced by the reference MCP lane. The
hosted response already carries `binding` (recorded in the `.hosted.json`
file), so the fix is local to the SDK: evaluate every entry per §6.4 step 3
(port `matches_login`), and refuse rows whose set contains a `requester` or
`connection` entry when the subject is a login. WS4 owns the code-level
remediation; this runner is its acceptance test.

### W2-3 / W2-4 — identity comparison (D17)

mcp-auth: `granteeCovers("*", "a@b@c.example")` and
`granteeCovers("*@example.com", "a@b@example.com")` are true, and `"@x"`
splits into an empty local part that compares equal to itself. Core's
`email_parts` rejects all three. Reachability is limited — the hosted
verifier never attributes a malformed identity, so the subject must arrive
through some other login path — hence Low. Gate: the allowlist and the
verified grantor are both lowercased, so an entry `User@example.com` admits
`user@example.com` (eleven probes, one per accept vector). Spec §5: the local
part is byte-exact, and a component that lowercases it is non-conforming.
The fix for both is to route through one `identityEq`/`granteeCovers` that
uses `email_parts`' exactly-one-`@` rule and never touches the local part.

### W2-6 — duplicated fields in the `_browserid` TXT record

The parser loops over `;`-separated fields and overwrites on repeats, so
`public-key=A; public-key=B` yields B with no error, and the same for `v`,
the algorithm and `host`. One DNSSEC-signed record is the sole trust root
(§3, B1); a record that names two keys is ambiguous and under B5 should
reject, not pick the later one. Exploiting it needs write access to the
zone, which already means owning the key, so this is a robustness finding:
the hazard is a zone-editing mistake that leaves a stale key live and
invisible. Fix: reject a repeated field. (browserid-dnssec already rejects
*two records*, `test_multiple_browserid_records_signed_is_bogus`; this is
the within-record twin.) The other twelve malformed-TXT vectors reject as
expected, including standard-alphabet base64 with padding, 31- and 33-byte
keys, comma separators and upper-case field names.

### W2-5 — `@browserid-ng/verify` drops `holder` and `grantee_issuer`

The hosted response carries both; the SDK's result type does not. Not a
security gap (an RP cannot make a wrong decision on a field it never sees),
but §6.1 step 9 lists them as part of a verifier's answer and the gate's
attribution line wants `holder`. Add the two fields.

## 3. Disagreement matrix (I11)

Rows are vector families; a cell says what each verifier answers. `✓` =
agrees with the spec expectation; otherwise the finding that explains the
divergence. "inh." = inherited from the hosted response.

| Vectors | Expectation | Rust core | Hosted | sdk/js | python | mcp-auth | gate |
|---|---|---|---|---|---|---|---|
| all signature, shape, typ/purpose, audience, expiry, binding-in-P, grantee/grantor, issuer-authority, revocation vectors (109) | reject | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| all plain accept vectors (P-OK-01…06, -09…11, -13; A-OK-01…07, -09, -10) | accept | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| P-OK-07 (sbo audience with `/`, `mode` entry) | accept, entries verbatim | ✓ | D7 (strings) | D7 inh. | **W2-1** (audience altered) | **W2-1** | **W2-1** |
| P-OK-08, A-OK-08 (parameterized entries) | accept, entries verbatim | ✓ | D7 | D7 inh. | D7 inh. | D7 inh. | D7 inh. |
| P-OK-12 (grantor domain case) | accept | W6-1 | W6-1 | inh. | inh. | inh. | inh. |
| P-TIME-05…09, A-REJ-21 (post-dated, iat>exp) | reject | D16 | D16 | inh. | inh. | inh. | inh. |
| P-TYP-01/02, A-REJ-13 (v1) | reject | S3 | S3 | inh. | inh. | inh. | inh. |
| P-STAT-06 (cert status host ≠ iss) | reject | W6-4 | W6-4 | inh. | inh. | inh. | inh. |
| P-CONS-01/06 (satisfied / empty constraints) | reject (per §4.7 text) | S5 | S5 | inh. | inh. | inh. | inh. |
| A-REJ-01…05 (binding entries in op A) | reject at match | ✓ | n/a (validates; match is the SDK's) | n/a | n/a | **W2-2 / D5** (admits) | via mcp-auth |
| A-REJ-07…09 (malformed subjects) | reject at match | ✓ | n/a | n/a | n/a | **W2-3 / D17** (admits) | via mcp-auth |
| A-REJ-06, -10…12, -32, -33 (subject not covered) | reject at match | ✓ | n/a | n/a | n/a | ✓ | via mcp-auth |
| `P-OK-nn/case` probes (allowlist differs in local-part case) | reject | — | — | — | — | — | **W2-4 / D17** (admits) |
| A-REJ-01…05 in gate policy mode | refuse | — | — | — | — | — | **D5** (admits) |
| A-REJ-07…10 in gate policy mode | refuse | — | — | — | — | — | **D17** (admits) |
| A-REJ-13, -20…-31 in gate policy mode (record never validated) | refuse | — | — | — | — | — | **D6** (admits) |
| P-OK-08/entries, A-OK-08/entries (object scope entries from a D7-fixed hosted) | accept, entries verbatim | — | — | ✓ | **W4-14** (500) | ✓ | — |
| T-OK-01…05, T-REJ-01…10, -12, -13 (TXT record grammar) | per §3 | ✓ | n/a (calls core) | n/a | n/a | n/a | n/a |
| T-REJ-11 (two `public-key` fields) | reject | **W2-6** (last wins) | n/a | n/a | n/a | n/a | n/a |

Genuine cross-verifier disagreement — a vector where two verifiers in the
repo return different verdicts today — exists in exactly four places: D7
(core preserves parameters, everything behind the HTTP boundary flattens),
W2-1 (hosted and sdk/js verify the slash audience, the three resource-shaped
SDKs cannot), W2-2/D5 and W2-3/D17 (core's admission rejects, mcp-auth
admits). Everything else is the whole stack agreeing with each other and
disagreeing with the spec (S3, D16, S5, W6-1, W6-4), which the core fix
resolves for all six at once.

## 4. Invariants re-verified (agreeing vectors)

- **I1** ≠4 objects, swapped slots, non-JWS slot, unknown `typ` on warrant
  or access cert, access-cert typ in the config slot, unknown and wrong
  `purpose`, missing/empty holder, missing `exp`, scopes-as-string — all
  reject everywhere (P-SHAPE-01…06, P-TYP-03…09, P-TIME-10, P-SCOPE-04).
- **I2** four wrong-key signatures, a post-signature payload edit, `alg:
  none`, and an empty signature segment reject everywhere (P-SIG-01…07,
  A-REJ-24/25); a cert whose `iss` names the primary but is broker-signed
  fails on signature, not on resolution (P-ISS-06).
- **I3** fallback-for-primary, primary-for-foreign-domain, unaccepted
  issuer, and the cross-issuer grantor case reject in core (through the
  resolver obligation) and hosted alike (P-ISS-01…05, A-REJ-28). The
  `_browserid` TXT grammar: missing/unknown version, unsupported algorithm,
  missing/empty/short/long/non-base64url key, empty record, comma
  separators, upper-case field names all reject; host delegation, field
  order, whitespace and unknown fields parse (T-*). Duplicated fields are
  W2-6.
- **I4** trailing slash, case, explicit `:443`, scheme, path, foreign origin
  on the assertion; warrant audience mismatch, slash, array (P-AUD-01…09,
  A-REJ-18/19).
- **I5** grantee/grantor local-part case and subaddress differences reject;
  domain case differences on the grantee accept (P-ID-03…05, -07…09, P-OK-11,
  A-OK-04/09, A-REJ-10…12, -32, -33); malformed identities in any slot reject
  (P-ID-11…16). The grantor-domain half is W6-1.
- **I6** matcher grantees in P, connection in P, missing holder entry, dead
  paper, delegated multi-entry set, namespace-boundary and prefix slack on
  matchers, conjunctive holder entries (P-ID-01/02, P-BIND-01…12, -17, -18);
  in A: requester/connection/holder entries evaluated by core (A-REJ-01…05),
  the connection self-grant rule, unknown protocol, empty id, missing
  client_host (A-REJ-14…17).
- **I7** mismatching stamp, missing stamp, stamp without entry, non-origin
  requester (P-BIND-13…16); matched stamp accepts (P-OK-06).
- **I8** unknown binding kind alone or beside a holder entry, unknown
  constraint key, unknown scope parameter, entry without `scope`, bad `mode`
  value, unrecognized top-level claim on a set-form record (P-BIND-06/07,
  P-CONS-05, P-SCOPE-01…03, -05, A-REJ-30).
- **I9** revoked access cert, config cert (intermediate), warrant, and a
  revocation on a primary's foreign list all reject; a missing v2 status ref,
  a private-host and an unresolvable status URI reject fail-closed
  (P-STAT-01…05, -07…09, A-REJ-22/23/29). The cert-URI-host clause is W6-4.
- **I10** resolved by S3's decision; both v1 shapes (with and without
  `status`) still verify today (P-TYP-01/02).
- **I12/I13** the config-cert `scopes` allowlist and `max-ttl` stop a widened
  chain in both operations (P-CONS-03/04, A-REJ-26); subaddress covers
  downward only (P-OK-09, P-ID-08/09).

## 5. How to use the suite

```
# regenerate after editing a vector, then re-record the hosted responses
WS2_REGEN=1 cargo test -p browserid-core --test audit_2026_11_ws2_generate
WS2_REGEN=1 cargo test -p browserid-verifier --test audit_2026_11_ws2_runner
# judge
cargo test -p browserid-core --test audit_2026_11_ws2_runner -- --nocapture
cargo test -p browserid-verifier --test audit_2026_11_ws2_runner -- --nocapture
(cd sdk/js && node --test)
(cd sdk/mcp-auth && node --test test/conformance-vectors.test.mjs)
(cd sdk/gate && node --test test/conformance-vectors.test.mjs)
(cd sdk/python-mcp-auth && python3 -m unittest tests.test_conformance_vectors)
```

Vectors are valid for wall-clock verifiers until 2035 (`iat` 2025-10-09,
ten-year `exp`); the deterministic clock for `verify_at` is `environment.at`.
The hosted runner pre-seeds the primary's status list as a token signed by
the primary's deterministic key; only P-STAT-07/08 touch the network, and
both are refused before or at DNS.

Vectors for P-STAT-07/08 reach DNS only; op T has one implementation in the
repo (`DnsRecord::parse`, which browserid-dnssec calls), so only the core
runner judges it.

When a finding is fixed: delete its rows from every runner's `EXPECTED_FAIL`;
the runner fails until you do (`FIXED … remove it`). For S5, if Dan amends
§4.7 instead of core, flip P-CONS-01/06 to `accept` in the generator and
regenerate.

## 6. What needs Dan's decision

1. **S5 direction.** The spec text ("no verifier in the reference
   implementation implements this section") is false for core, which
   enforces `aud`, `scopes`, `max-ttl` and fails closed on anything else
   (WS6 §1.7). Either amend §4.7 to name core (then P-CONS-01/06 become
   accept vectors) or strip the implementation so any `constraints` claim
   rejects. Recommendation: amend the spec; the implementation is the
   conservative one.
2. **W2-1.** Confirm the three SDKs should stop stripping the trailing
   slash from `resource` (spec: exact match). The only cost is operators
   who configured a resource with a slash and rely on the strip.
3. **W2-4 / D17 at the gate.** Byte-exact allowlists mean an admin who
   types `Dan@…` for a `dan@…` identity locks them out. The spec is
   explicit; a friendlier alternative is to normalize at *configuration
   time with a warning* and compare exactly at admission.

## Appendix — vector table

`id | invariant | title | expected | known findings`

| id | inv | title | expected | known |
|---|---|---|---|---|
| P-OK-01 | I11 | as-you login, fallback-issued, singular holder binding | accept |  |
| P-OK-02 | I3 | as-you login, primary-issued (status refs on the primary's list) | accept |  |
| P-OK-03 | I13 | delegated grant: grantee user+agent, grantor user, config cert covers the base identity | accept |  |
| P-OK-04 | I3 | cross-issuer delegation: primary-issued grantee, fallback-issued grantor | accept |  |
| P-OK-05 | I1 | array-form binding set with one holder entry | accept |  |
| P-OK-06 | I7 | requester entry matched by the assertion's req_origin stamp | accept |  |
| P-OK-07 | I11 | scope entry with the `mode` parameter; non-web audience with trailing slash; entries returned verbatim | accept | D7 |
| P-OK-08 | I11 | scope entry with a family parameter (`cap`); a relay carries it verbatim | accept | D7 |
| P-OK-09 | I13 | subaddressed grantor user+agent covered by a config cert for user (authorization-only widening) | accept |  |
| P-OK-10 | I6 | exact holder matcher equal to the access cert holder | accept |  |
| P-OK-11 | I5 | grantee domain differs only in case from the access identity (domain is case-insensitive) | accept |  |
| P-OK-12 | I5 | grantor domain differs only in case from the config cert identity (spec §5 rule) | accept | W6-1 |
| P-OK-13 | I6 | wildcard holder matcher | accept |  |
| P-SIG-01 | I2 | access cert signed by a key that is not the issuer's | reject: signature |  |
| P-SIG-02 | I2 | config cert signed by a key that is not the issuer's | reject: signature |  |
| P-SIG-03 | I2 | warrant not signed by the config cert's key | reject: signature |  |
| P-SIG-04 | I2 | assertion not signed by the access cert's key | reject: signature |  |
| P-SIG-05 | I2 | access cert payload altered after signing (identity swapped) | reject: signature |  |
| P-SIG-06 | I2 | warrant JOSE header alg:none (signature bytes still present) | reject: signature |  |
| P-SIG-07 | I2 | warrant with an empty signature segment | reject: signature |  |
| P-AUD-01 | I4 | assertion aud with a trailing slash | reject: audience |  |
| P-AUD-02 | I4 | assertion aud differs in case | reject: audience |  |
| P-AUD-03 | I4 | assertion aud with an explicit default port | reject: audience |  |
| P-AUD-04 | I4 | assertion aud with a different scheme | reject: audience |  |
| P-AUD-05 | I4 | assertion aud with a path | reject: audience |  |
| P-AUD-06 | I4 | assertion aud for a different origin | reject: audience |  |
| P-AUD-07 | I4 | warrant audience differs from the assertion's and the RP's | reject: audience |  |
| P-AUD-08 | I4 | warrant audience with a trailing slash | reject: audience |  |
| P-AUD-09 | I4 | warrant audience is an array (exactly one string required) | reject: audience |  |
| P-TIME-01 | I2 | access cert expired | reject: expired |  |
| P-TIME-02 | I2 | config cert expired | reject: expired |  |
| P-TIME-03 | I2 | warrant expired | reject: expired |  |
| P-TIME-04 | I2 | assertion expired | reject: expired |  |
| P-TIME-05 | I2 | access cert post-dated (iat far in the future) | reject: future_iat | D16 |
| P-TIME-06 | I2 | warrant post-dated (iat far in the future) | reject: future_iat | D16 |
| P-TIME-07 | I2 | config cert post-dated (iat far in the future) | reject: future_iat | D16 |
| P-TIME-08 | I2 | access cert iat > exp | reject: iat_after_exp | D16 |
| P-TIME-09 | I2 | warrant iat > exp | reject: iat_after_exp | D16 |
| P-TIME-10 | I2 | warrant without exp | reject: shape |  |
| P-TYP-01 | I1 | retired browserid-warrant-v1 (top-level holder, no status) | reject: typ | S3 |
| P-TYP-02 | I1 | retired browserid-warrant-v1 carrying a status ref | reject: typ | S3 |
| P-TYP-03 | I1 | warrant with an unknown typ | reject: typ |  |
| P-TYP-04 | I1 | access cert with an unknown typ | reject: typ |  |
| P-TYP-05 | I1 | config cert slot holds an access-cert typ | reject: typ |  |
| P-TYP-06 | I1 | config cert with purpose authentication (an auth cert is never presented) | reject: purpose |  |
| P-TYP-07 | I1 | config cert with an unknown purpose | reject: purpose |  |
| P-TYP-08 | I1 | config cert without a holder | reject: shape |  |
| P-TYP-09 | I1 | access cert with an empty holder | reject: shape |  |
| P-SHAPE-01 | I1 | three objects (config cert missing) | reject: shape |  |
| P-SHAPE-02 | I1 | five objects (config cert repeated) | reject: shape |  |
| P-SHAPE-03 | I1 | assertion and access cert swapped | reject: shape |  |
| P-SHAPE-04 | I1 | warrant and config cert swapped | reject: shape |  |
| P-SHAPE-05 | I1 | empty presentation | reject: shape |  |
| P-SHAPE-06 | I1 | warrant slot is not a JWS | reject: shape |  |
| P-BIND-01 | I6 | connection-bound record presented in a bundle | reject: connection_in_p |  |
| P-BIND-02 | I6 | holder plus connection entries: connection is unsatisfiable in P | reject: connection_in_p |  |
| P-BIND-03 | I6 | requester entry only, no holder entry (dead paper) | reject: missing_holder |  |
| P-BIND-04 | I1 | empty binding set | reject: binding |  |
| P-BIND-05 | I1 | warrant without a binding claim | reject: binding |  |
| P-BIND-06 | I8 | binding entry of an unimplemented kind | reject: binding |  |
| P-BIND-07 | I8 | holder entry plus an unimplemented kind (conjunctive: the unknown entry fails) | reject: binding |  |
| P-BIND-08 | I1 | holder entry without a matcher | reject: binding |  |
| P-BIND-09 | I6 | holder matcher for another namespace | reject: holder |  |
| P-BIND-10 | I6 | exact holder matcher naming a different holder | reject: holder |  |
| P-BIND-11 | I6 | matcher equal to the namespace without `.*` (no prefix slack) | reject: holder |  |
| P-BIND-12 | I6 | namespace matcher that is a string prefix of the holder's namespace | reject: holder |  |
| P-BIND-13 | I7 | requester entry with a mismatching req_origin stamp | reject: requester |  |
| P-BIND-14 | I7 | requester entry but the assertion carries no req_origin | reject: requester |  |
| P-BIND-15 | I7 | req_origin stamped but the record has no requester entry | reject: requester |  |
| P-BIND-16 | I7 | requester origin with a trailing slash is not a web origin | reject: binding |  |
| P-BIND-17 | I6 | delegated record with a multi-entry set (self-grant-only) | reject: binding |  |
| P-BIND-18 | I6 | two holder entries, one not covering the holder (conjunctive) | reject: holder |  |
| P-ID-01 | I6 | domain grantee matcher presented in a bundle | reject: matcher_in_p |  |
| P-ID-02 | I6 | wildcard grantee matcher presented in a bundle | reject: matcher_in_p |  |
| P-ID-03 | I5 | grantee differs from the access cert identity | reject: join |  |
| P-ID-04 | I5 | grantee local part differs in case from the access identity (local part is byte-exact) | reject: join |  |
| P-ID-05 | I5 | grantee is a subaddress of the access identity | reject: join |  |
| P-ID-06 | I5 | grantor not in the config cert's identities | reject: grantor |  |
| P-ID-07 | I5 | grantor local part differs in case from the config cert identity | reject: grantor |  |
| P-ID-08 | I13 | config cert for a subaddress does not cover the base grantor (never widens upward) | reject: grantor |  |
| P-ID-09 | I13 | config cert for a sibling subaddress does not cover the grantor | reject: grantor |  |
| P-ID-10 | I6 | grantor is a matcher (attribution is always exact) | reject: grantor |  |
| P-ID-11 | I5 | identity with two @ signs | reject: identity_malformed |  |
| P-ID-12 | I5 | identity with an empty local part | reject: identity_malformed |  |
| P-ID-13 | I5 | identity with an empty domain | reject: identity_malformed |  |
| P-ID-14 | I5 | identity with no @ | reject: identity_malformed |  |
| P-ID-15 | I5 | well-formed access identity, malformed warrant grantee | reject: identity_malformed |  |
| P-ID-16 | I5 | malformed warrant grantor | reject: identity_malformed |  |
| P-ID-17 | I5 | mixed-case local part end to end; the config cert names the lowercase identity | reject: grantor | D17 |
| P-ISS-01 | I3 | fallback-issued certs for a domain that has a DNSSEC primary | reject: issuer |  |
| P-ISS-02 | I3 | primary-issued access cert, fallback-issued config cert for the same primary domain | reject: issuer |  |
| P-ISS-03 | I3 | certs from an issuer outside the RP's accepted fallback set | reject: issuer |  |
| P-ISS-04 | I3 | a primary vouching for identities in a domain it is not authoritative for | reject: issuer |  |
| P-ISS-05 | I3 | cross-issuer: grantee's primary signs the grantor's config cert for another domain | reject: issuer |  |
| P-ISS-06 | I3 | access cert claims iss primary.example but is signed by the broker's key | reject: signature |  |
| P-ISS-07 | I3 | access cert without iss | reject: shape |  |
| P-STAT-01 | I9 | access cert status bit set | reject: revoked |  |
| P-STAT-02 | I9 | config cert status bit set (revoked intermediate) | reject: revoked |  |
| P-STAT-03 | I9 | warrant status bit set | reject: revoked |  |
| P-STAT-04 | I9 | access cert revoked on the primary's foreign list | reject: revoked |  |
| P-STAT-05 | I9 | v2 warrant without a status ref | reject: status |  |
| P-STAT-06 | I9 | access cert status.uri host differs from its iss (broker cert pointing at the primary's list) | reject: status_uri_host | W6-4 |
| P-STAT-07 | I9 | access cert status.uri on a non-public host | reject: status |  |
| P-STAT-08 | I9 | access cert status.uri on an unreachable host (cannot prove unrevoked) | reject: status |  |
| P-STAT-09 | I9 | status ref without an idx | reject: shape |  |
| P-CONS-01 | I8 | access cert carries a satisfied `aud` constraint; §4.7 says no reference verifier implements constraints, so any claim rejects | reject: constraints | S5 |
| P-CONS-02 | I8 | access cert `aud` constraint that does not permit the RP | reject: constraints |  |
| P-CONS-03 | I12 | warrant scopes wider than the config cert's `scopes` allowlist (widened scope in chain) | reject: constraints |  |
| P-CONS-04 | I8 | warrant validity exceeds the config cert's `max-ttl` | reject: constraints |  |
| P-CONS-05 | I8 | access cert with an unknown constraint key | reject: constraints |  |
| P-CONS-06 | I8 | config cert with an empty constraints object | reject: constraints | S5 |
| P-SCOPE-01 | I8 | scope entry with an unknown parameter | reject: scope |  |
| P-SCOPE-02 | I8 | scope entry object without a scope string | reject: scope |  |
| P-SCOPE-03 | I8 | `mode` with a value outside auto/prompt | reject: scope |  |
| P-SCOPE-04 | I1 | scopes is a string, not an array | reject: shape |  |
| P-SCOPE-05 | I8 | set-form record with an unrecognized top-level claim | reject: shape |  |
| A-OK-01 | I6 | holder-* record, login without a holder | accept |  |
| A-OK-02 | I6 | namespace matcher, login holder in the namespace | accept |  |
| A-OK-03 | I6 | domain grantee matcher covers a login at that domain (permission, not attribution) | accept |  |
| A-OK-04 | I5 | domain matcher covers a subaddressed login with a differently-cased domain | accept |  |
| A-OK-05 | I6 | wildcard grantee covers any authenticated email | accept |  |
| A-OK-06 | I6 | connection-bound self-grant validates (subject authenticated by the custody dance, not a login) | accept |  |
| A-OK-07 | I1 | array-form binding on an admission record | accept |  |
| A-OK-08 | I11 | parameterized scope entries on an admission record are returned verbatim | accept | D7 |
| A-OK-09 | I5 | login domain differs only in case from the grantee | accept |  |
| A-OK-10 | I6 | delegated admission record: agent login with a covered holder | accept |  |
| A-REJ-01 | I6 | requester entry is unsatisfiable in admission | reject: requester_in_a (match) |  |
| A-REJ-02 | I6 | connection-bound record does not match a login | reject: connection_login (match) |  |
| A-REJ-03 | I6 | exact holder matcher, login with a different holder | reject: holder (match) | D5 |
| A-REJ-04 | I6 | namespace matcher, login holder outside the namespace | reject: holder (match) | D5 |
| A-REJ-05 | I6 | non-* matcher against a holder-less login | reject: holder (match) | D5 |
| A-REJ-06 | I5 | domain matcher does not cover a subdomain login | reject: grantee (match) |  |
| A-REJ-07 | I5 | wildcard grantee never covers a malformed identity (a@b@c) | reject: identity_malformed (match) | D17 |
| A-REJ-08 | I5 | wildcard grantee never covers an identity with an empty local part | reject: identity_malformed (match) | D17 |
| A-REJ-09 | I5 | domain matcher never covers a malformed identity | reject: identity_malformed (match) | D17 |
| A-REJ-10 | I5 | login local part differs in case from the grantee | reject: grantee (match) | D17 |
| A-REJ-11 | I5 | login is a subaddress of the grantee | reject: grantee (match) |  |
| A-REJ-12 | I5 | login is a different identity | reject: grantee (match) |  |
| A-REJ-13 | I1 | retired v1 record held for admission | reject: typ | S3 |
| A-REJ-14 | I6 | connection-bound record that is not a self-grant | reject: binding |  |
| A-REJ-15 | I8 | connection entry with an unimplemented protocol | reject: binding |  |
| A-REJ-16 | I6 | connection entry with an empty id (instance must be pinned) | reject: binding |  |
| A-REJ-17 | I6 | connection entry without client_host | reject: binding |  |
| A-REJ-18 | I4 | record audience differs from the resource | reject: audience |  |
| A-REJ-19 | I4 | record audience with a trailing slash | reject: audience |  |
| A-REJ-20 | I2 | expired record | reject: expired |  |
| A-REJ-21 | I2 | post-dated record | reject: future_iat | D16 |
| A-REJ-22 | I9 | record status bit set | reject: revoked |  |
| A-REJ-23 | I9 | config cert under the record is revoked | reject: revoked |  |
| A-REJ-24 | I2 | record not signed by the config cert's key | reject: signature |  |
| A-REJ-25 | I2 | config cert under the record not signed by its issuer | reject: signature |  |
| A-REJ-26 | I12 | record scopes wider than the config cert's allowlist | reject: constraints |  |
| A-REJ-27 | I5 | record grantor not covered by the config cert | reject: grantor |  |
| A-REJ-28 | I3 | fallback-issued config cert for a domain with a primary | reject: issuer |  |
| A-REJ-29 | I9 | v2 record without a status ref | reject: status |  |
| A-REJ-30 | I8 | record scope entry with an unknown parameter | reject: scope |  |
| A-REJ-31 | I1 | four-object bundle handed to the record validator | reject: shape |  |
| A-REJ-32 | I5 | domain matcher with a differently-cased domain does not cover a subdomain login | reject: grantee (match) |  |
| A-REJ-33 | I5 | domain matcher does not cover a look-alike domain | reject: grantee (match) |  |
| T-OK-01 | I3 | minimal record | accept |  |
| T-OK-02 | I3 | record with host delegation | accept |  |
| T-OK-03 | I3 | extra whitespace around fields and separators | accept |  |
| T-OK-04 | I3 | unknown field is ignored (forward compatibility) | accept |  |
| T-OK-05 | I3 | fields in a different order | accept |  |
| T-REJ-01 | I3 | missing v | reject: malformed_txt |  |
| T-REJ-02 | I3 | unsupported version | reject: malformed_txt |  |
| T-REJ-03 | I3 | unsupported algorithm | reject: malformed_txt |  |
| T-REJ-04 | I3 | missing public-key | reject: malformed_txt |  |
| T-REJ-05 | I3 | empty public-key | reject: malformed_txt |  |
| T-REJ-06 | I3 | public-key too short (31 bytes) | reject: malformed_txt |  |
| T-REJ-07 | I3 | public-key too long (33 bytes) | reject: malformed_txt |  |
| T-REJ-08 | I3 | public-key in standard base64 alphabet with padding, not base64url | reject: malformed_txt |  |
| T-REJ-09 | I3 | public-key is not base64 at all | reject: malformed_txt |  |
| T-REJ-10 | I3 | empty record | reject: malformed_txt |  |
| T-REJ-11 | I3 | two public-key fields in one record (ambiguous root) | reject: malformed_txt |  |
| T-REJ-12 | I3 | fields separated by commas instead of semicolons | reject: malformed_txt |  |
| T-REJ-13 | I3 | field names in upper case | reject: malformed_txt |  |
