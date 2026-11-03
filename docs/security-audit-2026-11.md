<!-- This Source Code Form is subject to the terms of the Mozilla Public
   - License, v. 2.0. If a copy of the MPL was not distributed with this
   - file, You can obtain one at http://mozilla.org/MPL/2.0/. -->

# browserid-ng Security Audit — 2026-11-02

**Scope:** full-pass adversarial audit of browserid-ng, not a differential
against July: the protocol core (`browserid-core`), the hosted verifier,
DNSSEC resolver and RP library, the broker (browserid.me, treated as **live
production**) and registrar, the hosted-primary tenancy, OIDC bridge and
FedCM mint, the JS/Python MCP authorization layers (`sdk/mcp-auth`,
`sdk/gate`, `sdk/python-mcp-auth`), the Electron wallet and the hosted
wallet-service, `sdk/agent`, and the supply chain, build, deploy, secrets
and logging posture. Nine workstreams (WS1–WS9), tracking epic
`browserid-ng-ag1l`. Threat model: `docs/design/threat-model.md`
(adversaries A1–A10, invariants I1–I28).

**Method.** WS1 read the three specs against every implementation and
produced candidates D1–D20 and spec findings S1–S13. Each candidate was then
re-verified by a skeptic in the owning workstream (WS4 layers, WS5 broker
HTTP, WS6 core/verifier) whose default was *refute unless a test proves it*;
every confirmed finding is encoded as an `#[ignore]`d or skipped test tagged
`AUDIT-2026-11 <id>` (`grep -rn AUDIT-2026-11`), and **un-ignoring that test
is the acceptance criterion for the fix**. WS2 built 177 conformance vectors
run by six verifiers with expected-fail tables that double as the open
ledger; WS3 added proptest suites and seven cargo-fuzz targets; WS7 ran every
scanner and read the infra repo; WS8 built working PoCs against a **local
broker only** for every High and for the WS1 ordering list. Severities below
are the **post-verification** severities. All 29 product decisions
(`docs/security-audit-2026-11-decisions.md`, Q1–Q29) were settled by Dan on
2026-11-02, so every remediation bean is `todo`.

Per-workstream reports: `security-audit-2026-11-ws1-spec-review.md`,
`-ws2-conformance.md`, `-ws3-fuzz-proptest.md`, `-ws4-layers.md`,
`-ws5-http-surface.md`, `-ws6-core-verifier.md`, `-ws7-supply-chain.md`,
`-ws8-pocs.md`.

## Executive summary

The cryptographic core is still sound: Ed25519 only with pinned `alg`, key
and signature lengths; fail-closed DNSSEC; signatures before claims;
parameterized SQL; no credential has ever been committed in 1020 commits;
every image ships without secrets; 20M+ fuzz executions over every wire
parser with zero crashes. The July 2026 fixes held where they were applied.
The material findings are **drift and gaps around that core**, in five
themes:

1. **Identity rule drift across layers.** The subaddress rule is purpose-blind
   at the mint (D1); the JS verifiers fold the local part or accept malformed
   identities (D17/W2-3/W2-4); the grantor branch of core compares the domain
   byte-exact (W6-1); the SDKs rewrite the audience (W2-1). One rule, stated
   in core §5, has three implementations.
2. **Missing chokepoint checks.** Consent `respond` never verifies the
   config cert (D2, High, PoC); the hosted IdP copies a caller-chosen holder
   (D3); JIT requests are unsigned (D4); agent provisioning bypasses
   `authorize_mint` (W5-7); the registry login token is minted with no
   return-origin binding (S1/W5-10, High); the hosted wallet admits an agent
   as the human (W4-22, July M2 recurring in a layer never audited before).
3. **Unchecked time arithmetic.** No object has a lower bound on `iat`;
   `exp - iat` and `iat + ttl` overflow (D16/S6, W3-1, W3-2), which defeats
   `max-ttl` and the July M3 status-list ceiling. One clock rule closes all
   of them (Q28).
4. **Resource exhaustion.** The status-list decoder inflates before it caps
   (W6-3/W5-8, High, PoC: 1 MB in, 845 MiB RSS), reachable unauthenticated
   through `/status/proxy`; nothing on `/api/v1` answers 429 (D8, ~20k req/s
   measured); the hosted IdP password endpoints are unthrottled (W5-2); the
   `.well-known` discovery fetch is the July H1 class on a second fetcher
   (W6-5/W5-5).
5. **Supply chain and operations.** No scanning gate existed (W7-1, closed
   during the audit); 16 Rust advisories and the MCP SDK DoS fixes are a
   `cargo update` / `npm audit fix` away (R7-1..3); actions pinned by mutable
   tag (W7-2); containers run as root (W7-8); the registrar access log prints
   single-use pickup codes (W7-10) and consent logs reconstruct the RP–user
   association (W7-11).

**Counts (post-verification, confirmed findings only).**

| Severity | Count | Ids |
|---|---|---|
| Critical | 0 | — |
| High | 3 | D2, W6-3/W5-8, S1/W5-10 |
| Medium | 29 | D1, D3, D4, D5/W2-2, D6, D7, D8, D14, D15, D16/S6, S3, W6-4, W6-5/W5-5, W5-2, W5-4, W5-7, W5-14, W4-22, W4-30, W4-31, W3-3/W5-11, W7-1 (closed), W7-2, W7-8, W7-10, W7-11, W7-12, R7-1, R7-2 |
| Low | 44 | D9, D11, D12 (dd), D13, D17/W2-3/W2-4, D18, D19, D20, W2-1, W2-5, W2-6, W6-1, W6-2, W3-1, W3-2, W3-4, W5-1, W5-3, W5-6, W5-12/S11, W5-13, W5-15, W4-10, W4-11, W4-12, W4-13, W4-14, W4-20, W4-21, W4-23, W4-32, W4-33, W4-34, W4-40, W4-41, W4-42, W7-5, W7-6, W7-7, W7-9, R7-3, PostHog salt (Q13), C1 residual, M8 residual |
| Info | 5 | W4-44, W5-9, W7-3, W7-4, Q29 |

Downgrades and refutations on verification (details in §4): **D1 High →
Medium** (holder-pinned warrants unaffected); **D8 takeover refuted**
(approval codes need an enrolled session), limiter gap stands; **D10
refuted**; **D12 refuted** as a security finding; **S5 refuted** as a code
gap (core already enforces constraints; the spec was wrong); **W5-6 Medium →
Low** (dokku's nginx overwrites `X-Forwarded-For` today; the broker change is
still wanted); the `/device/issue` absent-`return_origin` lead refuted;
**W6-3 Info → High** once WS5 showed unauthenticated reachability.

## 1. Severity ledger

Columns: final severity; where; the acceptance test(s) or vector ids (un-ignore,
un-skip, or delete from `EXPECTED_FAIL`); PoC if WS8 reproduced it; the
decision reference and its state; the remediation bean. Test file
abbreviations: `authz` = `browserid-broker/tests/authz_matrix_test.rs`;
`ws4-broker` = `browserid-broker/tests/audit_2026_11_ws4.rs`; `core-ws6` =
`browserid-core/tests/audit_2026_11_ws6.rs`; `core-ws3` =
`browserid-core/tests/audit_2026_11_ws3_proptest.rs`; `ver-ws6` =
`browserid-verifier/tests/audit_2026_11_ws6.rs`; `runners` = the six WS2
`EXPECTED_FAIL` tables (core, hosted, sdk/js, python, mcp-auth, gate);
`mcp-ws4` / `gate-ws4` / `ws-ws4` / `wallet-ws4` / `agent-ws4` / `py-ws4` =
the per-layer `audit_2026_11_ws4` test files.

### High

| # | Finding | Where | Acceptance | PoC | Decision | Bean |
|---|---|---|---|---|---|---|
| D2 | Consent `respond` never checks the config cert: no issuer signature, not checked as recorded on the account, no status check; a self-minted "config cert" signs approvals delivered to the filer | `browserid-registrar/src/consent.rs:678-760`, `:551-581` | `authz`: `respond_refuses_a_config_cert_the_issuer_never_signed`, `respond_refuses_a_config_cert_not_recorded_on_the_account` | WS8 §1.2, `browserid-broker/tests/audit_2026_11_ws8_d2.rs` (200 `{}`, forged grant delivered) | none needed | `browserid-ng-0fy3` |
| W6-3 (= W5-8) | Status-list decoder inflates the whole zlib stream before the 4 MiB cap; unauthenticated via `/status/proxy` and every foreign status fetch. W3-4: encoder `from_revoked`/`set` allocate on an unbounded index (publisher-side) | `browserid-core/src/status.rs:96-108`, `:66-81`; `browserid-broker/src/routes/status.rs:46` | `browserid-core/tests/audit_2026_11_ws6_bomb.rs`: `w6_3_oversized_status_list_is_rejected_without_inflating_it`; `audit_2026_11_ws3_status_alloc.rs`: `decode_allocation_is_bounded_for_any_input` | WS8 §3, `audit_2026_11_ws8_w6_3.rs` (1 MB → 768 MiB, RSS 9 → 845 MiB) | none needed | `browserid-ng-rn46` |
| S1 / W5-10 | Registry login page delivers the login token to any same-origin `return_url`; the handler mints it with no origin binding and the token *is* the account (enrols a login key) | `browserid-broker/src/routes/registry_login.rs:34-78`; `static/common/js/registry-login.js` | `authz`: `registry_login_token_minting_checks_the_return_origin` | WS8 §4 walkthrough (design finding) | S1 accepted 2026-11-01; reg §4.2 amended | `browserid-ng-rw5q` |

### Medium

| # | Finding | Where | Acceptance | PoC | Decision | Bean |
|---|---|---|---|---|---|---|
| D1 | Auth cert for `user@d` mints access certs for `user+tag@d`: the subaddress rule in `identity_matches` is purpose-blind; breaks attribution, the per-agent revocation axis, widens browser-key compromise via `*`-holder warrants. **High → Medium** (holder-pinned warrants unaffected) | `browserid-core/src/device.rs:96-111`; `routes/device.rs:455`, `routes/hosted_idp.rs:536`; `sdk/agent/src/device.mjs:447-455` | `core-ws6`: `d1_authentication_cert_for_base_identity_does_not_authorize_subaddress`; `core-ws3`: `auth_cert_identity_is_exact`; `agent-ws4`: "D1 (client mirror)"; flip `device::tests::base_identity_authorizes_subaddresses` | WS8 §1.1, `audit_2026_11_ws8_d1.rs` | Q1 settled: spec §4.6 stands, code moves; (b) PoC first, done | `browserid-ng-v8s0` |
| D3 | Hosted IdP passes the page's `holder` through verbatim; a tenant user stamps another device's holder and satisfies holder-pinned matchers | `routes/hosted_idp.rs:396-403`; `idp-device-authorize.js:23` | `ws4-broker`: `d3_tenant_device_cert_does_not_take_a_caller_chosen_holder` | WS8 §1.3 (holder `zzzzzzzzzz.attacker` issued) | none needed | `browserid-ng-2lgy` |
| D4 (+ D18 Low) | JIT `warrant_request` is unsigned: anyone with an agent's public cert files consent requests in its name. D18: 1–10 grants (spec 8), duplicate audiences, foreign cert status unchecked, in-memory mint `jti` | `browserid-registrar/src/consent.rs:1337-1470`, `:1386-1388`; `routes/device.rs:29-43` | `authz`: `warrant_request_needs_a_signature_by_the_agent_key`, `warrant_request_caps_grants_at_eight_and_rejects_duplicate_audiences` | — | none needed | `browserid-ng-jvfr` |
| D5 (= W2-2) | mcp-auth and gate admission match policy rows by grantee only; a row narrowed to one holder, or carrying a `requester` entry, admits every subject. Core's `matches_login` rejects all five vectors | `sdk/mcp-auth/index.mjs:1040,1051`; `sdk/gate/src/gateway.mjs:121`, `mount.mjs:82` | `mcp-ws4` D5 ×2; `gate-ws4` D5; runners A-REJ-01…05 (mcp-auth, gate) | WS8 §1.5 (un-skipped tests) | Q15 settled: (a) refuse non-`{holder,"*"}` policy rows | `browserid-ng-cjh3` |
| D6 (+ W4-12 Low) | Gate fails open: single-server mode never validates policy rows (revoked/expired admit); gateway `isRowLive` admits on a *thrown* fetch; an HTTP 503 is read as definitive `invalid_grant` and `grantsDiff` deletes signed rows (WS1 wording corrected by WS4) | `sdk/gate/src/mount.mjs:76-85`, `gateway.mjs:216,221`; `sdk/mcp-auth/index.mjs:318` | `gate-ws4` D6 ×3; `mcp-ws4` W4-12; gate runner A-REJ-13, -20…-31 | — | Q14 settled: (a) fail closed; never delete on 5xx | `browserid-ng-0og2` |
| D7 | Hosted `/verify` and `/validate-record` flatten scope entries to strings; every `pay:`/`contract:` attenuation is void downstream (every SDK inherits) | `browserid-verifier/src/verify.rs:122,487,602,689`; `browserid-rp` `VerifiedIdentity.scopes` | `ver-ws6`: `d7_verify_response_carries_scope_parameters`, `d7_validate_record_response_carries_scope_parameters`; runners P-OK-07, P-OK-08, A-OK-08 | — | S7 settled (relay rule) | `browserid-ng-oa6s` |
| D8 (+ W5-9 Info) | No 429 anywhere on `/api/v1`. **Takeover refuted** (approvals need an enrolled session); what stands is enumeration, approval-queue floods to `MAX_PENDING`, proof-window pressure and cost | `browserid-registrar/src/lib.rs:205-237`; `approvals.rs:30-39,57-104` | `authz`: `api_v1_login_guessing_is_throttled` | WS8 §2: 600 × 401 / 0 × 429; ~20,000 req/s | Q5 settled: (a) blanket limiter, generous defaults; Q7 (XFF) both | `browserid-ng-4r2j` (blocked by `gajq`) |
| D14 | DoT connect failure, timeout, empty answer, REFUSED all map to "insecure" and demote a primary to the fallback path; `fallback_to_broker` treats its own Insecure as hard error, so the asymmetry is accidental | `browserid-dnssec/src/dns.rs:139-184`, `:545-548`; `lib.rs:268` | `browserid-dnssec/tests/audit_2026_11_ws6.rs`: `d14_transport_failure_is_not_an_insecure_answer`, `d14_resolve_idp_key_does_not_report_not_primary_on_transport_failure`; flip `test_refused_is_insecure_not_bogus` | — | Q2 settled: (b) retry once (~2 s), then hard reject | `browserid-ng-rq5b` |
| D15 | `browserid-rp` pinned-table status path: follows redirects, no private-IP guard, no URI-host == `iss`, ten-year `ttl` honoured (July H1/M3 class; the `verify_dnssec` path is clean) | `browserid-rp/src/lib.rs:272-290`, `:723`, `:779` | `browserid-rp/tests/audit_2026_11_ws6.rs`: `d15_pinned_status_refresh_refuses_redirects_and_private_hosts`, `d15_pinned_status_cache_caps_the_issuer_declared_ttl` | — | Q3 settled: (b) deprecate `refresh`/`refresh_status` | `browserid-ng-ll22` |
| D16 / S6 (+ W3-1, W3-2 Low) | No lower bound on `iat` anywhere: future `iat` defeats `max-ttl` and keeps a status list fresh past the July M3 cap; `exp - iat` and `iat + ttl + grace` overflow (debug panic, release wrap) | `device.rs:61,314-317`; `admission.rs`; `status.rs:190,198` | `core-ws6`: `s6_*` ×3, `d16_future_iat_defeats_max_ttl`, `d16_status_list_with_future_iat_is_not_fresh`; `core-ws3`: `max_ttl_check_never_overflows`, `warrant_iat_is_bounded_by_exp_and_now`, `status_list_freshness_never_overflows`; runners P-TIME-05…09, A-REJ-21 | — | Q28 settled: (a) one clock rule, one core helper | `browserid-ng-gdo0` |
| S3 | `browserid-warrant-v1` still accepted (and emitted); a refless v1 record is unrevocable at the registry (I10) | `device.rs:1304` (accept arm), `:1231` (`Warrant::create`); signers `dialog.js:796`, `wallet/src/login.js:29`, `mediator.js:53` | `core-ws6`: `s3_v1_warrant_rejects_in_presentation`, `s3_v1_record_rejects_in_admission`; runners P-TYP-01/02, A-REJ-13 | — | S3 settled: drop v1 outright (signers first) | `browserid-ng-3zpa` |
| W6-4 | A cert's `status.uri` host is never compared to its `iss`; a primary's certs pointing at the broker's own list verify via the own-list shortcut | `browserid-verifier/src/verify.rs:754-771`, `:575-594` | `ver-ws6`: `w6_4_cert_status_uri_host_must_equal_cert_iss`; runners P-STAT-06 | — | §6.3 amended (I9); none needed | `browserid-ng-lnf7` |
| W6-5 (= W5-5) | `.well-known` discovery fetch has no H1 guard (redirects, private IPs, uncapped body), target is the attacker-chosen DNS `host=`, runs before any signature; `/status/proxy` is unauthenticated, unlimited, and echoes the guard's internal-DNS error text | `browserid-verifier/src/discovery.rs:15-27,193-202`, `verify.rs:25-47`; `routes/status.rs:46-76` | `ver-ws6`: `w6_5_discovery_fetch_refuses_redirects_and_private_hosts`; add a `/status/proxy` test | — | none needed | `browserid-ng-2tyx` |
| W5-2 | `/idp/login`, `/idp/password` never 429 and run bcrypt only when the roster entry exists (timing oracle); July M6 covered only the broker login | `routes/hosted_idp.rs:186-216`, `:263-303` | `authz`: `idp_login_is_throttled` | — | none needed | `browserid-ng-i4kj` (blocked by `gajq`) |
| W5-4 | Password *change* evicts cookie sessions only; every registry login key enrolled by the old password, and its bearer sessions, survive (July H2 class; reset lane is correct) | `routes/auth.rs:265-280` vs `signin_code.rs:280-317` | `authz`: `password_change_ends_registry_sessions_enrolled_by_password` | — | Q4 settled: (a) retire `enrolled_by=password` keys | `browserid-ng-a7mx` |
| W5-7 | `/agent-provision/complete` signs 90-day auth certs without `authorize_mint` (not a documented exemption); a Lightweight/unadmitted session gets a cert for the account's own address in `self` mode | `browserid-registrar/src/agent_provision.rs:885-892`, `:1391` | none encoded; write one on the `mint_chokepoint_test` harness (bean lists the four lanes) | — | Q6 settled: (b) route through `authorize_mint`; E2 parents redeem a bridge grant | `browserid-ng-o1zy` |
| W5-14 | Restoring a suspended identity another account now holds needs only fresh certs: no config cert, no `confirm_takeover` (S10 code side) | `browserid-registrar/src/account.rs:704-709` | none encoded (two accounts + suspension); add per reg §5.2.4 | — | S10 accepted | `browserid-ng-u6f2` (blocked by `0fy3`) |
| W4-22 | Hosted wallet `/oauth/login` keys the tenant on `email`, never compares `grantee`, never checks `scopes`: an agent with any warrant for the wallet origin takes over the custodied key (July M2 recurrence) | `wallet-service/src/server.mjs:33-35,116-120` | `ws-ws4`: "W4-22: a delegated presentation (grantee != email) does not open the human's tenant"; flip the no-`login`-scope pin | WS8 §1.4 (200 for delegated and scope-less presentations) | Q16 settled: (a) human-only | `browserid-ng-2x2w` |
| W4-30 | Any account opens a `PendingDns` tenant for any domain; pending rows never expire; the real owner gets 409 forever | `routes/hosted_idp.rs:782-880`; `store/sqlite.rs:3129-3144` | `ws4-broker`: `w4_30_pending_tenant_squat_does_not_block_the_domain_owner` | — | Q17 settled: (a) expire + DNSSEC-validated replacement | `browserid-ng-dobu` |
| W4-31 (+ W4-32 Low) | Stateless `/idp` cookie ignores an admin password reset (`must_change` read from the cookie, not the roster) for up to 2 h while issuing 90-day certs; W4-32: the cookie is a raw root-key signature over an untagged payload (July L3 shape). WS4 rated Low–Medium; ledger takes Medium (July H2 class) | `routes/hosted_idp.rs:113-158`, `:355-362`, `:1190-1196` | `ws4-broker`: `w4_31_admin_password_reset_stops_an_open_idp_session_from_issuing`, `w4_32_idp_session_cookie_payload_carries_a_type_tag` | — | none needed | `browserid-ng-cn3f` |
| W3-3 (= W5-11) | Registrar does not enforce the one scope grammar: empty, uppercase, whitespace, control/bidi and non-ASCII scopes are signed into warrants and rendered on the card (WS5 rated Low, WS3 Medium; ledger takes Medium, the card's stripping is the only mitigation) | `browserid-registrar/src/consent.rs:868-889` | `browserid-registrar/src/consent/audit_2026_11_ws3_proptest.rs`: `grant_shape_accepts_exactly_the_scope_grammar`; `authz`: `filed_scopes_must_match_the_one_scope_grammar` | — | Q27 settled: (a) grammar check in core | `browserid-ng-lu7i` |
| W7-1 | No dependency or secret scanning gate existed | `.github/workflows/` | **Closed in WS7**: `supply-chain.yml` (cargo-audit, npm audit, pip-audit, gitleaks; push/PR/weekly), `make audit`, per-ecosystem ignore files. Red on main until R7-1..3 land | — | — | (done; follow-up `j0rh`) |
| W7-2 | Every third-party action pinned by mutable tag, including `publish.yml` with `id-token: write` and the deploy workflows with the dokku key | all nine workflows | grep for `@v` in workflows returns only comments | — | Q11 settled: (a) SHA pins + Dependabot (actions) | `browserid-ng-s6ya` |
| W7-8 (+ M8 residual Low) | Broker (root key + db) and all Node/Python images run as uid 0; no `USER`, no healthcheck, no read-only fs. M8 residual: µs 0644 window on create, mode never re-asserted on load | `Dockerfile` ×5; `browserid-broker/src/config.rs:116-144` | image inspection; mode assertion test | — | Q9 settled: (a) non-root, broker first, infra chown | `browserid-ng-4c8h` (blocked by infra `u3q7`) |
| W7-10 | Registrar access log prints raw paths: the filer's single-use pickup code and approval ids (threat model §3 item 6) | `browserid-registrar/src/session.rs:60` | capturing-subscriber test: code absent | — | Q10 settled: (a) opaque ids, matched route | `browserid-ng-fy1k` |
| W7-11 | Consent/device/account logs print delegator email + audience and agent identity: the RP–user association the spec protects (item 7) | `consent.rs:1241,498,1483`; `routes/device.rs:380` | grep review of every `tracing!` | — | Q10 settled: (a) | `browserid-ng-fy1k` |
| W7-12 | Without `SMTP_HOST` the broker silently logs every verification and reset code with the address | `browserid-broker/src/email/console.rs:24-42` | startup refusal test | — | none needed | `browserid-ng-t7pa` |
| R7-1 | 16 RUSTSEC advisories (rustls-webpki distrusted intermediates and name-constraint bypass reachable via DoT/SMTP; h2 DATA flood; `time` stack exhaustion via cookie/jsonwebtoken), 14 close with `cargo update`; hickory-proto 0118/0119 unfixed, ignored to 2027-02-01 | `Cargo.lock` | `make audit` exit 0 | — | Q8 settled: (a) land now | `browserid-ng-j0rh` |
| R7-2 | `@modelcontextprotocol/sdk` ≤1.31 unbounded body/batch DoS on every StreamableHTTP service; zod < 4.6.6 on tool arguments; 7 packages, all in-range | 7 lockfiles | `make audit`; redeploy 3 services, publish gate + wallet | — | Q8 settled | `browserid-ng-j0rh` |

### Low

| # | Finding | Where | Acceptance | Decision | Bean |
|---|---|---|---|---|---|
| D9 (partial) | `accounts`/`lookup` run DNSSEC discovery + status fetch per carried cert before the possession proof and replay check (cheap local checks can go first) | `browserid-registrar/src/account.rs:86-108` | `authz`: `lookup_checks_the_possession_proof_before_any_fetch` (network-ignored until reordered) | none | `browserid-ng-cd6r` |
| D11 | Attaching a key active on another account rewrites holder/identities but keeps `user_id` (sqlite); the memory store moves the row instead | `store/sqlite.rs:2836-2850`; `account.rs:88-96` | `authz`: `sqlite_upsert_of_a_key_active_on_another_account_keeps_the_row_coherent` | none | `browserid-ng-uphh` |
| D12 (defence in depth) | Wallet signs under a payload-decoded stored grant with no signature check (refuted as a finding: the store writer already holds `configKey`) | `wallet/src/request.js:166-190` | `wallet-ws4`: "D12 (defence in depth)" | Q23 settled: add | `browserid-ng-7ith` |
| D13 | wallet-service drops status refs; 30-day refresh with no re-check; no revoke/logout/disconnect (custodied agent key behind the session) | `wallet-service/src/server.mjs:116-120`, `oauth.mjs:213-227` | `ws-ws4`: "D13: a tenant can revoke a connection" | Q21 settled: (a) | `browserid-ng-3k53` |
| D17 (= W2-3, W2-4) | mcp-auth splits on the last `@` and `granteeCovers("*")` admits any string with `@`; gate lowercases the whole email in admin and grantor checks. Refuted in wallet-service, sdk/js, hosted_idp, python | `sdk/mcp-auth/index.mjs:71,87`; `sdk/gate/src/gateway.mjs:687,779`, `mount.mjs:61,318` | `mcp-ws4` D17 ×2; `gate-ws4` D17 ×2; runners A-REJ-07…10 (mcp-auth), `P-OK-nn/case` + A-REJ-07…10 policy mode (gate) | Q26 settled: (a) byte-exact | `browserid-ng-4y7y` |
| D18 | JIT lane details (see D4) | `consent.rs:1386-1388` | `authz`: `warrant_request_caps_grants_at_eight_and_rejects_duplicate_audiences` | none | `browserid-ng-jvfr` |
| D19 | FedCM throwaway config cert + warrant carry no status refs (5-min bound, pinned) | `routes/fedcm.rs:296-312,325` | under (a) delete `d19_fedcm_config_cert_and_warrant_carry_status_refs`, keep the 5-min pin | Q20 settled: (a) documented exception (spec edit) | `browserid-ng-vpdi` |
| D20 | `binding.id` not indexed 1:1; two validated records naming one id both mint | `sdk/mcp-auth/index.mjs:364,1296` | `mcp-ws4`: "D20" | none | `browserid-ng-g4gs` |
| W2-1 | python-mcp-auth, mcp-auth, gate strip the trailing slash from `resource` and verify a different audience (fail-closed; `sbo+raw://…:506/` never verifies through them) | `__init__.py:135`; `index.mjs:159`; `mount.mjs:55` | runners P-OK-07 (python, mcp-auth, gate) | Q25 settled: (a) stop normalizing | `browserid-ng-0vk8` |
| W2-5 | `@browserid-ng/verify` omits `holder` and `grantee_issuer` (§6.1 step 9) | `sdk/js/index.mjs:116-125` | add the comparison to P-OK-01 in `sdk/js/conformance.test.mjs` | none | `browserid-ng-94k7` |
| W2-6 | `DnsRecord::parse` keeps the last of duplicated fields; two `public-key` values resolve to the second | `browserid-core/src/dns.rs:30-45` | core runner T-REJ-11 | none (B5) | `browserid-ng-zsi1` |
| W6-1 | Exact and subaddress branches of `identity_matches` compare the grantor's domain byte-exact (fail-closed; July L1 class) | `device.rs:73-74,107` | `core-ws6`: `w6_1_grantor_match_uses_spec_domain_comparison`; runners P-OK-12 | none (§5) | `browserid-ng-j84h` (blocked by `v8s0`) |
| W6-2 | `Assertion::verify` never reads the JOSE header (not exploitable; the one typed-signing inconsistency left) | `browserid-core/src/assertion.rs:570-582` | add an `alg != EdDSA` rejection test | none | `browserid-ng-hgxv` |
| W3-1 | `exp - iat` unchecked in `Constraints::check` (panic in debug, wrap passes any `max-ttl`) | `device.rs:315` | `core-ws3`: `max_ttl_check_never_overflows` | Q28 | `browserid-ng-gdo0` |
| W3-2 | `iat + ttl + grace` unchecked; negative `ttl` passes the cap; wrapped sum reads fresh forever | `status.rs:190,198` | `core-ws3`: `status_list_freshness_never_overflows` | Q28 | `browserid-ng-gdo0` |
| W3-4 | Encoder allocates on an unbounded index (publisher-side) | `status.rs:66-81` | with W6-3 | none | `browserid-ng-rn46` |
| W5-1 | Fast filer poll answers 400 `slow_down`, not 429 (I18) | `consent.rs:1868-1872` | `authz`: `poll_too_fast_is_429` | none | `browserid-ng-66jv` |
| W5-3 | `/wsapi/record_device_cert` is an unauthenticated existence oracle (lookup before signature; July M7 class) | `routes/primary.rs:265-320` | `authz`: `record_device_cert_does_not_reveal_account_existence` | none | `browserid-ng-imn6` |
| W5-6 (+ W4-23) | Throttles trust the first `X-Forwarded-For` hop. **Medium → Low**: WS7 confirmed dokku's nginx overwrites the header with `$remote_addr`; nothing declares or audits that | `routes/auth.rs:47-61`; `wallet-service/src/server.mjs:76-77` | `ws-ws4`: "W4-23"; add a `client_ip` unit test | Q7 settled: both (broker last hop + infra declaration) | `browserid-ng-gajq`; infra `browserid-ng-zthh` |
| W5-12 / S11 | Approvals cap answers `403 login_rejected` only for existing accounts; foreign-login-key refusal is distinguishable | `approvals.rs:74-85`; `account.rs:266-274` | `authz`: `approvals_at_the_cap_answer_like_an_unknown_account` | S11 accepted | `browserid-ng-imn6` |
| W5-13 | `claim` answers 404 for `agent`-kind requests (reg §5.3) | `consent.rs:337-343` | `authz`: `claim_accepts_a_pending_agent_request` | spec | `browserid-ng-1dy0` |
| W5-15 | Membership reason still `holder_mismatch` (reg §7.1: `holders_differ`) | `account.rs:124`; `consent.rs:771` | add assertion | spec | `browserid-ng-1dy0` |
| W4-10 | Policy conjunction runs only in connection mode; Lane A mints with `permittedBy: null` (no live exposure) | `sdk/mcp-auth/index.mjs` `createAuthCodeLane` | `mcp-ws4`: "W4-10" | none | `browserid-ng-1x50` |
| W4-11 | Refresh grant accepts a request with no `client_id` | `index.mjs:1323` | `mcp-ws4`: "W4-11" | none | `browserid-ng-1x50` |
| W4-12 | `validateRecord` reads any non-2xx as definitive `invalid_grant` (shapes D6) | `index.mjs:318` | `mcp-ws4`: "W4-12" | Q14 | `browserid-ng-0og2` |
| W4-13 | Lane A bearer lives 1 h regardless of warrant expiry; `/verify` returns no expiry | `index.mjs:266`; python `handle_token` | `py-ws4`: `test_bearer_never_outlives_the_presented_warrant` | Q23 settled: fold into D7 | `browserid-ng-fqnh` (blocked by `oa6s`) |
| W4-14 | Object scope entry crashes the Python AS (`TypeError` → 500) | `__init__.py:235` | `py-ws4`: `test_parameterised_scope_entries_fail_closed`; python runner P-OK-08/entries | S7 | `browserid-ng-la0k` |
| W4-20 | Native prompt renders bare scope names: auto vs prompt mode and parameters invisible | `wallet/src/request.js:116-120`, `main.js` | `wallet-ws4`: "W4-20" | none | `browserid-ng-25lq` |
| W4-21 | Loopback page origins may pair with the wallet in release builds | `wallet/src/server.js:17,108-111` | `wallet-ws4`: "W4-21" | Q22 settled: (a) `WALLET_TEST` gate | `browserid-ng-hynd` |
| W4-32 | `idp_session` cookie: raw root-key signature, untagged payload | `hosted_idp.rs:118-127,137-158` | `ws4-broker`: `w4_32_…` | none | `browserid-ng-cn3f` |
| W4-33 | OIDC flow records the starting session but attaches to the callback session | `oidc/mod.rs:180-233`; `routes/oidc.rs:338-393` | `ws4-broker`: `w4_33_oidc_attaches_to_the_session_that_began_the_claim` | none | `browserid-ng-1676` |
| W4-34 | Bridge grant redeemable by any Full session of the account within 10 min | `state.rs:253-284`; `routes/device.rs:112` | `ws4-broker`: `w4_34_bridge_grant_is_redeemable_only_by_the_proving_session` | Q18 settled: (a) per session | `browserid-ng-whxv` |
| W4-40 | Spec gap: assertions carry no `iat`, so amended §6.1 cannot be satisfied | spec §5; `assertion.rs:14-28`; `sdk/agent/src/protocol.mjs:45-48` | flip the `agent-ws4` pin; add assertion P-TIME vectors | Q19 settled: (a) add `iat` | `browserid-ng-b18d` (blocked by `gdo0`) |
| W4-41 | Agent mints at whatever endpoint the registrar's poll body names, no `iss` cross-check, no https | `sdk/agent/src/device.mjs:143-150,297,384-385` | `agent-ws4`: "W4-41" ×2 | none | `browserid-ng-lh3i` |
| W4-42 | Key seeds on public properties (`console.log(agent)` prints the seed) | `device.mjs:291`; `crypto.mjs:33,43` | `agent-ws4`: "W4-42" ×2 | none | `browserid-ng-lh3i` |
| W7-5 | `publish.yml` runs `npm install -g npm@latest` unpinned in the OIDC-publishing job | `publish.yml:37` | grep | none | `browserid-ng-9jle` |
| W7-6 | `npm install` (not `npm ci`) in five SDK dirs; three without a committed lock | `sdk-tests.yml:26-38`, `test.yml` | grep | none | `browserid-ng-9jle` |
| W7-7 | Base images by floating tag (reproducibility only) | all Dockerfiles | optional | none | `browserid-ng-9jle` |
| W7-9 (infra) | One age recipient for every secret on both hosts and the backups; no rotation note | `sandmill-infra/secrets/*.env.age` | — | Q12 settled: (a) second recipient | `browserid-ng-afn5` |
| R7-3 | `fastmcp==3.4.6` (GHSA-7xgj-8392-5q4r, not reachable) | `python-mcp-demo/requirements.txt` | `make audit` | Q8 | `browserid-ng-j0rh` |
| PostHog (Q13) | `distinct_id = sha256(email)[:12]` unsalted; membership confirmable with PostHog access | `browserid-broker/src/analytics.rs:114` | unit test | Q13 settled: (a) salt | `browserid-ng-jxhb` |
| C1 residual | Codes still 6 digits; attempt burn not atomic; no per-IP cap on completion | `code_guard.rs:43-88`; `crypto.rs:19` | add parallel-guess + IP-cap tests | none | `browserid-ng-eetq` |
| M8 residual | `OpenOptions::mode(0o600)` and assert mode on load | `config.rs:116-144` | with W7-8 | none | `browserid-ng-4c8h` |

### Info

| # | Finding | Bean |
|---|---|---|
| W4-44 | Legacy `Agent`/`Credential` lane in `@browserid-ng/agent` is dead but exported (posts a shape the registrar rejects) | `browserid-ng-g5qz` (delete at next major, Q23) |
| W5-9 | `POST /api/v1/approvals` and `/cancel` are anonymous by design (256-bit ids); opens flood under D8 | with `browserid-ng-4r2j` |
| W7-3 | One dokku-user `DOKKU_SSH_KEY` serves six deploy workflows (release any app, never host root); no `pull_request_target`, no event interpolation in `run:` | none |
| W7-4 | `type=gha` cache cannot be seeded from a fork | none |
| Q29 | Fuzzing cadence: weekly `make fuzz-smoke` launchd run | `browserid-ng-yk2z` |

### Spec-only items (settled 2026-11-01, bean `browserid-ng-kgjr`)

S2 (one identity rule in core §5), S4 (no registry allowlist; safe-fetch and
list-signer rules in §6.3), S5 (§4.7 names core; bean `browserid-ng-hp8k`
flips P-CONS-01/06), S7 (generic parameter mechanism; pay parameters move to
browserid-pay), S8 (fb §4 rewrite), S9 (one scope grammar), S12 (issuance
without second-device approval: accepted risk, threat model §6), S13
(editorial). Code sides of S1, S3, S6, S10, S11 are in the ledger above.

## 2. Refuted leads

Recorded so the reasoning is on record; no action.

- **D8 approval-code takeover.** `approvals.rs:179-234` requires an
  *enrolled* session on the same account to type the code, so a 30-bit code
  is only guessable by someone already inside. WS8 measured the limiter gap
  instead (~20k req/s, zero 429): the finding stands as D8 Medium, missing
  limiter, not takeover.
- **D10 possession proofs not replay-cached.** Every carried proof must
  share the header proof's `jti` (`account.rs:100-104`), and
  `session.rs:replay_check` caches `proof|kid|jti`; a captured proof is
  unusable without a fresh header `jti`, which then mismatches. Pinned by
  `proof_jti_replay_is_rejected`.
- **D12 wallet signs under unverified stored grants.** The store is
  safeStorage-encrypted and the record was signed by the wallet's own config
  key: anyone who can write it already holds `configKey`. What the lane
  enforces is pinned (origin, holder, audience, grantee, scope, expiry,
  fail-closed status). Kept as Low defence in depth (Q23).
- **S5 constraints "not implemented".** Core rejects unknown constraint keys
  on either cert in presentation and admission and enforces `aud`,
  `scopes`, `max-ttl` (`s5_*` ×4 pass; vectors P-CONS-02…05). The spec text
  was wrong, not the code (Q24: amend §4.7).
- **Absent `return_origin` on `/device/issue`.** The only caller that omits
  it is the broker's own same-origin, CSRF-bound dialog, which stores certs in
  the broker origin and never delivers to a `return_url`; a foreign page
  cannot reach the handler (`SameSite=Lax` + CSRF). I15 holds for every
  delivery lane (`device_issue_checks_return_origin_at_the_endpoint`).
- **D17 outside mcp-auth/gate.** wallet-service keys tenants byte-exact (its
  one `toLowerCase` can only drop a held warrant); sdk/js passes identities
  through verbatim; `hosted_idp.rs` lowercases the local part before the
  roster lookup, which is issuer-side canonicalisation; python-mcp-auth has
  no identity comparison.
- **W6-2 assertion header.** Ed25519 still has to verify under the access
  key; a wrong `alg` buys nothing. Kept as Low consistency.
- **W5-6 exploitability today.** Dokku 0.38.31's shipped nginx template emits
  `proxy_set_header X-Forwarded-For $remote_addr` (overwrite, not append),
  and the firewall blocks the container port, so the first hop is the
  connection address on the identity host. Downgraded to Low; the broker
  change stays because the guarantee lives in an undeclared default.
- **July M8 (key file mode) holds;** **secrets-in-git clean** (gitleaks over
  1020 commits: 12 hits, all test material, allowlisted with reasons);
  **nothing secret in any image**; **FedCM `Sec-Fetch-Dest` gate**,
  **holder-namespace isolation at the mint**, **PKCE/redirect/rotation in both
  MCP AS implementations**, **wallet IPC/messaging boundaries**, **hosted
  tenancy key isolation**, **OIDC bridge pinning** all re-verified and pinned
  (WS4 §3, WS5 §3, WS6 §3, WS2 §4).

## 3. Cross-verifier disagreement (WS2)

177 vectors, six runners (Rust core, hosted `/verify` + `/validate-record`,
`@browserid-ng/verify`, python-mcp-auth, mcp-auth, gate), all green in CI with
expected-fail tables. Genuine disagreement, where two verifiers in the repo
return different verdicts today, exists in exactly four places:

| Vectors | Disagreement | Finding |
|---|---|---|
| P-OK-07, P-OK-08, A-OK-08 | core preserves scope parameters; everything behind the HTTP boundary flattens | D7 |
| P-OK-07 | hosted and sdk/js verify the slash-terminated audience; the three resource-shaped SDKs send an altered audience | W2-1 |
| A-REJ-01…05 | core's `matches_login` rejects binding entries; mcp-auth (and gate through it) admits | D5 / W2-2 |
| A-REJ-07…10, `P-OK-nn/case` | core rejects malformed and case-variant subjects; mcp-auth and gate admit | D17 / W2-3 / W2-4 |

Everything else is the whole stack agreeing with itself and disagreeing with
the spec (S3, D16/S6, S5, W6-1, W6-4), which the core fix resolves for all six
at once. 109 reject vectors and every plain accept vector agree everywhere.

## 4. July 2026 re-verification

| July | Status now | Evidence / residual |
|---|---|---|
| C1 brute-forceable codes | **Held** | `code_guard` burns after 5; staging 10/IP/h. Residual: 6-digit codes, non-atomic burn, no IP cap on completion (bean `eetq`) |
| H1 SSRF on status fetch | **Held for status; recurred on two other fetchers** | `verify.rs:172-333` guard pinned (`i9_*`). Open: discovery fetch W6-5, `browserid-rp` pinned path D15, `/status/proxy` error oracle |
| H2 reset evicts nothing | **Held for reset; partial for change** | `signin_code.rs:280-317` evicts sessions + login keys; `update_password` cookie sessions only (W5-4) |
| M1 mailbox-only cert mint | **Held** | route deleted; every broker `DeviceCert::create*` passes `authorize_mint` (`mint_chokepoint_test`) except the registrar's `agent-provision/complete` (W5-7) |
| M2 SDK `allowAgent` no-op | **Held in sdk/js; recurred in wallet-service** | sdk/js throws on `allowAgent` and exposes `grantee`; the hosted wallet never does the comparison (W4-22) |
| M3 uncapped foreign `ttl` | **Held on the hosted path** | `is_fresh_capped` 300 s. Open: `browserid-rp::StatusCache` (D15); bypassable everywhere by future `iat` (D16) and overflow (W3-2) |
| M4 unbounded cache / body | **Held for transport** | 1024 entries, 4 MiB `read_capped`, 30 s negative cache. The cap is on compressed bytes: inflate unbounded (W6-3) |
| M5 malformed-but-signed record | **Held** | `dns.rs:295-361` filtered/multi-record/malformed → Bogus. Sibling demotion on *transport* failure is D14; within-record duplicate field is W2-6 |
| M6 login throttle | **Held for the broker login; not applied to the hosted IdP** | `auth.rs:84-107`; `/idp/login`, `/idp/password` unthrottled (W5-2) |
| M7 enumeration | **Held for the five endpoints** | `address_info` owner-only, uniform password failures, four lanes deleted. Residual oracles: W5-3, W5-2 timing, S11/W5-12 |
| M8 key file mode | **Held** | writes then chmod 0600; µs window and no re-assert on load (with W7-8) |
| M9 coarse SBO grant | **Held; not repeated in the native wallet** | per-record grants bound to origin, identity, audience, scope, holder, fail-closed status. Residual: prompt wording W4-20 |
| L1 parser differential | **Held for grantee/glob; open in two places** | core exact/subaddress branches (W6-1); mcp-auth/gate (D17) |
| L3 `fb_email` untagged root-key signature | **Held (`fb_email` gone); same shape recurred** | `idp_session` cookie (W4-32) |
| L4, L5, L6, L7, L8, L9, L12 | **Held** | pinned by existing tests; L6 unchanged by design on `Verifier::verify` |
| L10 cleartext seeds on disk | **Unchanged by design** | 0600 everywhere; in-memory counterpart W4-42 |
| L11 rustls 0.21 EOL | **Held (0.23 now); new advisories** | 16 RUSTSEC items, 14 fixed by `cargo update` (R7-1) |
| `oawf` (deferred July items) | **Stale claim corrected** | ytjn/dw35/7ww7 are fixed; oawf now carries D8, W5-2, W5-3, S11, W5-6, all with beans here |

**Recurrence pattern.** Three July fixes recurred in a layer or path the
July audit did not cover: H1 (discovery fetch, RP pinned path), M2 (hosted
wallet), L3 (`idp_session`). The July pass fixed call sites; this pass
encodes the rule as a test per layer so the next recurrence fails CI.

## 5. Remediation order

Mediums first, grouped so one change closes several tests. Highs are
first in each group they belong to. Beans are parented to
`browserid-ng-ag1l`; `blocked-by` relations are set where a fix depends on
another.

1. **Chokepoint fixes, broker and registrar (Highs first).**
   D2 `0fy3` (shared `recorded_config_cert` helper) → W5-14 `u6f2` (uses it);
   S1/W5-10 `rw5q`; D3 `2lgy`; D4+D18 `jvfr`; W5-7 `o1zy`; W5-4 `a7mx`;
   W4-31/W4-32 `cn3f`; W4-30 `dobu`.
2. **Resource exhaustion.** W6-3/W5-8/W3-4 `rn46` (High); W6-5/W5-5 `2tyx`
   (discovery guard + `/status/proxy`); W5-6/W4-23 `gajq` (client IP from
   the proxy hop) → D8 `4r2j` and W5-2 `i4kj` (limiters, blocked by `gajq`);
   infra `zthh` (declare and audit `x-forwarded-for-value`).
3. **Clock rule (Q28).** `gdo0` closes D16/S6, W3-1, W3-2 across core and
   all six runners; W4-40 `b18d` (assertion `iat`) follows it; W6-2 `hgxv`
   lands with the assertion change.
4. **Identity rule.** D1 `v8s0` (core split; PoC done) → W6-1 `j84h` (same
   function); D17/W2-3/W2-4 `4y7y` (one `parseIdentity` in mcp-auth and
   gate); W2-1 `0vk8` (stop normalizing the audience); W3-3/W5-11 `lu7i`
   (scope grammar in core; Q27).
5. **Verifier conformance.** D7 `oa6s` (scope entries verbatim) → W4-13
   `fqnh`; W4-14 `la0k`; W6-4 `lnf7`; D14 `rq5b`; D15 `ll22`; S3 `3zpa`
   (signers to v2 first, then core); W2-5 `94k7`; W2-6 `zsi1`; S5 spec
   `hp8k`.
6. **MCP and wallet layers.** D5/W2-2 `cjh3`; D6/W4-12 `0og2`; W4-22 `2x2w`;
   D13 `3k53`; D20 `g4gs`; W4-10/W4-11 `1x50`; W4-20 `25lq`; W4-21 `hynd`;
   W4-34 `whxv`; W4-33 `1676`; W4-41/W4-42 `lh3i`; D12 `7ith`; W4-44 `g5qz`;
   D19 `vpdi` (spec sentence).
7. **Supply chain and operations.** R7-1..3 `j0rh` (turns the new gate
   green); W7-2 `s6ya`; W7-12 `t7pa`; W7-10/W7-11 `fy1k`; W7-8 `4c8h`
   (blocked by infra chown `u3q7`); W7-5/6/7 `9jle`; W7-9 infra `afn5`;
   PostHog salt `jxhb`; fuzz cadence `yk2z`.
8. **Lows in the broker.** D9 `cd6r`; D11 `uphh`; W5-1 `66jv`;
   W5-3/W5-12/S11 `imn6`; W5-13/W5-15 `1dy0`; C1 residual `eetq`.

Before deploying anything in groups 1, 4 or 5 that touches `dialog.js`, the
wallet or the hosted-IdP pages, run the Playwright e2e locally against a warm
broker (CI does not run e2e). Verify production after every deploy.

## 7. Remediation status (2026-11-03)

69 of 75 beans under the epic are completed on branch `audit-2026-11`,
landed as five worktree merges (core 1f974ad, verifiers 5e76307, SDKs
f98cc05, registrar 509e46c, broker routes 2133bea) plus supply chain
e5fff75 and assertion `iat` / fuzz cadence b9e4224. Every `AUDIT-2026-11`
acceptance test and WS2 vector for a completed bean is un-ignored and
passing; the supply-chain gate is green with zero advisories.

Still open:

| Bean | Why |
|---|---|
| 3zpa S3 drop v1 warrants | Six signers still emit v1 (dialog.js, wallet login/mediator, FedCM, core `Warrant::create`); the wallet's registry-login warrant is deliberately refless and v2 requires `status`. Needs a decision: spec exception for issuer-registry login warrants, or pre-allocated refs. Then signers → v2, deploy, expire, delete the arm. |
| 4c8h W7-8 non-root containers | Blocked on infra chown (u3q7). |
| u3q7, afn5, zthh | sandmill-infra tasks (chown, second age recipient, declare `x-forwarded-for-value`). |
| ubk3 | hosted `/verify` `expires_at`; sdk/agent D1 mirror. |

Discovered during remediation (fixed, bean 0246): hosted-tenant agents
minted through the D1 wide mint; `/idp/device_cert` now issues sub-identity
auth certs. Deploy notes gathered from the merges: run Playwright e2e
locally before deploying (dialog.js, registry-login/session, idp-device-
authorize, authorize.html changed); existing `/idp` cookies stop
validating; hosted IdP and agent SDK deploy together and the github-mcp
demo agent is re-provisioned; publish agent 1.0.0 / mcp-auth 0.6.0 /
verify 0.4.0 / gate 0.11.0 before regenerating SDK lockfiles from the
registry; MCP resource configs must have no trailing slash; set
`POSTHOG_ID_SALT` and keep `TRUSTED_PROXIES=1` in the broker env;
wallet-service and hosted wallet redeploy.
