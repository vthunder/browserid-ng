<!-- This Source Code Form is subject to the terms of the Mozilla Public
   - License, v. 2.0. If a copy of the MPL was not distributed with this
   - file, You can obtain one at http://mozilla.org/MPL/2.0/. -->

# Security audit 2026-11 — WS5: broker HTTP surface, authz matrix

**Status:** workstream output, 2026-11-02. Epic `browserid-ng-ag1l`, bean
`browserid-ng-t25u`. Oracle: `docs/design/threat-model.md` I15–I28. Input:
WS1 candidates (`docs/security-audit-2026-11-ws1-spec-review.md` §1 and
appendix). Nothing in production code was changed.

**Method.** Full read of `browserid-broker/src/routes/*`, `registrar_glue.rs`
and `browserid-registrar/src/*` against the invariants, plus a delegated
read-only sweep of the July findings. Every verdict below is backed by a
test in `browserid-broker/tests/authz_matrix_test.rs`: passing tests are the
durable matrix; `#[ignore]` tests marked `AUDIT-2026-11 Dx: fails today`
encode confirmed findings and were each run once with `--include-ignored`
to check they fail for the stated reason. Two of them (D9, W5-3) reach the
network on the existing-account path and were confirmed by code reading
only; they stay ignored until the ordering is fixed.

Run: `cargo test -p browserid-broker --test authz_matrix_test` (10 pass,
11 ignored). Findings: `-- --include-ignored --skip lookup_checks --skip
record_device_cert`.

## 1. Verdicts on WS1 candidates

| # | Verdict | Severity | Where | Encoding test | Remediation sketch |
|---|---|---|---|---|---|
| **D2** consent `respond` never checks the config cert | **CONFIRMED** | **High** | `browserid-registrar/src/consent.rs:678-760` (`validate_grant_warrants`), `:551-581` (`respond_record`). Both paths check purpose, expiry, `authorizes_identity` and that the warrant verifies under the cert's own key — never the issuer signature, never the store (`get_device_cert_by_pubkey`), never the status bit. Contrast `api.rs:611-623` (`register_warrant`: `config_cert_not_recorded`). | `respond_refuses_a_config_cert_the_issuer_never_signed` (a cert signed by a random key is accepted and delivered to the filer), `respond_refuses_a_config_cert_not_recorded_on_the_account` | One shared `recorded_config_cert(state, user_id, jws)` used by `respond_core`, `respond_record` and `register_warrant`: parse → `verify(issuer key)` for the broker's own domain (or the presentation verifier for a primary) → `get_device_cert_by_pubkey` must be this account's and `is_active()`. Reason `config_cert_not_recorded`. |
| **D4** JIT request is unsigned | **CONFIRMED** | Medium | `consent.rs:1337-1470` (`warrant_request`): body carries `device_cert`, `identity`, `grants`; nothing is verified against the agent's private key. Anyone who has seen the public cert files requests in the agent's name (consent phishing with a real agent identity on the card). | `warrant_request_needs_a_signature_by_the_agent_key` | Require a `request_proof` JWS over the body hash signed by the device key (the registry-api `Proof` shape already exists in `session.rs`), `jti` single-use, `iat` window. Same for `/warrant/poll` (code is a bearer, fine) and `record_request` (audience proof already covers it). |
| **D8** no rate limit on `/api/v1` | **PARTIAL** | Medium | `browserid-registrar/src/lib.rs:205-237`: only body-size and `buffer_body`; no 429 anywhere on the v1 router. The approval code claim is **refuted as a takeover vector**: `approvals.rs:179-234` requires an *enrolled* session on the same account to type the code, so a 30-bit code is only guessable by someone already inside. What stands: unbounded `login_page` token spends, `stored_key` attempts, approval-open floods (`MAX_PENDING=5`, anyone can fill a victim's queue → `login_rejected` for the real device), and the account-id timing oracle on `/wsapi/registry_login`. | `api_v1_login_guessing_is_throttled` | Reuse `routes/rate_limit.rs` as a layer on the v1 router (per IP, lower limit on `/api/v1/login` and `/api/v1/approvals`); cap approval opens per IP; `client_ip` must trust only the proxy's own hop (see W5-6). |
| **D9** fetches before proof verification on `accounts`/`lookup` | **PARTIAL** | Low | `browserid-registrar/src/account.rs:86-108`: `verify_device_cert` (DNSSEC discovery + status fetch via `registrar_glue.rs:1057-1112`) runs before the possession proof `p.verify` and before the header-proof replay check (`header_by_carried`, after `carried_certs`). The cert *signature* genuinely needs the issuer key, so the fetch cannot precede it entirely; but the cheap local checks (possession proof, `jti` replay, `htu`, `bh`) can and should run first. | `lookup_checks_the_possession_proof_before_any_fetch` (ignored: network) | Reorder `carried_certs`: parse cert → parse + verify proof under `claims.public_key` → `check_claims` → replay → then `verify_device_cert`. Also the discovery client itself (W5-5). |
| **D10** possession proofs not replay-cached | **REFUTED** | — | `account.rs:100-104`: every carried proof must share the header proof's `jti`; `session.rs:replay_check` caches `proof|kid|jti`. A captured possession proof is unusable without a fresh header `jti`, which would then mismatch. | `proof_jti_replay_is_rejected` (passes) | None. |
| **D11** cross-account attach corrupts the row | **CONFIRMED** | Low | `browserid-broker/src/store/sqlite.rs:2836-2850`: `ON CONFLICT(pubkey) DO UPDATE` rewrites identities, holder, `login_key_id`… but not `user_id`. `account.rs:88-96` only refuses an *inactive* existing row, so an active key on account A attached from B leaves `user_id=A, holder=B's, identities=B's`. The memory store (`store/memory.rs:935-946`) moves the whole row to B instead — a different wrong answer, invisible to memory-store tests. Low because reaching the handler path needs the cert's private key (the attacker already proves the identity). | `sqlite_upsert_of_a_key_active_on_another_account_keeps_the_row_coherent` (SqliteStore) | In `carried_certs`, refuse when `existing.user_id != caller` (`cert_recorded_elsewhere`) unless the identity is being transferred, in which case `record` must move the row (`user_id = excluded.user_id`) in the same transaction. Make the two stores agree. |
| **D18** JIT lane details | **CONFIRMED** | Low | `consent.rs:1386-1388`: 1–10 grants (spec 8); no duplicate-audience check; primary-issued cert status never fetched (`:1380-1385` checks only the registrar's own list); `jti` for `/access/mint` is in-memory. | `warrant_request_caps_grants_at_eight_and_rejects_duplicate_audiences` | Cap at 8, `HashSet` on audiences, status check through the presentation verifier for foreign `iss`. |
| **Appendix** absent `return_origin` on `/device/issue` | **REFUTED** (holds, with a caveat) | — | `routes/device.rs:273-277` checks when supplied. The only caller that omits it is the broker's own dialog (`static/dialog.js:644`), same-origin and CSRF-bound; it stores the certs in the broker origin's own storage and never delivers to a `return_url`. The ceremony page (`static/common/js/fb-device-authorize.js:182`) always sends it. A foreign page cannot reach the handler at all (cookie `SameSite=Lax` + CSRF). So I15 holds for every delivery lane; the caveat is that the handler trusts the *page* to say whether certs will leave the origin. | `device_issue_checks_return_origin_at_the_endpoint` (passes: foreign 403, loopback 200, absent 200) | Optional hardening: make `return_origin` required and have the dialog send its own origin; then the handler never issues "blind". |
| **S11** code side | **CONFIRMED** (decided, low) | Low | `account.rs:266-274` `"this key is a login key on another account"` vs success for a fresh key; `approvals.rs:74-85` `login_rejected` only when the account exists. Leaks only yes/no about an opaque key or account id. Decision in kgjr: answer identically. | Documented in `anon_is_refused_on_every_api_v1_session_route` (opening an approval for an unknown account answers a code). | Generic `login_rejected` for the foreign-key case; the approvals cap returns the unknown-account shape. |
| **S1** code side | **CONFIRMED** (design, decided) | High (spec) | `routes/registry_login.rs:34-78` mints a login token with no `return_url`/origin binding; delivery is `static/common/js/registry-login.js`'s choice. Conforms to reg §4.2 as written; the fix is the accepted S1 spec change. | — (behaviour change pending spec) | Bind the token to the opener's login-key pubkey passed in the fragment, or apply fb §3.1's accepted origins in the handler. |

## 2. New findings (W5-n)

| # | Finding | Severity | Where | Test | Remediation |
|---|---|---|---|---|---|
| **W5-1** | Fast poll answers 400 `slow_down`, not 429 (I18). | Low | `consent.rs:1868-1872` → `bad(...)` → `RegistrarError::ValidationError` → 400 (`error.rs:84`); `PollTooFast` (429) exists at `error.rs:107` and is unused here. | `poll_too_fast_is_429` | Return `PollTooFast`. |
| **W5-2** | Hosted-primary password endpoints have no throttle and a bcrypt timing oracle. `/idp/login` and `/idp/password` run bcrypt only when the tenant and roster entry exist (no dummy hash) and never 429. July M6 covered only the broker login. | Medium | `routes/hosted_idp.rs:186-216`, `:263-303` | `idp_login_is_throttled` | Reuse the `login_attempts` window keyed `idp|ip`; verify against a dummy hash on the miss path. |
| **W5-3** | `/wsapi/record_device_cert` is an unauthenticated existence oracle: identity lookup precedes the cert signature check (`"no account holds this identity"` vs a later issuer/signature error). July M7 class. | Low | `routes/primary.rs:265-320` | `record_device_cert_does_not_reveal_account_existence` (ignored: network) | Verify signature first; answer one generic refusal. |
| **W5-4** | Password change does not retire registry login keys. `update_password` ends cookie sessions (H2 fix) but every enrolled login key and its bearer sessions survive, so a wallet an attacker enrolled keeps the account after the user "changes the password". The reset lane does revoke them (`signin_code.rs:308-314`). Spec is silent on whether a *change* (not reset) retires keys. **Decision needed.** | Medium | `routes/auth.rs:265-280` vs `signin_code.rs:280-317` | `password_change_ends_registry_sessions_enrolled_by_password` | Either revoke keys with `enrolled_by=password` on change, or show the device list after a change and require re-proof. |
| **W5-5** | Discovery fetch lacks the H1 guard. `browserid-verifier/src/discovery.rs:15-27,193-202` uses a blocking client with default redirect-following, no post-resolution IP check and an uncapped `response.json()`; the host comes from the DNS `host=` value. Reachable unauthenticated via `/verify`, `/wsapi/address_info`, `record_device_cert`, `handle_claim`. `/status/proxy` (`routes/status.rs:46-76`) is unauthenticated, outside the rate-limited router, fires a GET at any public `https://host:port` before any issuer check, and returns the guard's error text verbatim (an internal-DNS oracle: "resolves to non-global address 10.x"). | Medium | as cited; hand to WS6 for the core/verifier side | — (needs a fetch stub; WS6) | Route discovery through the same guarded client as status fetches; put `/status/proxy` behind `rate_limit::verification_api` and return a generic error; constrain `uri` to a `.well-known/browserid-status` path on the issuer host. |
| **W5-6** | Every IP throttle trusts the first `X-Forwarded-For` hop (`routes/auth.rs:47-61`). If the fronting proxy appends rather than overwrites, a client-supplied header rotates the bucket. Infra question (the dokku nginx config is in `sandmill-infra`). | Medium (conditional) | `auth.rs:47-61`, used by `rate_limit.rs`, `registry_login.rs`, `code_guard` callers | — | Take the *last* hop (the proxy's) or read `X-Real-IP` set by the proxy; verify the nginx directive. |
| **W5-7** | `/agent-provision/complete` signs a 90-day auth cert without `authorize_mint`: `owns_verified_email` only, no session-level check. With `identity_mode:"self"` a Lightweight or unadmitted session gets a broker-signed cert for the account's own E2/E3 address. Not one of the documented exemptions in `mint.rs:25-31`. | Medium | `browserid-registrar/src/agent_provision.rs:885-892`, `:1391` | — (flow is long; see `mint_chokepoint_test` for the harness) | Route through `authorize_mint` with the session level, or add it to the documented exemptions with a stated rationale. |
| **W5-8** | Status-list decode inflates before capping. `StatusList::decode` runs `read_to_end` on zlib data and checks the 4 MiB cap afterwards; a ~4 MiB compressed bomb (the body cap) inflates to gigabytes before rejection, reachable unauthenticated through `/status/proxy`. Core issue; **handed to WS6**. | High (DoS) | `browserid-core/src/status.rs:96-108` | — (WS6) | `take(4 MiB + 1)` on the decoder before `read_to_end`. |
| **W5-9** | Anonymous-by-design v1 routes worth a second look: `POST /api/v1/approvals` (anyone opens approvals for any account id; floods to `MAX_PENDING`), `POST /api/v1/approvals/:id/cancel` (anyone holding the id cancels). Ids are 256-bit, so this is the opener's own channel; recorded, not a finding. | Info | `approvals.rs:57-104`, `:155-167` | pinned in `anon_is_refused_on_every_api_v1_session_route` | Rate-limit opens per IP (D8). |

## 3. Matrix results (what holds today)

Passing tests, each a durable guard:

- **Anonymous** is refused on 23 cookie-session routes (401; a few 422 where
  the extractor runs first — rows list the accepted set) and on all 28
  `/api/v1` session or proof routes (401 `invalid_session`/`invalid_proof`).
- **Bearer without the login-key Proof**, or a Proof by another key, is not
  a session (I22).
- **CSRF** is required on every state-changing cookie route tested
  (`update_password`, `stage_email`, `remove_email`, `/device/issue`,
  `tenant/create`, `tenant/check`): 403 with a wrong token.
- **Another account holder** gets 404 on a user's consent request
  (respond, claim), approval (approve, deny), login key (revoke, rename),
  cert (revoke), holder (rename, forget) and identity (detach), and
  his inbox does not list it (I25). On the cookie surface he cannot issue
  for or remove a foreign identity.
- **Tenant admin**: roster and every mutation are owner/admin-only
  (anon 401, stranger 403, owner 200).
- **Return origin** is checked at `/device/issue` (foreign 403, loopback
  200) — I15.
- **Proof replay** rejected (I22) — D10 refuted.
- **Policy PUT** is owner-only and cannot loosen below the floor (I25).

Cookie attributes (delegated read, verified by the existing
`cookie_session_security_test`): `browserid_session` HttpOnly, Secure
(except localhost), `SameSite=Lax`, `/`, 30 d; `browserid_fedcm` HttpOnly,
Secure, `SameSite=None`, `/fedcm`; `idp_session` HttpOnly, Lax, `/idp`, 2 h,
stateless and signed with the root key; `browserid_oidc_flow` HttpOnly, Lax,
`/oidc`, 600 s. CSP inline hashes are guarded by the existing test in
`routes/mod.rs`. Routes using a cookie session without a CSRF token:
`/wsapi/auth_with_presentation` (JSON content-type + Lax), `/idp/device_cert`
(cookie only), `/wsapi/session_admit` (Bearer + Proof instead),
`/fedcm/assertion` (`Sec-Fetch-Dest`), `/fedcm/reset` (only removes consent).

## 4. July 2026 re-verification

| ID | July | Now | Evidence |
|---|---|---|---|
| C1 | Critical, brute-forceable codes | **FIXED (residual)** | `code_guard.rs:21,43-88` burns after 5 tries; staging 10/IP/h and one code per address per 300 s (`signin_code.rs:90-109`). Residual: codes still 6 digits (`crypto.rs:19`), read-compare-increment is not atomic, completion has no IP cap, and the IP cap inherits W5-6. |
| H1 | SSRF on status fetch | **FIXED for status; OPEN for discovery and `/status/proxy`** | Guard at `browserid-verifier/src/verify.rs:172-333`. Gaps are W5-5. |
| H2 | Reset evicts nothing | **FIXED for reset; PARTIAL for change** | `signin_code.rs:280-317` evicts sessions and revokes login keys. `update_password` evicts cookie sessions only (W5-4). |
| M1 | `/auth/device_cert` password bypass | **FIXED** | Route deleted (`routes/mod.rs:267-271` comment); every `DeviceCert::create*` in the broker passes `authorize_mint` (`mint_chokepoint_test` source guard) — except the registrar's `agent-provision/complete` (W5-7). |
| M2 | SDK `allowAgent` no-op | not in WS5 scope (WS4) | — |
| M3 | TTL ceiling | **FIXED (residual)** | `core/status.rs:197-200` caps at 300 s; no `iat` lower bound (WS1 S6/D16 covers it). |
| M4 | unbounded cache / body | **FIXED (new residual W5-8)** | 1024 entries, 4 MiB body cap, negative cache (`verify.rs:204-246`). Decode-before-cap is W5-8. |
| M5 | malformed signed record demotes | **FIXED** | `browserid-dnssec/src/dns.rs:295-361`: filtered, multi-record and malformed-but-signed → Bogus. |
| M6 | login throttle | **FIXED for broker login; OPEN for hosted IdP** | `auth.rs:84-107`, `registry_login.rs:50-68`; `/idp/login`, `/idp/password` unthrottled (W5-2). |
| M7 | enumeration | **FIXED for the five named endpoints; residual oracles** | `address_info` state only for the owning session, `stage_signin_code` identical, `authenticate_user` dummy bcrypt; the four `*_status`/`stage_*` lanes deleted (`retired_endpoints_test`). Residual: W5-3, W5-2 timing, S11. |
| M8 | key file mode | **FIXED (residual)** | `config.rs:127-141` writes then chmods 0600 (brief 0644 window; existing files not re-checked). |
| M9 | coarse SBO grant | **FIXED** | `sbo-signer.js:99-116`: per-record grants bound to origin, identity, audience, scope, holder, fail-closed status. |

## 5. Resolution of bean `oawf`

`browserid-ng-oawf` (todo) says ytjn, dw35 and 7ww7 are "re-confirmed open in
code". **That is stale; all three are fixed and the beans' `completed`
status is correct:**

- **ytjn (M6):** `routes/auth.rs:37-107` — 10 failures / 5 min / IP → 429;
  test `authentication_test::login_is_rate_limited_after_repeated_failures`.
- **dw35 (M7 phase 1):** `address_info` returns `state` only to the owning
  session (`email.rs:796-826`); password failures are indistinguishable
  (`auth.rs:114-135`); phase 2 (`8gqm`) deleted the four remaining oracle
  endpoints (`retired_endpoints_test`).
- **7ww7 (M1):** the `/auth/device_cert` cookie lane no longer exists; the
  ceremony page issues through `/device/issue` behind `authorize_mint`.

What oawf should carry forward instead, re-pointed at this report: D8
(no 429 on `/api/v1`), W5-2 (hosted IdP throttle), W5-3 and S11 (residual
oracles), W5-6 (`X-Forwarded-For` hop). oawf is updated accordingly.

## 6. Decisions for Dan

1. **W5-4** — should a password *change* (not reset) retire login keys
   enrolled by password and end their sessions? Today it does not.
2. **D8 scope** — a blanket per-IP limiter on `/api/v1` (simple, 300/min
   like the verification API) versus targeted limits on `login`,
   `approvals` and `accounts`.
3. **W5-7** — is `agent-provision/complete` an intended `authorize_mint`
   exemption? If so, document it in `mint.rs`; if not, it needs the
   session level.
4. **W5-6** — confirm the proxy's `X-Forwarded-For` behaviour in
   `sandmill-infra` before trusting any IP throttle in production.

## 7. Routing

- D2, D4, D8, D11, D18, W5-1..4, W5-7 → remediation beans under the epic.
- W5-5, W5-8 → WS6 (verifier/core fetch and decode).
- S1, S11 → spec change already accepted (kgjr); code follows.
