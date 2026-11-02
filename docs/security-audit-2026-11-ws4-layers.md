<!-- This Source Code Form is subject to the terms of the Mozilla Public
   - License, v. 2.0. If a copy of the MPL was not distributed with this
   - file, You can obtain one at http://mozilla.org/MPL/2.0/. -->

# Security audit 2026-11 — WS4: never-audited layers (MCP, wallet, agent SDK, hosted IdP, OIDC, admission)

**Status:** skeptic pass complete, 2026-11-02. Epic `browserid-ng-ag1l`, bean
`browserid-ng-n6nn`. Scope: `sdk/mcp-auth`, `sdk/gate`,
`sdk/python-mcp-auth`; the Electron wallet (`wallet/`), its extension, and
`wallet-service`; `sdk/agent` plus the mingo CLI custody (read-only
reference); broker hosted-primary tenancy (`routes/hosted_idp.rs`,
`tenant_keys.rs`), the OIDC bridge (`oidc/`, `routes/oidc.rs`,
`routes/handle_claim.rs`), session admission and signing grants, and the
FedCM mint (D19). Broker HTTP routes in general and the Rust verification
core are WS5 / WS6 and are not repeated here. Oracle:
`docs/design/threat-model.md`; specs `browserid-ng-protocol.md` §4–§8,
`fallback-idp-api-v1.md` §3, §7, `registry-api-v1.md`; the 2026-11-01
decisions (`security-audit-2026-11-decisions.md`), in particular S2 (one
identity rule: domain folded, local byte-exact), S3 (v1 retired), S7
(parameter mechanism; `mode` wallet-enforced, pay parameters
audience-enforced).

**Method.** Four parallel reviewer passes, one per layer, each followed by a
skeptic pass that tried to refute every candidate by reading more code or
writing a test. Every verdict below is backed by a test that runs today.
Tests encoding behaviour that FAILS today are skipped / `#[ignore]`d with an
`AUDIT-2026-11 <id>: fails today` comment and are the acceptance test for the
fix; every skipped test was confirmed to fail when un-skipped. Everything
else passes and pins what the audit re-verified. No production code was
changed, no new dependencies were added, nothing was run against production
hosts.

| Harness | Test file | Pass | Skipped (fail today) |
|---|---|---|---|
| browserid-broker (Rust) | `browserid-broker/tests/audit_2026_11_ws4.rs` | 13 | 7 |
| sdk/mcp-auth (`node --test`) | `sdk/mcp-auth/test/audit_2026_11_ws4.test.mjs` | 12 | 8 |
| sdk/gate (`node --test`) | `sdk/gate/test/audit_2026_11_ws4.test.mjs` | 11 | 6 |
| sdk/python-mcp-auth (unittest / pytest) | `sdk/python-mcp-auth/tests/test_audit_2026_11_ws4.py` | 7 | 2 |
| wallet (Electron, node-importable modules) | `wallet/test/audit_2026_11_ws4.test.mjs` (`node --test wallet/test/…`, not in `npm test`) | 6 | 2 (+2 skipped only while port 8873 is held by a running wallet) |
| wallet-service (`node --test`) | `wallet-service/test/audit_2026_11_ws4.test.mjs` | 7 | 3 |
| sdk/agent (`node --test`) | `sdk/agent/audit_2026_11_ws4.test.mjs` | 5 | 5 |

Finding ids are allocated per layer: W4-1x MCP, W4-2x wallet, W4-3x broker,
W4-4x agent SDK. Gaps in the sequence are deliberate.

## 1. Verdicts on the WS1 candidates

| ID | Verdict | Severity | Where | Test |
|---|---|---|---|---|
| D3 | **CONFIRMED** | Medium | `browserid-broker/src/routes/hosted_idp.rs:396-403` (`req.holder` copied verbatim; only a format check); contrast `routes/device.rs:300-313` which enforces the account's `browsers` namespace | `d3_tenant_device_cert_does_not_take_a_caller_chosen_holder` (ignored); pin `d3_pin_tenant_device_cert_self_assigns_a_fresh_holder_when_absent` |
| D5 | **CONFIRMED** | Medium | `sdk/mcp-auth/index.mjs:1040,1051` (`conjoinPolicy` filters by `granteeCovers` only, `pv.binding` never read); `sdk/gate/src/gateway.mjs:121`, `mount.mjs:82` (same, and the stored row keeps no binding) | mcp-auth `D5: a policy row narrowed to one holder…`, `D5: … requester entry…`; gate `D5: a policy row narrowed to another holder…` (all skipped) |
| D6 | **CONFIRMED, two halves; WS1 wording corrected** | Medium | (a) `sdk/gate/src/mount.mjs:76-85` single-server `entitlementFor`: no `/validate-record`, no status, no `exp`. (b) `gateway.mjs:216,221` `isRowLive` returns `cached?.ok ?? true` when the validator **throws** (connection refused, DNS); an HTTP 503 does NOT reach that branch because `validateRecord` maps 5xx to `invalid_grant` (W4-12), so an HTTP 503 fails closed | gate `D6: single-server — … REVOKED…`, `… EXPIRED …`, `D6: gateway signed mode — an UNREACHABLE validator must fail closed` (skipped); pins for refuse-on-revoked and refuse-on-HTTP-503; mcp-auth pins that `conjoinPolicy` / `ensureUnrevoked` fail closed on 503 |
| D12 | **REFUTED as a security finding** (Low defence-in-depth residue) | Low | `wallet/src/request.js:166-190` (`coveringRecord`) | pins `D12 (pinned): coveringRecord enforces…`, `…fails CLOSED…`, `…(pinned, S7)…`; skipped `D12 (defence in depth)` |
| D13 | **CONFIRMED** | Low | `wallet-service/src/server.mjs:116-120` (`statusRefs` dropped), `src/oauth.mjs:213-227` (30-day refresh re-mints 1 h tokens with no verifier contact) | pins `D13 (pinned)…` ×2; skipped `D13: a tenant can revoke a connection (RFC 7009 /oauth/revoke)` |
| D17 | **CONFIRMED in mcp-auth / gate; REFUTED in wallet-service, sdk/js, hosted_idp** | Low | `sdk/mcp-auth/index.mjs:71` (`splitEmail` on last `@`), `:87` (`granteeCovers("*")` admits any string containing `@`); `sdk/gate/src/gateway.mjs:687,779` (admin check lowercases the whole email), `mount.mjs:318` (grantor lowercased before entitlement lookup), `config.mjs normEmail`, `connectauth.mjs userFor` | mcp-auth `D17: a string with two '@'…`, `D17: granteeCovers('*')…`; gate `D17: the admin gate must not fold…`, `D17: the grantor gate must not fold…` (skipped) plus pins of today's behaviour and of `identityEq` byte-exactness |
| D19 | **CONFIRMED (bounded)** | Low | `routes/fedcm.rs:296-312` (config cert + warrant with `None` status), `:325` (`status_idx: None`) | `d19_fedcm_config_cert_and_warrant_carry_status_refs` (ignored); pin `d19_pin_fedcm_presentation_is_bounded_to_five_minutes` |
| D20 | **CONFIRMED** | Low (defence in depth) | `sdk/mcp-auth/index.mjs:364,1296` (`bindingId` stored on bearer and refresh records, never indexed) | `D20: a second record naming an already-bound binding.id…` (skipped) |

### 1.1 D3 — hosted-primary holder is caller-chosen (Medium)

A tenant user, or anyone holding the roster password, stamps any well-formed
holder on tenant-issued device certs, including the holder of a device the
grantor already approved. Holder-pinned warrant matchers are the attenuation
axis against stolen credentials (B3); for tenant identities they are
bypassable. The tenant has no broker account namespace to check against, so
the broker lane's prefix rule cannot simply be copied. A code comment ("the
reissue hop supplies a corrected one") shows the dialog relies on the
passthrough to reconcile the browser's holder across issuers.

Remediation: self-assign always on the hosted lane and drop the `holder`
fragment parameter from `idp-device-authorize.js`; or keep a per-tenant-user
holder namespace and apply the same prefix rule as `/device/issue`. Either
way the dialog needs another way to reconcile holders (or accept reassigned
ones). WS8's PoC target.

### 1.2 D5 — JS admission ignores bindings (Medium)

Spec §6.4 step 3 requires every binding entry to be evaluated: a `holder`
matcher must cover the subject's holder, a non-`*` matcher against a
holder-less OAuth connection subject fails closed, and a `requester` entry is
unsatisfiable in operation A. Today a policy record narrowed to
`matcher: "agents.x"` admits every connection subject and every jwt-bearer
login regardless of holder, and a record carrying a `requester` entry admits
too. Exposure condition: the broker's authoring card signs `holder: "*"` for
gate-compiled grants, so the narrowed record has to be authored elsewhere
(the wallet). The widening is real but needs a grantor who deliberately
narrowed.

Remediation: persist `binding` on the policy row at `requestAuthoring`; in
`conjoinPolicy` and both gate entitlement paths evaluate the set: refuse any
`requester` entry, refuse a `connection` entry on a policy row, and for
`holder` require the matcher to cover the subject's holder (connection
subjects have none, so only `*` passes; jwt-bearer subjects pass
`vctx.holder` through). The simpler alternative is to refuse to store any
policy record whose binding is not exactly `{holder, "*"}` (decision 2).

### 1.3 D6 — gate fails open (Medium)

Two separate defects. Single-server policy mode reads rows from the store
with no validation at all, so a broker-revoked or expired policy row keeps
admitting jwt-bearer subjects until the operator deletes it (connection
bearers are fine: `mintConnectionTokens` revalidates fail-closed). In
gateway signed mode `isRowLive` admits on last-known-good while the broker
is unreachable; the code comment shows this was a console-diff UX choice
that leaked into enforcement. Because W4-12 maps an HTTP 503 to a definitive
`invalid_grant`, an HTTP 503 during an outage does the opposite: the gate's
`grantsDiff` custodially deletes signed policy rows, forcing a re-sign.

Remediation: route the single-server `entitlementFor` through
`isRowLive`-style validation with `exp`; in `isRowLive` drop the `?? true`
and treat unreachable as not-live for enforcement, keeping last-known only
for the console view; fix W4-12 so a 5xx is `temporarily_unavailable`.

### 1.4 D12 — wallet stored grants (refuted)

`coveringRecord` does payload-decode the stored grant without a signature
check, but the record was signed by the wallet's own config key and lives in
the safeStorage-encrypted store: anyone who can write the store already holds
`configKey` and can mint a fresh record, so the missing check buys an
attacker nothing (A6/A9). What the lane does enforce is substantial and now
pinned: requester origin == browser-verified origin, holder matcher covers
this device, exact audience, grantee == identity, `sign:sbo:<action>` scope
present, record expiry, unknown channel kinds refused, and a per-signature
`/status/check` that fails **closed** on unavailable (contrast gate D6).
"Config cert expiry never checked" is UX only: the verifier rejects the
presentation. "Parameters other than `mode` ignored" is correct under S7:
pay parameters pass through verbatim for the audience to enforce; the wallet
refuses an unknown `mode` and `normalizeGrants` refuses unknown parameter
keys at grant time. Optional hardening: verify the stored JWS against
`configKey.x` in `coveringRecord`.

### 1.5 D13 — wallet-service sessions outlive revocation (Low)

Ordinary RP-session semantics and the spec does not require RPs to end
sessions on login-warrant revocation, hence Low. What makes it worth fixing
is the asset behind the session: a custodied agent key. There is no RFC 7009
revoke, no logout, no per-tenant disconnect, and the accounts table stores
only `email, created_at`, so nothing a re-check could use. Remediation:
persist `statusRefs` per account, call `checkStatus` on refresh (fail
closed), add `/oauth/revoke` and a "disconnect all clients" page or tool.

### 1.6 D17 — identity comparison (Low)

Under S2 / I5, `Admin@example.com` and `admin@example.com` are distinct
identities. In the gate the first signs in as the admin and `Erin@` is
admitted under a row for `erin@`; mcp-auth treats `a@b@c.com` as an identity
with local part `a@b`, and `granteeCovers("*")` admits `@`, `@x`, `nobody@`.
Exposure needs an IdP in the admin's own domain that issues case-variant
local parts to different people, so Low. Refuted elsewhere: wallet-service
keys tenants byte-exact (the safe direction; the one `toLowerCase` at
`mcp.mjs:279` can only drop a held warrant); sdk/js passes identities
through verbatim; `hosted_idp.rs` lowercases the local part before the
roster lookup, which is issuer-side canonicalisation, not verifier
divergence; python-mcp-auth has no identity comparison at all. The Electron
wallet lowercases only user-typed input before issuance. This is the July L1
parser differential, still open in these two JS verifiers. Remediation: one
`parseIdentity` in mcp-auth (exactly one `@`, non-empty parts, domain-only
folding) used by every gate comparison.

### 1.7 D19 — FedCM throwaway objects carry no status refs (Low, decision)

Every object in the FedCM presentation expires in 5 min (pinned), so the
unrevocable window is 5 min, but "forget this site" cannot revoke the
registered warrant and the per-key refs of fb §3.2 / core §6.3 do not hold.
Decision 5: accept as the documented FedCM exception and say so in core §6.3
/ fb §3.2, or allocate broker-list refs for both throwaway keys (two
`allocate_status` calls per mint; the list grows by two per FedCM login).

### 1.8 D20 — binding.id not 1:1 (Low)

Two different records whose validation returns the same `binding.id` both
mint, so §6.6 invariant 5 is not held resource-side. Needs a double-minting
broker to exploit. Remediation: a `bindingId → record` map in the lane; on
code release and every mint/refresh refuse (and optionally burn the existing
family) if the id is bound to a different record.

## 2. New findings

| ID | Finding | Severity | Where | Test |
|---|---|---|---|---|
| W4-22 | **Hosted wallet admits delegated and non-login presentations as the human.** The comment says "default verifier rejects subject=agent", but `@browserid-ng/verify` dropped `allowAgent` (July M2 fix) and tells RPs to compare `grantee` with `email`; `/oauth/login` never does, and neither layer checks `scopes`. An agent identity holding any warrant whose audience is the wallet origin signs in as the human and gets full OAuth control of the custodied agent key. Needs one human-approved consent card for that audience. | **Medium** | `wallet-service/src/server.mjs:33-35,116-120` | skipped `W4-22: a delegated presentation…`; pin `…without the login scope is still admitted today` |
| W4-30 | **Tenant onboarding squat.** Any broker account opens a `PendingDns` tenant for any domain; a second attempt gets 409, pending rows never expire, and only the squatter may `check` or `delete`. The real domain owner can never onboard (A4; DoS on onboarding only, activation still needs DNS control). | Medium | `hosted_idp.rs:782-880` (`tenant_create`), `store/memory.rs:1116`, `store/sqlite.rs:3129-3144` | `w4_30_pending_tenant_squat_does_not_block_the_domain_owner` (ignored); pin `pin_pending_tenant_issues_nothing` |
| W4-31 | **Stateless `/idp` cookie ignores an admin password reset.** `/idp/device_cert` reads `must_change` from the cookie, not the roster; `roster_password` sets `must_change` in the roster but an open 2 h session keeps issuing 90-day certs. Roster `Disabled` is re-read (pinned); the reset is not. | Low–Medium | `hosted_idp.rs:113-158`, `:355-362`, `:1190-1196` | `w4_31_admin_password_reset_stops_an_open_idp_session_from_issuing` (ignored); pin `pin_roster_disable_stops_an_open_idp_session_from_issuing` |
| W4-10 | **Policy conjunction runs only in connection mode.** With `createAuthCodeLane({policy})` a jwt-bearer (Lane A) presentation from a non-owner with no covering policy row still mints a bearer and `authenticate` returns `permittedBy: null`. The gate compensates by re-running `entitlementFor` at `/mcp`; mcp-demo configures no policy, so no live exposure; footgun for any other consumer. | Low | `sdk/mcp-auth/index.mjs` `createAuthCodeLane` vs `createMcpAuth.handleToken` | skipped `W4-10: with policy configured, a jwt-bearer presentation…` plus pin |
| W4-11 | **Refresh grant accepts a request with no `client_id`** (`p.client_id != null && …`); the authorization-code branch requires it. OAuth 2.1 §4.3.1 makes it REQUIRED for public clients. Rotation and family burn bound the impact. | Low | `sdk/mcp-auth/index.mjs:1323` | skipped `W4-11: a refresh without client_id must be refused…` |
| W4-12 | **`validateRecord` reads any non-2xx as a definitive `invalid_grant`.** A broker 503 becomes a verdict: `conjoinPolicy`'s 503 rethrow never fires and the gate's `grantsDiff` deletes signed policy rows during an outage. Shapes D6. | Low | `sdk/mcp-auth/index.mjs:318` | skipped `W4-12: an HTTP 5xx from /validate-record is 'temporarily_unavailable'…`; gate pin `…HTTP 503 … read as DEFINITIVE` |
| W4-13 | **Lane A bearer outlives the presented warrant.** A jwt-bearer token lives `tokenTtlS` (1 h) regardless of warrant or access-cert expiry; `/verify` returns no expiry for presentations so the AS cannot cap (WS6 D7 class, verifier-side). Same in Python. | Low | `sdk/mcp-auth/index.mjs:266`; python `handle_token` | python skipped `test_bearer_never_outlives_the_presented_warrant` plus pin |
| W4-14 | **Parameterised scope entry crashes the Python AS.** A `scopes` entry that is an object makes `handle_token` raise `TypeError` from `" ".join(scopes)`: an unhandled 500 rather than a refusal or verbatim relay (S7 relay rule). JS renders `[object Object]` instead. | Low | `sdk/python-mcp-auth/browserid_mcp_auth/__init__.py:235` | python skipped `test_parameterised_scope_entries_fail_closed`; mcp-auth pin |
| W4-20 | **Native warrant prompt does not distinguish auto from prompt mode.** Renders bare scope names; spec §5 / §7.5 require the consent card to say auto-mode scopes are standing authority. A page requesting `sign:sbo:post` (default `auto`) gets silent repeated signing after a prompt that never said so. Parameters are invisible too (the safe direction). Related, code-read only: prompt-mode signature summaries render four fields while `signingBytes` signs every envelope field; owner is identity-pinned so clarity, not forgery. | Low | `wallet/src/request.js:116-120`, `main.js approveRequest`; `request.js:233-241` | skipped `W4-20: the native warrant prompt distinguishes…`; pin of what the prompt shows |
| W4-21 | **Loopback page origins may pair with the wallet in release builds.** `ALLOWED_ORIGIN` admits `http(s)://localhost:*` and `127.0.0.1:*` unconditionally ("for the e2e harness"); any local dev-server page can POST `/pair`, and once paired `/request` trusts the body `origin`, so it files requests as any origin and login requests for any RP (A9). Mitigated by a default-Cancel native dialog that names the page; any 32-letter `chrome-extension://` origin may pair likewise. | Low | `wallet/src/server.js:17`, `:108-111` | skipped `W4-21` (also needs port 8873 free) |
| W4-23 | **wallet-service trusts the first `X-Forwarded-For` hop** for every rate limiter and the audit-log `ip`; any client resets its own budget per request (cf. W5-6). | Low | `wallet-service/src/server.mjs:76-77` | skipped `W4-23` |
| W4-32 | **July L3 class is back: `idp_session` cookie is a raw root-key signature over an untagged payload** (`b64(json{email,exp,mc}).b64(sig)`). The only raw root-key signature left in the broker; every other is a JWS whose signing input contains a `.`, so not exploitable today. | Low | `hosted_idp.rs:118-127`, `:137-158` | `w4_32_idp_session_cookie_payload_carries_a_type_tag` (ignored); pin `pin_idp_session_cookie_payload_is_signature_bound` |
| W4-33 | **OIDC flow records the starting session but attaches to the callback-time session.** `FlowState.session_id` is stored and never read; the double-submit cookie proves the same browser, not the same account. No login-CSRF vector found (JSON + preflight). | Low | `oidc/mod.rs:180-186,206-233`; `routes/oidc.rs:338-345,377-393` | `w4_33_oidc_attaches_to_the_session_that_began_the_claim` (ignored) |
| W4-34 | **Bridge grant is per (account, email), not per session.** Any Full session of the account redeems it at `/device/issue` within 10 min, so a second session (e.g. enrolled with a leaked password) mints certs for the E2 address the moment the user re-proves it elsewhere, never seeing Google. fb §3.2 says "a live bridge grant" without saying whose. | Low (decision) | `state.rs:253-284`, `routes/device.rs:112` | `w4_34_bridge_grant_is_redeemable_only_by_the_proving_session` (ignored); pin `pin_bridge_grant_is_single_use` |
| W4-40 | **Spec gap: assertions carry no `iat`.** The amended §6.1 time-bounds paragraph (S6) rejects every checked object unless `iat ≤ exp`, but §5's assertion table lists only `aud`/`exp`/`req_origin`, and neither the JS SDK, the Rust agent nor `browserid-core::AssertionClaims` emit one. No implementation can satisfy §6.1 as written. | Low (spec) | `sdk/agent/src/protocol.mjs:45-48`; `browserid-core/src/assertion.rs:14-28` | pin `W4-40 (pin): the assertion … carries no iat` |
| W4-41 | **Mint endpoint and IdP taken verbatim from the registrar's poll body**, never cross-checked against the device cert's `iss`, no https required. A lying registrar redirects every device-key-signed access request to itself. No key leaves the process and the signed request is unusable at the real IdP (wrong `domain`), so attribution/availability only. | Low | `sdk/agent/src/device.mjs:143-150`, `:297`, `:384-385` | skipped `W4-41: the agent mints only at the IdP that signed its device cert`, `W4-41: … cleartext scheme is refused` |
| W4-42 | **Private key seeds on public properties.** `console.log(agent)`, `util.inspect` or `JSON.stringify` prints the device key seed; same for any `KeyPair`. Log aggregators and crash dumps become a key-leak path. | Low | `sdk/agent/src/device.mjs:291`, `src/crypto.mjs:33,43` | skipped `W4-42: inspecting a DeviceAgent…`, `…a KeyPair…` |
| W4-44 | **Legacy `Agent` lane is dead but exported** (WS1 class D confirmed): posts `{request_bundle}` the registrar does not accept, reads `json.warrants` where the server sends `grants`, `/provision/endorse` and `/provision/mint` 404; keeps the cleartext `secret_key` format alive. | Info | `sdk/agent/src/agent.mjs:259-262`, `:281-285` | pin `W4-44 (pin)` |

Also pinned for the D1 remediation: `sdk/agent/src/device.mjs:447-455`
`authorizesIdentity` mirrors the purpose-blind subaddress rule (skipped test
`D1 (client mirror)`; un-skip with the Q1 core fix).

Remediation sketches not given above: W4-30 expire pending rows (24–72 h)
and let a fresh attempt replace a pending one so DNS decides; W4-31 carry a
password epoch in the cookie and re-read `must_change` from the roster at
issuance; W4-32 add `"typ":"idp-session"` to the signed payload or HMAC
under a derived cookie key; W4-33 enforce `flow.session_id` or delete the
field; W4-34 store the session id in the grant and require it at redemption;
W4-10 make `policy` live on `createMcpAuth` so Lane A mints conjoin; W4-11
require `p.client_id === rt.clientId`; W4-12 map 5xx and 429 to the 503
error before the generic branch; W4-13 have `/verify` return `expires_at`
and cap both JS and Python bearers (fold into D7); W4-14 refuse entries the
AS cannot represent or render string-form only and keep the entry in `ctx`;
W4-20 feed entries through `BrowserIDScopeLabels` and call out `prompt`
entries; W4-21 gate the loopback branch on `WALLET_TEST=1` and consider
pinning the extension id; W4-22 reject `grantee !== email` and require
`login` in scopes at `/oauth/login`; W4-23 take the last XFF hop behind the
known proxy; W4-41 derive `idpDomain` from `deviceCertClaims.iss`, refuse a
mismatching `credential.idp`, require `https:` (loopback exempt); W4-42
private fields with `toJSON` / `util.inspect.custom` redaction; W4-44 delete
`Agent`, `Credential` and the provisioning helpers from the package.

## 3. Re-verified, no finding (pinned)

- **MCP OAuth AS (JS and Python):** PKCE S256 enforced, `plain` refused;
  `redirect_uri` exact-match against the DCR set, no redirect on failure;
  code single-use, bound to `client_id` + `redirect_uri` + PKCE, burned on a
  failed exchange; `client_host == redirect host` at release and every
  mint/refresh; refresh rotation with family burn; `/verify` always
  audience-pinned to the configured resource; per-call status re-check fails
  closed on HTTP 503 and on thrown fetch in both languages; `conjoinPolicy`
  fails closed on validator errors; a mount bearer is not valid at another
  resource. Replayed jwt-bearer assertions mint again (stateless verifier,
  no AS jti cache); audience-pinned and 5-min lived; RFC 7523 §3 only MAYs a
  replay cache. Login CSRF against `/connect/login` is possible but ends at
  an interstitial naming the foreign identity plus a broker grantor pin the
  victim's wallet cannot satisfy.
- **Malicious MCP server:** the gate lane only ever signs with its own agent
  against a warrant delivered by broker poll for `audience === resource`,
  and the agent validates grantee/holder before holding it; nothing a server
  returns changes what is signed. The wallet-service MCP surface
  (`mcp.mjs`) lets a connected client drive everything for the tenant by
  design; `grantor` goes to the broker verbatim and the broker enforces
  attribution; no path signs outside a broker-approved warrant.
- **Wallet messaging:** `relay.js` accepts only `ev.source === window`;
  `background.js` takes the origin from `sender.origin`/`sender.url`; no
  `externally_connectable`; pair token random 24 bytes, bound to the
  pairing origin; the server binds 127.0.0.1 and reflects only allow-listed
  origins. IPC handlers check the sender webContents id and that the frame
  URL is still the broker's `/consent`; `contextIsolation`, `sandbox`, no
  `nodeIntegration`; `wallet:consent-sign` signs only
  `browserid-warrant-v[12]` claims. `WALLET_AUTO_APPROVE=1` is a
  process-environment switch, outside A9.
- **Wallet-service OAuth:** PKCE S256 only, exact `redirect_uri`, https-only
  in production, single-use codes with family burn, refresh rotation with
  reuse detection, `resource` pinned to the wallet origin, `iss` in the
  response, Origin-checked `/oauth/login` and `/oauth/approve`.
  `client_name` from DCR is attacker-chosen and rendered as the consenting
  party (standard DCR risk).
- **Hosted tenancy:** cookie email == requested email; tenant derived from
  the email domain, never from Host or body; `/idp/access_cert` routes by
  `iss` and verifies under that tenant's key; forged-iss and cross-tenant
  access requests refused; sealed tenant keys AAD-bound to the domain;
  `managed` audience honoured only when the device cert is marked
  `managed`. Observations: `tenant_check` activates on key match even when
  `host=` names another provider (fail-closed downstream since verifiers
  follow DNS); after activation the broker never re-checks DNS, so if the
  TXT is removed signing continues but nothing verifies. `/idp/password`
  and `/idp/login` throttling is W5-2.
- **OIDC bridge:** verifier pinned to RS256 (HS256 with the modulus
  refused), `email_verified` required, nonce / state / PKCE single-use, flow
  cookie must equal the redeemed state. **handle_claim:** attestor pinned by
  config, DNSSEC-rooted key, `aud` = broker domain, jti single-use
  (in-memory; D18 class). **session_admit:** refuses a registry session on
  another account, unbinds on key revoke; login keys live 90 d > 30 d session
  max, so admission cannot outlive key liveness.
- **sdk/agent:** access request conforms to §4.2 (`jti` 8 random bytes,
  10-min window, `holder` / `domain` from the cert, `audience` only when
  `managed`); `Agent.save` / `Credential.load` 0600 on create and re-chmod
  on overwrite; `holderMatches("*")` matches spec semantics.
- **Login warrants:** `wallet/src/login.js:29` and `mediator.js:53` still
  emit refless `browserid-warrant-v1`; pinned by the S3 decision, not new.
  `registry.js:177-180` creates a new account on any lookup 404 (WS1 class
  D, unchanged).

## 4. July 2026 findings re-verified in these layers

| July | Status now | Note |
|---|---|---|
| M1 mailbox-only `/auth/device_cert` mint | **Fixed** | Route gone; every tenant mint sits behind the roster password and an Active roster check. |
| M2 sdk/js `allowAgent:false` dead default | **Fixed in sdk/js**; **recurs in wallet-service** | `sdk/js/index.mjs:52-65` throws if `allowAgent` is passed and exposes `grantee`. wallet-service's `/oauth/login` never does the comparison the fix delegated to RPs (W4-22). |
| M9 sbo-signer confused deputy | **Not repeated** in the native wallet or `wallet-signer.js` | Grants are per (verified requester origin, exact audience), identity-, holder- and scope-pinned, status-checked per use; prompt mode exists. Residual is W4-20's missing verb. |
| L1 parser differential | **Open** in mcp-auth / gate | D17 above. sdk/js, wallet-service, python have no divergent parser. |
| L3 `fb_email` cookie signed by root key, no `typ` | **Fixed for `fb_email`** (gone); **same shape recurs** as `idp_session` | W4-32. |
| L10 cleartext seeds on disk, 0600 | **Unchanged by design** | `sdk/wallet/server.mjs:42-48` plaintext 0600 in 0700 dir; sdk/agent and mingo (`~/.mingo/device-credential.json`, dir 0700 / file 0600 via `OpenOptions.mode`, no umask race, no keychain) same; Electron wallet uses safeStorage with a loud plaintext fallback shown in the tray; wallet-service AES-256-GCM under `WALLET_KEK` (production refuses the dev fallback), plaintext `DeviceAgent` cached in process memory per tenant. W4-42 is the in-memory counterpart. |

## 5. What needs Dan's decision

1. **D6 (b):** is last-known-good admission during a broker outage acceptable
   for the self-hosted gateway (availability over fail-closed), or should
   enforcement fail closed with last-known kept only for the console diff?
   Spec §6.4 says fail closed.
2. **D5:** support narrowed holder matchers on policy rows (implement the
   evaluation) or refuse to store any policy record whose binding is not
   exactly `{holder, "*"}` (simpler, equally fail-closed)?
3. **W4-22:** confirm the hosted wallet is human-only (reject delegated and
   non-`login` presentations), or document that an as-you agent may own a
   wallet tenant.
4. **D13:** tenant-side revoke/disconnect and status re-check on refresh in
   scope for the hosted wallet, or accepted RP-session semantics for now?
5. **D19:** accept as the documented FedCM exception (and say so in core §6.3
   / fb §3.2) or allocate broker-list refs for both throwaway keys.
6. **W4-34:** bridge grant account-wide (today) or bound to the proving
   session.
7. **W4-30:** pending-tenant expiry policy, and whether a DNSSEC-validated
   record for the real owner's key should be able to replace a squatter's
   pending row.
8. **W4-40:** add `iat` to assertions (spec §5, core, Rust agent, JS SDK) or
   scope §6.1's lower bound to objects that carry `iat`.
9. **W4-21:** keep the loopback-page pairing allowance in release builds, or
   gate on `WALLET_TEST` (and whether to pin the extension id).
10. **W4-13:** fold the `/verify` expiry field into the D7 scope-parameter
    work, or leave Lane A bearers at a fixed 1 h.
11. **W4-44:** delete the legacy `Agent` / `Credential` lane from
    `@browserid-ng/agent` (breaking export) or leave it documented as dead.
12. **D12:** stored-grant signature check in the wallet: fix or record as
    accepted.

## 6. Hand-off

- **WS8 PoC targets from this workstream, in order:** D3 (holder stamping
  against a local broker tenant), W4-22 (agent warrant for the wallet
  origin signs in as the human), D5 (narrowed policy record admits every
  holder), W4-30 (pending-tenant squat).
- **WS2 vectors this pass shows are missing:** mixed-case local parts and
  `a@b@c` identities fed to mcp-auth / gate; a policy record with a narrowed
  holder matcher and one with a `requester` entry through both JS admission
  paths; a scope entry with parameters through the Python AS.
- **Spec edits implied:** fb §3.2 "a live bridge grant" needs an owner
  (W4-34); core §6.3 / fb §3.2 need the FedCM-exception sentence or the ref
  requirement (D19); §5 assertion table vs §6.1 `iat` (W4-40).
