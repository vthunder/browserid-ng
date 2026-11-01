<!-- This Source Code Form is subject to the terms of the Mozilla Public
   - License, v. 2.0. If a copy of the MPL was not distributed with this
   - file, You can obtain one at http://mozilla.org/MPL/2.0/. -->

# Security audit 2026-11 — WS1: threat model, spec review, divergence ledger

**Status:** reviewer output, 2026-11-01. Nothing here has been through the
skeptic pass or a PoC; every code item is a **candidate** routed to WS4–WS8
for confirmation. Epic `browserid-ng-ag1l`. Threat model:
`docs/design/threat-model.md`.

**Method.** Full read of the three specs and request-kinds. Three parallel
read-only divergence checks (verification side; registry API; issuance and
consent) against every implementation in the repo: Rust core, verifier, rp,
dnssec, broker, registrar, sdk/js, sdk/python-mcp-auth, sdk/mcp-auth,
sdk/gate, wallet, wallet-service.

## 1. Headline candidates (class A: code weaker than spec)

Ordered by what an attacker gets. File:line are the reviewer's citations.

| # | Candidate | Where | Gets the attacker | Route |
|---|---|---|---|---|
| D1 | **Subaddress widening at the mint.** `identity_matches` lets an auth cert for `user@d` mint access certs for `user+anything@d`; both `/access/mint` and `/idp/access_cert` use it, and `warrant_request` lets it file JIT requests as the agent. Spec §4.6/§7.2: exact only. | core `device.rs:96-111`; broker `routes/device.rs:455`, `hosted_idp.rs:536` | Any browser auth cert acts as every agent identity of the user, bypassing the agent's own cert and revocation axis | WS6 + WS8 PoC |
| D2 | **Consent `respond` never checks the config cert.** No `config_cert_not_recorded` lookup, no issuer-signature or status verification on that path; only `warrants/register` checks. | registrar `consent.rs:457-465, 551-561` | A retired cert, a revoked device's cert, or a self-minted unsigned "config cert" naming the grantor signs approvals that are stored and delivered to the filer | WS5 + WS8 PoC |
| D3 | **Hosted-primary holder is caller-chosen.** `/idp/device_cert` passes the page fragment `holder` through verbatim, no namespace check. Spec fb §3.2, §7.4: issuer-assigned, never choosable. | `hosted_idp.rs:396-403`, `idp-device-authorize.js:23` | Holder isolation (B3) broken for tenant identities: a party can name another's holder and satisfy its warrant matchers | WS4 + WS8 PoC |
| D4 | **JIT warrant request is unsigned.** Body carries the public device cert + identity + grants; no device-key signature is verified. Spec §7.5 step 1. | `consent.rs:1268-1300` | Anyone with a copy of an agent's public cert files consent requests in its name (consent phishing at scale) | WS5 |
| D5 | **Admission in the JS layer ignores bindings.** mcp-auth/gate match policy rows on grantee only; a `requester` entry or specific holder matcher still admits a connection subject. Rust core enforces both. | `sdk/mcp-auth index.mjs:1027-1061`, gate `gateway.mjs:121`, `mount.mjs:82` | A policy record the grantor narrowed to one holder admits every holder | WS4 + WS2 vector |
| D6 | **Gate fails open on status.** `isRowLive` keeps a row live on a 503 from `/validate-record`; single-server mode never re-checks status or expiry at all. | gate `gateway.mjs:211-226`, `mount.mjs:76-85` | Revocation of a policy record does not reach the resource | WS4 |
| D7 | **Scope parameters are dropped at the HTTP verifier.** `/verify` and `/validate-record` return bare scope strings; `pay:` with a `cap` arrives uncapped at every SDK consumer. | `verify.rs:122,487,602,689` | Every attenuation on `pay:`/`contract:` scopes is void downstream of the hosted verifier | WS6 + WS2 vector |
| D8 | **No rate limiting on `/api/v1`.** No 429 on `stored_key`, `login_page` token spends, approval-code guesses (30-bit code, 5 min), or anything else; only the password page backend throttles. | `registrar lib.rs:205-237`, `approvals.rs:30-39` | Online guessing against the account boundary | WS5 + WS8 PoC on approvals |
| D9 | **Network fetches before proof verification** on `accounts`/`accounts/lookup`: DNSSEC discovery and status fetches run per carried cert before any signature is checked; replay check after. | `registrar account.rs:86-108, 343-344, 398-399` | Unauthenticated SSRF-shaped amplification; violates I2 | WS5 |
| D10 | **Possession proofs never enter the replay cache.** Only the header jti is cached. | `account.rs:100-108` | A captured possession proof is reusable inside another request for 300 s | WS5 |
| D11 | **Attach of a key active on another account corrupts that row** (identities, holder, login_key_id overwritten; `user_id` kept). | `store/sqlite.rs:2836-2850` | Cross-account row pointing at a foreign login key | WS5 + SqliteStore test |
| D12 | **Wallet signs under unverified stored grants.** Stored record is payload-decoded with no signature check; config cert expiry never checked; scope-entry parameters other than `mode` ignored. | `wallet request.js:166-190, 273` | A tampered wallet store signs anything; inv. 9/14 not upheld client-side | WS4 |
| D13 | **wallet-service drops status refs**; 24 h cookie and 30-day refresh re-mint 1 h tokens with no status re-check. | `wallet-service server.mjs:116-120`, `oauth.mjs:213-227` | Login revocation invisible to the hosted wallet until the refresh token dies | WS4 |
| D14 | **DoT transport failure demotes primaries to fallback.** Connect failure, timeout, Refused → Insecure → fallback path; a fallback-issued cert for a primary's domain then passes step 2. | `browserid-dnssec/dns.rs:139-184, 273-276` | Network attacker blocking 853 turns B2 off | WS6 + WS8 (needs a rogue fallback; broker key required, so bounded) |
| D15 | **browserid-rp status path**: no URI-host == iss check, follows redirects, no private-IP guard, ttl + 600 s grace with no cap. Registrar validity bar likewise skips host == iss. | `browserid-rp lib.rs:272-290, 699-779`; `registrar_glue.rs:1115-1125` | July H1/M3 class, still open in the RP library | WS6 |
| D16 | **`max-ttl`/`cap.window` defeated by future `iat`.** No `iat ≤ exp` or `iat ≤ now` anywhere; `exp − iat` goes negative. Status lists: future `iat` stays fresh past the cap. | core `device.rs:61, 314-317`; `status.rs:197-200` | Managed-identity constraints void; spec text enables it | WS3 property test + spec fix |
| D17 | **Local-part case folding in gate/wallet-service**; mcp-auth splits on last `@` and treats malformed strings as identities; `granteeCovers("*")` admits any string containing `@`. Core rejects all of these. | gate `gateway.mjs:49…`, mcp-auth `index.mjs:71-94` | I5 violated; identity confusion between verifiers | WS2 vector + WS4 |
| D18 | **JIT lane details**: 1–10 grants not 1–8; duplicate audiences not rejected; primary-issued device cert status never checked on `warrant_request`; jti replay set in-memory (restart reopens the window). | `consent.rs:1386-1392`, `routes/device.rs:29-43` | Minor widening; replay after restart | WS5 |
| D19 | **FedCM mints a throwaway config cert and warrant server-side with no status refs.** Spec allows the FedCM exception but "no broker page signs" and per-key refs do not hold. | `fedcm.rs:280-320` | Unrevocable login warrant | WS4 (decide: accept or fix) |
| D20 | **mcp-auth binding.id not indexed 1:1**; two validated records naming one id both accepted. | `index.mjs:364, 1281-1301` | Needs a double-minting registry; defence in depth | WS4 |

**July items re-confirmed open by this pass:** H1/M3 class on the RP
library (D15); M8-deferred rate limiting now extends to the whole `/api/v1`
surface (D8). The beans marked completed for ytjn/dw35/7ww7 still need the
WS5 code check the epic asks for.

## 2. Spec findings (design-level, independent of code)

| # | Finding | Severity | Proposed fix |
|---|---|---|---|
| S1 | **Registry login page delivers a login token to any same-origin `return_url`** (reg §4.2: "no allowlist"). The token enrols the holder's own login key, which is a full account session. The rationale "whoever holds the token still needs the account" is wrong: the token *is* the account. fb §3.1 solves the identical problem for issuance with accepted return origins. Code conforms to the spec, so this is a design gap: an attacker page opens the real login page with its own `return_url`; the user types their password; the token lands at the attacker. | High | Apply fb §3.1's accepted-origin rule to `login_page`, enforced in the token-issuing handler; or bind the token to the login key pubkey passed in the opening fragment so only the opener's key can spend it. |
| S2 | **Identity comparison disagrees between specs.** Core §5: domain lowercased A-label, local byte-exact. Reg §2: "identities compare after lowercasing". Code is split the same way (D17). | Medium | One rule, in core §5, referenced by reg. |
| S3 | **v1 warrants without `status` are accepted indefinitely**; a rogue or buggy wallet can emit unrevocable-at-registry records. Only config-cert revocation at the IdP stops them. | Medium | Verifier knob `require_status` defaulting on after a sunset date; registries refuse to store refless records. |
| S4 | **Warrant `status.uri` is signer-chosen and unconstrained**, unlike cert refs (host == iss). A stolen config cert points warrants at an attacker-run list; every verifier fetches it. The spec's safe-fetch rules (§7.5) are stated for audience proofs, cited by reg §3 for status, but absent from core §6.3. | Medium | State safe-fetch rules in §6.3; let RPs pin accepted registries; say explicitly which host must sign a list. |
| S5 | **§4.7 constraints are "not implemented" yet §6.1 step 7 is a MUST.** Core does reject unknown keys; the spec should say that absent an implementation, *any* `constraints` claim rejects, and name the verifiers that implement it. §4.7's `scopes` also cannot restrict a scope-less login warrant (nothing is outside the set). | Medium | Add the sentence; define that an allowlist applies to logins as `[]`. |
| S6 | **No lower bound on `iat` anywhere** (D16). | Medium | Add `iat ≤ exp` and `iat ≤ now + skew` to §6.1 step 3/6 and §6.3. |
| S7 | **Scope-parameter enforcement is contradictory.** §5 says `pay:` parameters are audience-enforced and "a wallet never does"; inv. 9 says the wallet honors parameters; inv. 14 says any consumer must refuse an unimplemented one; step 9 lets a verifier return bare strings (which hosted `/verify` does, D7). | Medium | Require verifiers to return scope entries verbatim; name the enforcing party per parameter. |
| S8 | **fb §4 cites `/api/v1/token` and `/api/v1/devices/register`**; neither exists in reg or the router. `parent_presentation` (§7.1) is sent by dialog.js but read by nothing. | Low (doc) but breaks the conformance oracle | Rewrite fb §4 against `accounts`/`login`/`attach`. |
| S9 | **Scope grammar is stale**: reg §3 and request-kinds say `[a-z0-9_:.-]` ≤64; shipped SBO scopes use `/ * @ +` and the server allows ≤128 bytes with no charset; the wallet has a third regex. | Low | Update spec and schema; one grammar in one place. |
| S10 | **Reg §5.2.4 restore path needs no confirmation or config cert**, contradicting §2/§5.2.1 (code follows §5.2.4). A suspended identity returning silently pulls it off the account that now holds it. | Medium | Require `confirm_takeover` + fresh config cert on restore when another account holds it. |
| S11 | **Existence oracles the spec defines**: approvals cap `login_rejected` only for existing accounts (§5.2.8); "login key on another account" error (code). | Low | Same answer regardless. |
| S12 | **Issuance has no second-device approval**; fb §3.1 admits loopback squatting and consent phishing through a trusted wallet are uncovered. Reg §5.2.8 approvals exist for registry login but not for cert issuance. | Low (accepted risk, document) | Decide and record in the threat model. |
| S13 | Smaller spec-internal items: assertion has no `typ` (§4 rule); §3 silent on resolver transport failure (D14); §6.3 does not tie a cert ref's `uri` to its `iss` though the hosted verifier does; `PUT` policy vs "every mutation is a POST"; `claim` of an `agent` code undefined; `binding_id` minted at filing vs at claim; `holder_mismatch` reason name collision; §8 rule 1 "device-cert key" vs login keys; refless v1 record gets no revocation (§6.4 1e). | Low | Editorial pass. |

## 3. Class B / C / D summary (not security gaps, but conformance drift)

- **Stricter than spec (B):** core rejects unknown fields inside known binding
  kinds; registrar revokes every login key sharing a holder; `grantor`
  required on record responds; browserid-rp defaults to primaries only (hosted
  and python default to the broker, D).
- **Spec silent, code chose (C):** reason vocabulary drift
  (`identity_not_named`, `scope_mismatch`, `no_status_ref`, unreachable
  `not_self_grant`); validation order differs from §7.1 on both `respond` and
  `register`; filer poll uses legacy `400 {success:false}` envelope and 404
  for expired; `?code=` lists all items plus the external one; `registry`
  advertised only when agent provisioning is enabled but routes always
  mounted; `client_name` never marked unverified in mcp-auth/gate; python
  strips a trailing slash from the audience; sdk/js drops `holder` and
  `grantee_issuer`; agent quota counts identities (50) not certs (25).
- **Implementations disagree (D):** binding shape: mcp-auth accepts only the
  singular object, the wallet only arrays; `sdk/agent` posts a signed
  `request_bundle` the registrar does not accept, and expects 410/429 and
  `warrants` where the server sends 404 and `grants`; wallet creates a new
  account on any lookup 404.

## 4. What WS1 hands on

- **Threat model** with adversaries A1–A10 and invariants I1–I28
  (`docs/design/threat-model.md`). WS2 builds vectors from I1–I11, WS3
  properties from I12–I14 and S6, WS5's authz matrix from I22–I28.
- **Twenty class-A candidates** above, each routed. WS8 PoC targets, in
  order: D1, D2, D3, D8 (approvals), D5.
- **Spec fixes** S1–S10 need Dan's decision before the code is changed to
  match; S1 and S10 change behaviour users see.
- **Vectors the divergence pass showed are missing today:** array-form
  bindings, malformed identities (`a@b@c`, `@x`), mixed-case local parts,
  future `iat`, refless v1 warrant, `constraints` present, scope entries with
  parameters, a bundle verified by all six verifiers.

## Appendix: every endpoint that issues a cert (reviewer's table)

| Endpoint | Who can call | Bar enforced | Holder source | Identities |
|---|---|---|---|---|
| `POST /device/issue` (cookie form) `routes/device.rs:230` | Broker session + CSRF; same-origin dialog or `/device-authorize` | Unadmitted session may issue only an identity it proved (`:268`); `authorize_mint` (`mint.rs:85`): E3/agent need Full session, E2 need live bridge grant, primary refused; stale SMTP proof → reverify; `return_origin` checked server-side when supplied (`:273-277`) | Caller-supplied if prefix is the account's `browsers` namespace, else fresh (`:300-313`) | Auth cert exact; config cert always `local+*@domain` (`:325-328`) |
| `POST /device/issue` (Bearer + Proof form) `device.rs:246-257,280-287` | Wallet on an enrolled registry login key | Registrar §4.4 proof + `mint_rule_met` (`account_auth.rs:125`); bridged/primary never (`mint.rs:130`); no `return_origin` check (wallet is the caller) | Same | Same |
| `POST /idp/device_cert` `routes/hosted_idp.rs:346` | Tenant user with `/idp` cookie (roster password) | Cookie identity == requested email; `must_change` blocks; roster Active; `return_origin` checked (`:371-373`) | **Verbatim passthrough from caller**, else fresh (`:396-403`) — D3 | Config cert always `local+*@domain` (`:432`); `managed` from tenant policy |
| `POST /access/mint` `device.rs:407` | Anyone holding an auth device cert + signed access request | Own signature, iss, unexpired, purpose, own-list revocation, jti single-use (in-memory), domain pin, holder == cert holder | Copied from device cert | Via `authorizes_identity` — D1 widening |
| `POST /idp/access_cert` `hosted_idp.rs:493` | Same, tenant-issued cert | Tenant key sig, tenant-list revocation, jti, domain, holder, roster Active; `audience` honored only when cert is `managed` (`:560-600`) | Copied from device cert | Via `authorizes_identity` — D1 widening |
| `POST /fedcm/assertion` `routes/fedcm.rs:296-310` | Browser FedCM (Sec-Fetch-Dest gate `:59`) with FedCM session cookie | `authorize_mint == Allow` only (`:240`); silent token needs prior interactive opt-in (`:252-268`) | Fresh browsers-namespace holder; warrant matcher `<prefix>.*` | Access cert + throwaway config cert + warrant all signed server-side, no status refs — D19 |
| `POST /agent-provision/complete` `browserid-registrar/src/agent_provision.rs:885,1391` | Approving user (registry session) | User approval; two-stage identity/grants | Assigned from account namespace (`:1225-1233`); requester picks only the namespace name | Auth cert, single exact identity; quota counts agent identities (50), not certs (spec 25) |

Note the asymmetry: the cookie lane checks `return_origin` only "when supplied". WS5 should confirm an absent `return_origin` cannot reach the issuance handler from a page context (fb §3.1 says the check MUST be at the endpoint).

## 5. Decisions (2026-11-01)

Tracked in bean `browserid-ng-kgjr`. Accepted as proposed: **S1, S2, S5, S6,
S9, S10, S13**.

- **S3** — drop v1 outright, no sunset. `browserid-warrant-v2` is required
  everywhere; verifiers reject `browserid-warrant-v1`; the core compat path is
  deleted. Prerequisite: the signers still emitting v1 for login warrants
  (`browserid-broker/static/dialog.js:796`, `wallet/src/login.js:29`,
  `wallet/src/mediator.js:53`, `scripts/e2e/smoke-prod-dc.mjs:58`,
  `prototypes/menubar-wallet`) move to v2 with a `holder` binding entry and a
  status ref from `allocate_status`; `test-vectors/device-cert-v1.json`
  regenerated.
- **S4** — no RP registry allowlist. The registry is the grantor's agent and
  any DNSSEC-publishing domain may run one; pinning would gatekeep new
  registries for no security gain (a stolen config key signs fresh warrants
  anyway; only IdP-side config-cert revocation stops it, independent of
  registry). S4 narrows to two §6.3 rules: the §7.5 safe-fetch rules apply to
  every status fetch, and a list at `uri` is valid only when signed by the
  DNSSEC-published key of `uri`'s host.
- **S7** — core §5 keeps only the generic parameter mechanism (object entries,
  identity = scope string, stricter-wins attenuation, each parameter declares an
  enforcing role, relays pass entries through verbatim and reject what they
  cannot represent, enforcers fail closed on their own class, a parameter in no
  class is refused by everyone) and defines one parameter, `mode`
  (wallet-enforced). The pay parameters (`cap`, `counterparties`,
  `max_duration`, `min_reputation`) move to a browserid-pay spec as
  audience-enforced, mirroring §10's external-module pattern; the core parser
  becomes name-agnostic. Fixes D7 by the relay rule and removes the
  wallet-refuses-`cap` paradox (D12's parameter clause is then correct).
- **S8** — doc drift, confirmed deliberate on the spec side (`/api/v1/token`
  deleted in a8337d1; `devices/register` merged into `attach`). Rewrite fb §4
  and its pointers; clean two stale code comments.

Still open: **S11** (existence oracles), **S12** (second-device approval for
issuance).
