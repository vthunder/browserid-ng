<!-- This Source Code Form is subject to the terms of the Mozilla Public
   - License, v. 2.0. If a copy of the MPL was not distributed with this
   - file, You can obtain one at http://mozilla.org/MPL/2.0/. -->

# browserid-ng Security Audit — 2026-07-29

**Scope:** full adversarial audit of the browserid-ng protocol core, hosted
broker (browserid.me, treated as **live production**), registrar, RP library,
and the JS/Node SDKs. Six workstreams: verification core, credential issuance &
minting, account lifecycle & auth, network-facing input & DoS, client key
custody, dependency & secrets hygiene.

**Method:** each candidate finding was produced by a deep per-workstream reviewer
and then independently re-verified by an adversarial skeptic whose default was
*refute unless the code proves it real*. Severities below are the **post-verification**
severities. No proof-of-concept exploits were built; each finding is confirmed or
refuted by reading the code. Tracking epic: bean `browserid-ng-wre6`.

## Executive summary

The cryptographic core is **sound and conservative**: Ed25519-only with no
algorithm agility (no `alg:none`/confusion class exists), pinned key/signature
lengths, canonical point validation, genuinely fail-closed DNSSEC (SERVFAIL →
hard reject), fully parameterized SQL (no injection), a tight CSP, bcrypt cost
12, and correct verification *ordering* (signatures always checked before any
claim is trusted). The secrets-in-git posture is clean and the shipped Docker
image is safe-by-default (test/admin endpoints off).

The material risk is **not** in the crypto — it is in the **account-lifecycle
and network-facing HTTP surface** of the broker:

- **1 Critical** — unauthenticated account takeover via brute-forceable 6-digit
  codes (the reset path has no attempt-burn or IP throttle).
- **2 High** — blind SSRF from the verifier's status-list fetch; and credential
  rotation (password change/reset) that cannot evict an established attacker.
- **9 Medium** and **12 Low** — a mix of DoS amplification, a confused-deputy
  client signer, world-readable key-at-rest, an availability downgrade, and a set
  of defense-in-depth / consistency gaps.

Several initially-scary leads were **refuted or downgraded** on verification: the
FedCM token-mint gate is sufficient, holder-namespace isolation holds, the
config-cert `+*@domain` widening is redundant (not an escalation), and email
header injection is not reachable. Those are documented below so the reasoning
is on record.

## Severity ledger

| # | Sev | Finding | Location | Verdict |
|---|-----|---------|----------|---------|
| C1 | **Critical** | 6-digit reset code brute-forceable → unauthenticated account takeover (no attempt burn / IP throttle; same weakness on account-creation & email-add codes) | `broker/routes/reset.rs:114`, `account.rs:115`, `email.rs:266` | CONFIRMED |
| H1 | **High** | Blind SSRF: foreign status-list fetch has no scheme/host/private-IP restriction, follows redirects; reachable unauthenticated via `/verify-access` & `/guestbook` | `broker/verifier.rs:197` | CONFIRMED |
| H2 | **High** | Password reset/change invalidates no sessions or device certs — recovery cannot evict an attacker (30-day sessions) | `broker/routes/reset.rs:139`, `auth.rs:168` | CONFIRMED |
| M1 | Medium | Mailbox control alone mints 90-day warrant-signing config certs (no password/session/CSRF) — password-bypass for an email backing a password account | `broker/routes/fallback_idp.rs:282` | PARTIAL (overstated but real) |
| M2 | Medium | SDK `allowAgent:false` default is dead code — verifier no longer returns `subject`, so agent presentations pass as user logins | `sdk/js/index.mjs:100` | CONFIRMED |
| M3 | Medium | Foreign status-list `ttl` is issuer-declared with no verifier-side ceiling → cached all-clear list can defeat revocation for the process lifetime | `core/status.rs:190` | CONFIRMED |
| M4 | Medium | Unbounded status-list cache + no negative caching + uncapped response body → memory growth and 5s-per-request stall amplification (unauth) | `broker/verifier.rs:203,225` | CONFIRMED |
| M5 | Medium | Malformed-but-DNSSEC-signed record (or extra TXT RR; first-TXT-only selection) silently demotes a primary IdP to broker fallback → its own presentations rejected | `broker/dns_fetcher.rs:245,273` | CONFIRMED |
| M6 | Medium | `authenticate_user` has no rate limit / lockout / captcha — online password guessing bounded only by bcrypt | `broker/routes/auth.rs:37` | CONFIRMED |
| M7 | Medium | Unauthenticated user/account enumeration across five lifecycle endpoints (feeds C1/M6) | `broker/routes/reset.rs:48`, `account.rs:277`, `email.rs:521,556` | CONFIRMED |
| M8 | Medium | Broker **root signing key** written to disk with default (world-readable, 0644) permissions on auto-generate | `broker/config.rs:122` | CONFIRMED |
| M9 | Medium | Coarse per-origin SBO signing grant is a confused deputy: signs as **any** local identity, **any** audience, unlimited, no per-request consent | `broker/static/common/js/sbo-signer.js:186` | CONFIRMED |
| L1 | Low | Three-way email-domain parser differential; no `exactly-one-@` validation on identity fields | `core/device.rs:67`, `verifier.rs:296`, `rp/lib.rs:221`, `consent.rs:851` | CONFIRMED (narrowed) |
| L2 | Low | Access-request `jti` replay cache unimplemented at `/access/mint` (spec MUST) — replay inert without the access key, but unbounded mint | `broker/routes/device.rs:278` | CONFIRMED |
| L3 | Low | `fb_email` cookie signed by the IdP **root key** with no `typ`/domain tag (latent signing-confusion; not exploitable today) | `broker/routes/fallback_idp.rs:125` | CONFIRMED |
| L4 | Low | Cross-issuer safety is an unenforced caller precondition; module doc still advertises the removed `config.iss==access.iss` guarantee | `core/device.rs:15` | CONFIRMED |
| L5 | Low | `identity_matches` single-`*` glob has no `@`/domain boundary (`admin*`, `*` match across domains) | `core/device.rs:54` | CONFIRMED |
| L6 | Low | RP `IdentityVerifier` conformance uses a **static** primaries set, not live discovery — a trusted fallback can vouch for a domain that runs a primary | `rp/lib.rs:220` | CONFIRMED |
| L7 | Low | `complete_email_addition` is the only session-mutating wsapi endpoint with no CSRF check (SameSite=Lax mitigates) | `broker/routes/email.rs:254` | CONFIRMED |
| L8 | Low | Admin token compared with non-constant-time `==` (fail-closed when unset; remote timing impractical) | `broker/routes/account.rs:337,395` | CONFIRMED |
| L9 | Low | CORS mirrors any `Origin` on `/wsapi/*` → unauthenticated enumeration endpoints cross-origin readable | `broker/routes/mod.rs:219` | CONFIRMED |
| L10 | Low | Node wallet stores raw Ed25519 seeds in plaintext (mode 0600) — "non-extractable / never leaves origin" claim doesn't apply to the SDK | `sdk/wallet/server.mjs:149` | CONFIRMED (intended; doc-scope) |
| L11 | Low | `rustls 0.21` (EOL/unmaintained) pinned via hickory 0.24 — no open CVE, but no future patches | `Cargo.toml:45` | CONFIRMED |
| L12 | Low | `.dockerignore` omits `broker-key.json`/`browserid.db` — no defense-in-depth vs future `COPY . .` (current image safe) | `.dockerignore` | CONFIRMED |

### Verified non-issues (no action; recorded for the record)

- **FedCM token mint is safe.** `POST /fedcm/assertion` is gated on the browser-set
  forbidden header `Sec-Fetch-Dest: webidentity` before any cookie/session read;
  page JS cannot forge it, and a non-browser client that sends it still holds only
  its own session. (`broker/routes/fedcm.rs:59`) *Intended.*
- **Holder-namespace isolation holds.** A client cannot supply a holder outside
  its own namespace; the mint copies the device cert's holder verbatim and even a
  forged match is inert without the device key. (`broker/routes/device.rs:165`)
- **Config-cert `+*@domain` widening is redundant, not an escalation** — the base
  identity already authorizes its `+tag` subaddresses via the protocol rule.
  (`core/device.rs:189`)
- **Email header injection not reachable** — `lettre`'s typed `Address` parse
  rejects CRLF before any bytes are emitted; templates carry no attacker header
  content. (`broker/email/smtp.rs:114`)
- **Guestbook `escape()` omits `'`** but every interpolation is element-text or
  double-quoted, so it is a *latent* XSS only. (`broker/routes/guestbook.rs:107`)
- **Secrets-in-git: clean.** `broker-key.json`/`browserid.db*` untracked and
  gitignored, never committed; tracked test vectors use obvious dummy seeds.
- **Shipped image safe-by-default** — test endpoints and agent provisioning are
  off unless explicit env is set; admin endpoints fail closed when `ADMIN_TOKEN`
  is unset.

## Findings in detail

### C1 — Brute-forceable verification codes → account takeover *(Critical)*

`complete_reset` (`reset.rs:114`) resolves the pending record with
`get_pending(&req.token)` (`sqlite.rs:986`: `WHERE secret=?1`, no owner/type
filter) and **never burns the code on a wrong guess** — it deletes only on expiry
or success. Codes are `gen_range(100000..1000000)` = **900k** possibilities
(`crypto.rs:20`), valid **15 minutes**, and there is **no per-IP/per-account/
per-attempt counter anywhere** (grep confirms only `EmailRateLimited` exists, and
only on the *send* side). An unauthenticated attacker who knows a target email
(enumeration is free, M7) can spray the reset-completion endpoint and, on a hit,
set the victim's password. The identical unthrottled pattern applies to
`complete_user_creation` (`account.rs:115`) and `complete_email_addition`
(`email.rs:266`). Contrast the *fallback* path (`fallback_idp.rs:60`), which
already burns after 5 attempts — the fix is to bring the wsapi path to parity.

**Fix:** burn the pending record (or a per-record attempt counter, ≤5) on each
failed guess; add per-IP throttling on the completion endpoints; consider longer
codes for reset. This is the top priority.

### H1 — Blind SSRF in foreign status-list fetch *(High)*

`check_foreign_status` fires `status_http().get(&r.uri)` as the **first** action
after a cache miss (`verifier.rs:196`), *before* `parse`/`uri_matches_issuer`/
`token.verify` — all of which gate only how the *response* is interpreted, never
whether the request fires. The client sets a 5s timeout and **no redirect policy**
(reqwest default follows up to 10 redirects) and there is **no scheme allowlist or
private-IP/loopback/link-local block**. `r.uri` is attacker-authored (embedded in
a self-minted bundle's certs); the path is reachable **unauthenticated** via
`POST /verify-access` (with caller-controlled `accepted_fallbacks`) and
`/guestbook`, given only a DNSSEC-signed `_browserid` key for an attacker domain.
The response is blind, but connect-vs-refused timing and the distinct
`fetch {uri}: {e}` error strings form an internal host/port oracle, and redirects
reach internal targets (`http://169.254.169.254/...`) from an HTTPS origin.

**Fix:** require `https`, resolve and reject private/loopback/link-local IPs
(anti-rebinding: pin the resolved IP for the connection), disable redirects, and
cap the response body (see M4).

### H2 — Credential rotation evicts nothing *(High)*

`complete_reset` (`reset.rs:139`) and `update_password` (`auth.rs:168`) call only
`update_password` — a bare `UPDATE users SET password_hash` (`sqlite.rs:1043`)
that touches no sessions or certs. The `SessionStore` trait exposes only
create/get/delete-by-id — **there is no delete-by-user primitive** and no
`DELETE FROM sessions WHERE user_id`. Sessions live 30 days. So a
takeover-recovery reset cannot evict an already-established attacker session, and
any device certs the attacker minted remain valid until their own 90-day expiry.

**Fix:** add `delete_sessions_by_user` and call it on password change/reset;
optionally flip the status bit on device certs issued before the reset.

### Medium findings (summary)

- **M1** `/auth/device_cert` issues 90-day auth **and** config (warrant-signing)
  certs gated only on the `fb_email` cookie — no password/session/CSRF. This is
  the intended fallback trust model (mailbox control ≈ email account recovery),
  and the certs *are* status-revocable and expire in 90 days (so "unrevocable" was
  overstated), and `fb_email` is `SameSite=Lax` (so cross-site POST is blocked).
  The sharp residual is **password bypass for an email that also backs a
  password-protected account**. Consider requiring the account password (or a
  logged-in session) before issuing certs for an email that has one.
- **M2** The SDK's advertised `allowAgent:false` default is a **no-op**: the
  hosted verifier result dropped the `subject` field, so `json.subject || "user"`
  is always `"user"` and the agent-rejection branch is unreachable. An RP relying
  on the documented human-only gate silently accepts agents. Fix: derive agent-ness
  from `grantee !== email`, or remove the API and its doc promise.
- **M3** No verifier-side ceiling on foreign status-list `ttl`; a malicious issuer
  can sign `ttl = years` and its cached all-clear list stays authoritative for the
  process lifetime, defeating revocation. Clamp to a sane max (e.g. the reference
  5-minute cache window).
- **M4** The foreign-status cache is an unbounded `HashMap` keyed on
  attacker-supplied `r.uri` (memory exhaustion), the body read is uncapped (large-
  response OOM), and failed fetches aren't negative-cached (5s stall per request to
  a blackholed host). Add a size cap/LRU, a body-size limit, and negative caching.
- **M5** A corrupt-but-DNSSEC-signed `_browserid` record — or simply a second TXT
  RR (first-match-and-break selection) — downgrades to `secure_nxdomain` → broker
  fallback → `is_primary:false`, so a domain running its own primary has its own
  presentations rejected as "not an accepted fallback." Availability/attribution
  flip. Treat a malformed-but-signed record as **Bogus (hard reject)**, not
  NXDOMAIN, and reject (or deterministically handle) multiple `_browserid` TXTs.
- **M6** No rate limiting on `authenticate_user`; only bcrypt-12 bounds online
  guessing. Add per-IP/per-account throttling and backoff.
- **M7** Five endpoints confirm account existence unauthenticated
  (`stage_reset` 404-vs-200, `user_creation_status`, `email_addition_status`,
  `address_info`, `stage_user` 409). Standalone this is low-privacy, but it feeds
  C1/M6 — normalize responses/timing where feasible.
- **M8** `config.rs:save_keypair` uses `fs::write` with no mode → 0644 (world-
  readable) for the **broker root signing key**; a readable file is full issuer-key
  recovery. Write with 0600 (the SDK's `writePrivate` already does).
- **M9** `sbo-signer.js` gates only on a single per-origin boolean
  (`sbo_sign_granted`); `d.email` and `d.audience` are opener-supplied and
  unchecked against the granting session, and the popup holds device certs for
  **all** identities in the browser — so a granted origin can sign as any identity,
  for any audience, unlimited. Scope the grant to a specific identity/audience and
  require per-request (or per-identity) consent.

### Low findings

L1–L12 are in the ledger above with locations. They are defense-in-depth,
consistency, and hygiene items: a canonical single-`@` email parser (L1),
implementing the `jti` mint cache (L2), tagging the `fb_email` token type (L3),
fixing the stale cross-issuer doc + stating the caller precondition (L4),
domain-anchoring the glob (L5), documenting the RP static-primaries requirement
(L6), adding the missing CSRF check (L7), constant-time admin compare (L8),
tightening CORS on `/wsapi/*` (L9), scoping the wallet key claim (L10), tracking
the hickory/rustls upgrade to drop EOL rustls 0.21 (L11), and hardening
`.dockerignore` (L12).

## Remediation status (2026-07-29)

**Fixed in this pass** (code + tests, all crates build & test green):

- **C1** — `code_guard` module: `complete_user_creation`/`complete_reset`/
  `complete_email_addition` now bind the guess to the target **email** and burn
  the pending record after 5 wrong tries (mirrors `fallback_idp`). Request bodies
  and the account page carry the email they already had; no UX change.
- **H1** — SSRF guard on foreign status fetch: HTTPS-only, private/loopback/
  link-local/ULA IPs rejected, redirects disabled, response body capped
  (streaming-safe).
- **H2** — `SessionStore::delete_by_user`; reset evicts all sessions, password
  change evicts all then re-mints the caller's session (stays logged in).
- **M3** — `is_fresh_capped` TTL ceiling (5 min) for foreign status lists.
- **M4** — bounded status cache (1024 entries, stale-evict) + body cap (H1).
- **M5** — malformed-but-signed / multi-record `_browserid` now hard-reject
  (Bogus) instead of demoting to fallback; scan filters to the real record.
- **M8** — broker key written `0600`.
- **L2** — `jti` single-use replay cache at `/access/mint`.
- **L4** — corrected the stale cross-issuer module doc; states the caller
  conformance precondition.
- **L7** — `require_csrf` on `complete_email_addition`.
- **L8** — constant-time admin-token compare.
- **L12** — `broker-key.json`/`browserid.db*` added to `.dockerignore`.

**Deferred pending product decision** (UX / behavior / infra — flagged, not yet
changed):

- **M1** — requiring a password/session before the fallback mints certs for a
  *password-backed* email (adds a step to that flow).
- **M2** — the SDK `allowAgent` gate is a no-op; both honest fixes change SDK
  consumer behavior, and self-acting agents are no longer verifier-distinguishable
  from humans under the new model.
- **M6** — login rate-limiting needs a trusted client-IP source (behind the
  proxy) or a per-account lockout (a victim-DoS vector).
- **M7** — reducing enumeration changes the account page's "no such account" UX.
- **M9** — scoping the SBO signer to one identity/audience with per-request
  consent adds prompts.
- **L1 / L5** — canonical single-`@` email parser and glob domain-anchoring touch
  the core verification path; safer to land deliberately with focused tests.
- **L9 / L11** — CORS tightening on `/wsapi/*`; hickory/rustls 0.25 upgrade.

## Recommended remediation order

1. **C1** — burn codes + throttle the completion endpoints (unauthenticated
   takeover; do first).
2. **H1** — SSRF guard on the status fetch (scheme/IP allowlist, no redirects,
   body cap).
3. **H2** — session/cert invalidation on credential rotation.
4. **M4 + M3** — status-cache hardening and TTL ceiling (same module as H1).
5. **M8** — 0600 on the broker key (one-line, high value).
6. **M2, M9** — client-facing gates (SDK agent gate; SBO signer scoping).
7. **M1, M5, M6, M7** — auth hardening and the DNS downgrade.
8. **Lows** — batch as hardening.
