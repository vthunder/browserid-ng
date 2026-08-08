<!-- This Source Code Form is subject to the terms of the Mozilla Public
   - License, v. 2.0. If a copy of the MPL was not distributed with this
   - file, You can obtain one at http://mozilla.org/MPL/2.0/. -->

# browserid-ng — spec / codebase / cross-repo audit (2026-08-07)

Scope: `browserid-ng` plus its four satellites — `mingo`, `sbo`, `sandmill`
(PHP IdP), `browserid-bsky`, and the infra repo `sandmill-infra`. Goal: find
things broken, drifted, incongruous, confusing, or a security risk, with special
attention to **cross-repo divergence** (one repo on an older spec/API than
another).

Method: a four-angle adversarial fan-out (spec↔code conformance, cross-repo
drift, security-delta, broken/confusing), with the load-bearing and every
high/medium finding re-verified first-hand against code. This **builds on** the
prior security audit (`docs/security-audit-2026-07-29.md`, epic
`browserid-ng-wre6`) rather than repeating it — that pass fixed a Critical +
2 High + several Medium, and the crypto core came out sound. Tracking epic for
this audit: `browserid-ng-8g49`.

## TL;DR

The **implementation is in good shape and largely more advanced than the spec.**
The dominant problem is not broken code — it is **documentation drift on
security-critical protocol semantics**: the whole cert/warrant model was
re-shaped from `subject{user,agent}` + `identifier` to an opaque `holder` +
`grantor`/`grantee` delegation model (commits `fa21c8e`, `2582555`, 2026-07-23),
and the normative spec (`docs/specs/browserid-ng-protocol.md`, frozen 2026-07-19)
was never updated. Anyone implementing a verifier from the current spec would
build the *removed* trust model — including a `config_cert.iss == access_cert.iss`
check the reference verifier deliberately dropped.

Two findings rise above pure drift: the reference **RP library trusts Web-PKI
`.well-known` keys** (the exact downgrade the spec forbids), and **large user
flows have no e2e coverage** (whole specs quarantined, including a skipped
cert-leak security regression test).

The July-29 hardening holds: the SSRF guard, fail-closed status checks, jti
replay protection, prod-gated test endpoints, and now the session-cookie flags
are all present and correct in the deployed config. No secrets are committed.

## Test suite

`cargo test --workspace` — run via the `ssh localtest` route (required on this
Mac; Gatekeeper memo). **Result: green — exit code 0, zero failures, zero
warnings.** The workspace compiled clean; the broker integration binaries (each
spins a server + does DNS, ~24s apiece) all passed. (Output was piped through
`tail`, so the captured tail shows the final 13 binaries = 106 tests, 0 failed,
1 ignored; cargo's exit 0 confirms the full workspace was green.)

---

## Findings

Severity: **High** = security-relevant contradiction or an untested critical
flow; **Medium** = real drift/bug with a workaround or bounded blast radius;
**Low/Info** = hygiene, by-design-but-surprising, or latent. Each finding cites
`file:line`. IDs map to filed beans.

### High

**H1 — The core spec describes a superseded, security-critical trust model.**
The code factors credentials on an opaque broker-assigned `Holder` +
`HolderMatcher` (`browserid-core/src/device.rs:96-195`) and warrants on
`grantor`/`grantee` (`device.rs:455-478`); the spec §4–§6 still describes
`subject ∈ {user,agent}` + `identifier` and joins the bundle by
`(identity, subject, audience)`. Most consequential: spec §4.3 / §6.2 step 2 /
§8 / §9(b) require the verifier to enforce `config_cert.iss == access_cert.iss`
and call its absence "a privilege-escalation hole" — but `AccessPresentation::verify`
(`device.rs:616-632`) **deliberately removed** that binding for the
grantor/grantee cross-issuer model, arguing safety comes instead from "the write
attributes to the grantor, whose IdP must vouch for that identity." The code is
self-consistent and plausibly correct; the *spec* now normatively mandates a
check the reference implementation does not perform and mis-states the trust
argument. Sub-drift: access/config certs carry no `subject` (`device.rs:107`
calls it "the old, unenforceable hint"); the `/verify` return has no `subject`
(`VerifiedAccess`, `device.rs:544-568`); the "warrant is not bound to any
device/access key, reusable by any device" rationale (spec §5) is contradicted
by the holder-matcher anti-fungibility bind (`device.rs:669-674`).
→ Rewrite spec §4–§6 against the code (the design doc
`docs/design/browserid-end-to-end-flow.md` reflects the holder model but was
itself partially stale on the grantor/grantee split (now reconciled 2026-08-08)).

*Corrected actor model for the rewrite (from the 2026-08-08 review):* three
actors — **IdP** (authoritative for its identities; issues device certs and runs
the mint), **grantor** (identity holder with a config cert who authorizes
permissions by signing warrants; pinned to what the config cert is authoritative
for), **grantee** (identity holder who acts, proven live by the assertion). Key
nuance: the grantee is arbitrary at warrant-**signing** time (grantor's free
choice) but pinned at **presentation** time (`warrant.grantee == access_cert.identity`,
`device.rs:666`). The grantor presents its long-lived **config cert** rather than
an access cert because warrants must be durable/reusable (signed by the 90d config
cert, not a 24h access cert) — the grantor has no liveness to prove. And the
**holder** matcher (`device.rs:672`) binds a warrant to a specific credential
family, not just the identity — the piece that replaced `subject{user,agent}` and
that the spec still omits. Full write-up in bean `browserid-ng-25kf`; a companion
succinct README/overview section is tracked in `browserid-ng-rpsv`.

**H2 — The reference RP library trusts Web-PKI `.well-known` keys, the downgrade
the spec explicitly forbids.** Spec §3 is emphatic: the DNSSEC `_browserid`
record is the *sole* trust root, "a key presented only via `.well-known/browserid`
is NOT trusted… no dual path," and a mis-issued TLS cert must not be able to
forge an identity. But `browserid-rp`'s `fetch_well_known_key`
(`browserid-rp/src/lib.rs:532-562`, reached via `trust_issuer_from_well_known` /
`trust_primary_from_well_known`) takes the IdP key straight from the
`.well-known` JSON over plain HTTPS — and even accepts an `http://` base — with
**zero DNSSEC**. The broker-side verifier (`verifier.rs`) does DNSSEC correctly;
the RP *library* an integrator is told to use does not. Comments at
`browserid-rp/src/lib.rs:120-123,271-273` still claim the removed issuer binding
holds, compounding the mis-direction. → Either make the RP library resolve via
DNSSEC (or a detached proof), or clearly mark `_from_well_known` as a
test-only/pinning-bootstrap convenience, and fix the stale comments.

**H3 — Whole user flows have zero e2e coverage; a security regression test is
skipped.** In `e2e-tests/tests/`: `silent-assertion.spec.ts` is entirely
`test.fixme` (8/8 — the communication_iframe silent-session path is untested);
`primary-idp.spec.ts` skips 13/25 including line 656, the `bean-ugg2` test that
the shim "targets the parent origin (not `*`) and gates inbound on source" — a
cert-leak-to-malicious-parent regression; `cross-origin-rp.spec.ts` fixmes the
whole cross-origin section (4), including the test that mirrors the production
`browserid.me ↔ id.browserid.me` origin split; `guestbook.spec.ts:53` fills a
`#pv-handles` element that **no longer exists** in app code (current UI uses
`#pv-handle`), so the flow fails on a dead selector — and the tracking bean
`browserid-ng-78hi` understates this. → Re-enable or rewrite; treat the ugg2
skip as priority.

**H4 — The agent-provisioning interop spec mixes both models.** `docs/specs/agent-provisioning-and-grant-api.md`
(the module a third-party agent implements from) speaks of "`agent`-subject
device cert" and "(`identifier`, `subject`)" tuples through most of its body
(lines 13, 24, 50, 61, 96, 124, 139, 159, 173) while its tail and the
implementation use `holder`/`grantor`/`grantee`. An implementer following the
first half builds the removed model. `docs/specs/README.md:28` repeats the stale
"`agent`-subject device cert." → Reconcile with the holder model.

### Medium

**M1 — The mint does not check the device cert's revocation status.** Spec §4.2 /
§6.4 promise "instant revocation at the mint (a revoked device cert mints no new
access cert)." `access_mint` (`browserid-broker/src/routes/device.rs:274-329`)
verifies signature, issuer, expiry, purpose, jti-replay, target domain, identity
authorization, and holder — but never consults the device cert's `status` index.
A revoked device cert still mints fresh access certs. Blast radius is bounded:
the minted access cert *inherits* the device's status ref
(`routes/device.rs:320-323`), so a status-checking RP still rejects it — but the
spec-promised mint-side kill is not enforced. → Check the device status index at
mint.

**M2 — Support-document and verifier API shapes differ from the spec.** Spec §3.1
lists a `mint` field (REQUIRED for conformance); `SupportDocument`
(`browserid-core/src/discovery.rs:18-77`) has **no `mint`** — the mint path is
published as `access-cert` — plus five undocumented fields (`device-cert`,
`device-authorization`, `agent-device-authorization`, `device-revoke`). Spec §6.1
documents `POST /verify` with an `assertion` field and cites
`browserid-broker/src/routes/verify.rs`; the actual route is `POST /verify-access`
with a `presentation` field (`routes/device.rs:335-341`) and there is no
`verify.rs`. A spec-conformant client finds neither `mint` nor `/verify`.
→ Update §3.1/§6.1.

**M3 — mingo.place issues certs that can never be revoked.** `mingo-idp` passes
`None` for `status` on its device, config, and access certs
(`mingo-idp/src/device.rs:135,152,333`). Because the RP fail-closed status check
only fires when a ref is *present* (`browserid-rp/src/lib.rs:321-328`), these
certs verify fine but have no revocation authority — a compromised mingo.place
credential cannot be killed short of rotating the IdP key. (bsky explicitly
treats a real status ref as its differentiator.) → Allocate status indices at
issuance, like the broker and sandmill do.

**M4 — The golden-vector freeze test silently passes when the vector file is
absent.** `browserid-core/src/device/tests.rs:315` guards the drift assertion
with `else if let Ok(committed) = std::fs::read_to_string(path)`; if
`test-vectors/device-cert-v1.json` can't be read — exactly the case when
`browserid-core` is consumed as a git dependency (mingo, sbo), where
`../test-vectors` doesn't exist — the freeze check is skipped and the test passes
on the live-verify alone. The cross-language (Rust/JS/PHP) wire-compat anchor
evaporates with no failure. → Make a missing vector file a hard error (keep
`REGEN_VECTORS=1` as the only regeneration path).

**M5 — mingo's operational tooling calls endpoints that exist nowhere.**
`mingo-app` seed/appoint/livetest POST to `{idp}/admin/provision`
(`seed.rs:1261`, `appoint.rs:241`, `livetest.rs:482,1054`) and
`{broker}/wsapi/admin/cert_key` (`seed.rs:1302`), expecting a classic per-email
`cert` in the response. Neither route exists at HEAD (mingo-idp router:
`mingo-idp/src/lib.rs:42-68`; no `admin/cert_key` anywhere in the broker), and
the classic cert format is no longer issued. Dead ops tooling; no prod-serving
impact but it will fail whenever next run. → Port to the device-cert flow or
delete.

**M6 — A cluster of stale docs that will actively mislead.** `docs/test-coverage-audit.md`
(2026-01-01) triages against files the device-cert migration deleted;
`sbo/crates/README.md:145,417` documents `sbo id import` as working while the CLI
`bail!`s it (`sbo-cli/src/commands/identity.rs:774,809,855`); `sbo-capture/src/lib.rs:8`
cites a removed `/wsapi/cert_key`; `mingo/docs/notes/auth-spec-comparison.md`
(2025-12-21) describes a pre-JWT assertion format; `mingo-idp/Cargo.toml:18-20`
comments a different rev (`4fce152`) than the pin (`ac7b93e`); `sandmill/docs/deployment.md`
omits the IdP entirely. → Delete or mark superseded.

**M7 — Protocol logic is forked across repos with only convention keeping it in
sync.** The `{"secret_key": "<b64url seed>"}` keypair format is separately
parsed in 5 places (broker `config.rs:62`, mingo-idp `config.rs:97`, mingo
`mingo.rs:308`, bsky `idp/mod.rs:214`, sandmill PHP `GenerateBrowserIdKey.php:32`);
there are 3 full IdP implementations; and `mingo-idp/src/poster.rs:344-420`
hand-rolls the `/agent-provision` wire (string-indexed response parsing that will
mis-parse silently on a shape change) despite already depending on
`browserid-agent`. One protocol change = N uncoordinated edits, no shared test.
→ At minimum add cross-impl conformance vectors (and see M4).

**M8 — Deferred security items from the July-29 audit are still open in code.**
Re-confirmed: `authenticate_user` has no rate-limit/lockout (`routes/auth.rs`,
bean `ytjn`); unauthenticated account enumeration across lifecycle endpoints
(bean `dw35`); the fallback `/auth/device_cert` password-bypass for
password-backed emails (bean `7ww7`). These were consciously deferred for
product/infra decisions — this audit just verifies they haven't regressed shut.

**M9 — sandmill's dead classic-cert signing path is still routed.**
`POST /api/browserid/cert_key` → `certKey` (`sandmill/.../BrowserIdController.php:381`,
routed `routes/web.php:205`) still signs **classic `principal.email` certs**
(a format no current verifier accepts) with the live IdP key; admin can mint for
any `@sandmill.org` identity. It additionally 500s on a seed-only key because
`createCertificate` calls `base64urlDecode(privateKey)` raw (`:463`) instead of
the seed-expanding `secretKey()` helper. A "removal" commit (`9f81aaa`) actually
removed a *different* endpoint. → Remove it; a stray signing oracle for a dead
format is pure liability.

**M10 — Audience matching is raw string equality with no canonicalizer.**
`browserid-core` compares assertion and warrant audiences with `!=`
(`device.rs:645,675`); the only semantic rule (`sbo+raw://` vs `sbo://`) lives in
the sbo daemon (`sbo-core/src/authorize.rs:180`), and the literal
`sbo+raw://avail:turing:506/` is hardcoded in 5+ places across mingo and sbo.
Failure mode is fail-*closed* (a trailing-slash/case/port mismatch rejects a
valid login — an availability foot-gun, not a takeover), and no consumer re-uses
the verified audience as a capability, so there's no confused-deputy. Still,
core offers implementers no help and the shared constant invites cross-repo
skew. → Provide a canonicalization helper in core; make the audience a named
constant/env in one place.

### Low / Info

- **sbo's default broker host is dead** (`id.sandmill.org` fails TLS now); dormant
  because every CLI path that would dial it is `bail!`-stubbed and `broker_config`
  is `#[allow(dead_code)]` (`sbo-cli/.../identity.rs:816-825`). Flip the default to
  `browserid.me` before the device-cert CLI rebuild lands. (mingo already uses
  `browserid.me` everywhere — correct.)
- **CSP self-check only hashes the first inline script per file**
  (`browserid-broker/src/routes/mod.rs:485`). No strict page ships a second inline
  script today, so the CSP is sound; but adding one would silently break the page
  (blocked by CSP) while the guard test still passes. Count scripts, not files.
- **Whole-handle claim scope** (`routes/handle_claim.rs:126-157`): whoever proves
  current control of an atproto handle can `transfer_email` every historical
  `<label>@handle` into their account. By-design Persona per-email semantics, but a
  handle takeover vacuums all past labels — worth an explicit product note.
- **`set_public_name` is an arbitrary display byline** (`routes/email.rs:161-193`,
  served unauthenticated at `/public-name`): an account can publish "Dan Mills" as
  its guestbook name. No credential impact; cosmetic impersonation.
- **Authority/MX gate fails open on transport error** (`authority.rs`, `email.rs:261-284`):
  disrupting the bridge or MX answer downgrades a handle domain to the SMTP lane —
  a routing downgrade, not a possession-proof bypass (SMTP verification still
  required). Deliberate availability trade-off.
- **Two *different* `broker-key.json` files in the working tree** (repo root and
  `browserid-broker/`, both gitignored) — a local footgun: which key a
  locally-run broker loads depends on cwd. Stale DB copies under `browserid-broker/`
  likewise. Nothing is committed (verified).
- **Undocumented implicit `+`-subaddress authorization** in `identity_matches`
  (`device.rs:59-85`): a bare `user@domain` cert authorizes every
  `user+tag@domain`. It's a deliberate protocol rule (RFC 5233) but the protocol
  spec never states it. Add it to §4.1.
- **Two verifiers, two §8.1 policies:** the broker auto-accepts any DNSSEC primary
  (`verifier.rs:390`); `browserid-rp` accepts a primary only if explicitly pinned
  (`lib.rs:199-215,279-287`) and enforces the fallback-can't-vouch-over-primary
  boundary only for registered domains. Spec §8.1 says "primaries are always
  accepted." Document the RP library's pin-based model.
- **JOSE `alg` header is never validated** (`jws.rs:33-41`): harmless today
  (Ed25519-only, single code path) but `alg:"none"`/arbitrary header would pass the
  structural check. Assertions also carry no claim-level `typ`. Info only.
- **`§6.3` offline detached-DNSSEC-proof verification is not in core** — the spec
  presents it as the reason trust is DNSSEC-rooted, but the primitive lives only in
  the sbo repo. Clarify the spec's layering.
- **sandmill config default `broker_url = https://localhost:3000`** (an https URL on
  a http dev port) while `demoVerify` hardcodes `https://browserid.me`
  (`config/browserid.php:11` vs `BrowserIdController.php:345`). Wrong in both envs.
- Minor: e2e spec count is 19 not "18"; several `#[ignore]` live tests need
  undocumented env creds (`sbo-capture/src/lib.rs:489,511`); keystore
  legacy-key-migration test skipped (`keystore.spec.ts:48`).

---

## Verified non-issues / already fixed

Stated explicitly so they aren't re-investigated:

- **Prod fail-closed guarantees hold.** The `allow_private` / `allow_http` /
  `fail_open` / `without_status_checks` escape hatches are all keyed on a
  `localhost`/`127.` domain match (`routes/session.rs:24`); with
  `BROKER_DOMAIN=browserid.me` (`sandmill-infra/apps/id.conf`) none are reachable —
  the H1 SSRF guard and the three status checks are enforced. (One caveat: this
  safety hinges on the domain string; a misconfigured `BROKER_DOMAIN` starting
  `127.` would flip SSRF *and* cookie-Secure off together.)
- **Holder-namespace isolation holds.** A client-chosen holder is not a
  cross-account primitive — the verify join pins `warrant.grantee == access_cert.identity`
  and requires the config cert be authoritative for the grantor, so a victim's
  `<ns>.*` warrant never covers an attacker's cert (`device.rs:664-674`).
- **`set_parent` cannot attach across accounts** (`routes/email.rs:215-253`).
- **Test-only endpoints are prod-gated off** (`routes/mod.rs:210-217`, tied to
  `DISABLE_SMTP`; prod has real SMTP).
- **jti replay protection at the mint is implemented** (`routes/device.rs:299-305`).
- **Session-cookie flags are fixed** (bean `0eud`): `http_only`, `secure`,
  `SameSite=Lax` (`routes/session.rs:128-140`).
- **No secrets in git** (`broker-key.json`, DBs, smoke-state all gitignored;
  verified with `git ls-files` / `git check-ignore`).
- **Cross-repo cert *wire format* actually conforms** — sandmill (PHP), mingo-idp,
  and bsky all emit the current claim shape and validity windows; no stale
  `subject`/`identifier` issuer was found. The breaking model commits (`fa21c8e`,
  `2582555`) are ancestors of *both* consumer pins, so no consumer is mid-break.
- **Validity windows, DNS/DNSSEC trust mechanics, key formats, bundle fail-closed
  shape, and the three status authorities all match the spec** (verified per §2–§6).

---

## Cross-repo drift matrix

| Repo | browserid-ng pin | date | broker host | provisioning wire | audience | notes |
|---|---|---|---|---|---|---|
| browserid-ng | HEAD `a563153` | — | browserid.me | `/agent-provision/*`, `/device/issue`, `/access/mint` | string-eq only | source |
| mingo | `ac7b93e` | 07-26 | **browserid.me** ✓ | SDK + hand-rolled `poster.rs` | `sbo+raw://avail:turing:506/` ×5 | dual-core in lock (isolated); certs unrevocable (M3); dead admin tooling (M5) |
| sbo | `2582555` | 07-23 | **id.sandmill.org** ✗ dead | hand-rolled wsapi (mirrors broker) | rule lives here (`authorize.rs`) | CLI provisioning `bail!`-stubbed; README stale (M6) |
| browserid-bsky | `main`@`4a0daed` | ~HEAD | bsky.browserid.me (own IdP) | core types direct | n/a | closest to HEAD; real status refs |
| sandmill | (PHP, no pin) | — | browserid.me (pinned verifier) | device-cert, byte-compat | derived | legacy `cert_key` still routed (M9) |

`2582555` is an ancestor of `ac7b93e`; `ac7b93e..HEAD` = 80 commits,
`2582555..HEAD` = 119 — but no `feat!`/`fix!` between the pins and HEAD affects
consumers.

---

## Recommended order

1. **H2** (RP Web-PKI trust) and **M1** (mint revocation) — the two behavioral
   security gaps.
2. **H1 / H4 / M2** — re-spec §4–§6 and §3.1/§6.1 and the agent-provisioning
   module against the code; make the design doc's authority explicit or fold it in.
3. **H3 / M4** — restore e2e coverage and the golden-vector freeze guarantee.
4. **M3 / M5 / M9** — cross-repo: mingo cert status refs, mingo dead tooling,
   sandmill legacy endpoint.
5. **M6 / M7 / M10** and the Low cluster — docs, fork hygiene, audience helper.

One bean per finding filed under epic `browserid-ng-8g49`.

---

## Filed beans

Epic: `browserid-ng-8g49`.

| Finding | Bean |
|---|---|
| H1 spec trust-model drift | `browserid-ng-25kf` |
| H2 RP Web-PKI .well-known trust | `browserid-ng-kh0j` |
| H3 quarantined e2e / ugg2 skip | `browserid-ng-jvcl` |
| H4 agent-provisioning spec mixes models | `browserid-ng-rsh1` |
| M1 mint skips device-cert revocation | `browserid-ng-mmnp` |
| M2 support-doc / verify shape drift | `browserid-ng-o68b` |
| M3 mingo unrevocable certs | `browserid-ng-97jn` |
| M4 golden-vector silent skip | `browserid-ng-16i2` |
| M5 mingo dead ops tooling | `browserid-ng-lnas` |
| M6 stale docs cluster | `browserid-ng-c6wi` |
| M7 forked protocol logic | `browserid-ng-bmi0` |
| M8 deferred July-29 items still open | `browserid-ng-oawf` |
| M9 sandmill legacy cert_key | `browserid-ng-yc4r` |
| M10 audience canonicalization | `browserid-ng-fpcc` |
| Low/Info hygiene batch | `browserid-ng-ya11` |
| Docs: actors/artifacts/ceremonies overview | `browserid-ng-rpsv` |
