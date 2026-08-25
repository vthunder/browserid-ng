# Signing grants — implementation plan

**Date:** 2026-08-25 · **Status:** plan (design signed off 2026-08-25)
**Bean:** `ttn3` · **Design (source of truth):** `2026-08-22-signing-grants-design.md` (final at 95f4f45)
**Repos touched:** browserid-ng, sbo (`~/src/sbo`), mingo (`~/src/mingo`)

Five phases. 0–1 are browserid-ng-internal and backward compatible. Phase 2
ships the SBO verifier side **first** because `scopes_authorize` fails closed
on unknown scope dimensions (`sbo-core/src/authorize.rs:258`) — an
un-upgraded daemon rejects every write presented under a `sign:`-scoped
warrant, so the verifier must understand the new records before the wallet
starts presenting them. Phase 3 is the broker flip (consent + wallet), 4 the
mingo client, 5 verification and closure.

Two findings from the code survey that shape the plan:

- **The revocation story has no enforcement today.** `verify_device_attribution`
  returns the three status refs "for the caller to check fail-closed"
  (`device_attribution.rs:82-84`), but no SBO caller checks them —
  `sbo-core/src/authorize.rs:122` drops `verified.*_status`, and the daemon
  path (`sbo-daemon/src/validate.rs:182`) never fetches a status list. The
  design's "revocation is network-wide" claim is false until phase 2 lands.
- **The consent-page warrant signing is not yet a shared module** — it is
  inline in `consent.html:139-190` and duplicated in `authorize.html`. Phase 3
  extracts it; the dialog becomes the third consumer.

---

## Phase 0 — spec amendment PR (docs only)

The v2 spec landed normatively in `docs/specs/browserid-ng-protocol.md`
(d1385ac); this phase amends it. It **is** the "binding set amendment" the
rjmm bean has been carrying for the v2 spec — note that in rjmm when it lands.

- [ ] §5 warrant claims: `binding` holds a **set** of channel entries;
  singular object = one-entry shorthand (all deployed records); array form is
  new. Replace "Exactly one object" (`browserid-ng-protocol.md:386`) with
  "exactly one `binding` claim, holding a set".
- [ ] §5 bindings table → **kind × operation** table (holder / connection /
  requester, ops P and A, unsatisfiable cells) per design §3. This subsumes
  the standalone "connection not presentable" rule.
- [ ] §5: `requester` kind (`origin` field, web origin the only source
  specced); multi-entry sets are self-grant-only; delegated records exactly
  one `holder` entry; the three labeled doors (design §3) as non-normative
  notes.
- [ ] §5: scope entries — bare string `s` ≡ `{"scope": s}`; identity is the
  scope string everywhere scopes are identifiers; parameters are attenuations,
  stricter-wins; `mode` (`"prompt"` > `"auto"`, absent = auto); unknown
  parameter ⇒ reject.
- [ ] §5: `sign:` scope namespace, `sign:sbo:<action>` enumerated for phase 1.
- [ ] Assertion claims table (~:356-362): optional `req_origin`; honesty tier
  stated plainly (stamper is the wallet, same tier as an optional
  `ceremony: "prompted"` claim — design §5).
- [ ] §6.1/§6.6: presentation verification evaluates the **full** channel set
  per the table; invariants 9–14 appended (wallet-must-not-sign-uncovered,
  self-grant channel-set rule, consent-ceremony rule, no-cross-use,
  `req_origin` match fail-closed, **unknown means reject** — noting it
  supersedes, for these records, the ignore-unknown-claims working
  assumption).
- [ ] `docs/warrant-use-cases.md`: keep case 5 "proposed" until phase 3 ships,
  then flip to live; add the login-as-degenerate-signing-grant sentence to the
  spec if cheap, else leave in the use-cases doc.

## Phase 1 — browserid-core: record format + verification (backward compatible)

All in `browserid-core`, plus compile-fix ripples. Existing singular-binding
records must parse and verify byte-identically.

- [ ] `device.rs:636-655` `Binding` enum: add `Requester { origin }`; new
  `BindingSet` (or `Vec<Binding>` newtype) with serde accepting singular
  object **or** array; unknown `kind` ⇒ parse error (invariant 14).
- [ ] `WarrantClaims.binding` (`device.rs:698`) → set type; normalizers
  `binding()`/`holder_matcher()` (`device.rs:712,726`) become "find the holder
  entry"; v1 sugar unchanged.
- [ ] `check_shape` (`device.rs:809-845`): v2 requires ≥1 entry; multi-entry ⇒
  `grantor == grantee`; delegated (grantor ≠ grantee) ⇒ exactly one `holder`
  entry; per-entry field checks (connection `id`/`client_host` as today;
  requester `origin` non-empty, `https://` origin shape).
- [ ] Scope entries: `ScopeEntry` type (untagged string | object `{scope,
  mode?}`); unknown object keys ⇒ parse error; identity-projection helper
  (`as_str()`) so `Constraints::check` (`device.rs:260`), fingerprints, and
  intersections keep operating on strings.
- [ ] `assertion.rs:14-20`: optional `req_origin` claim + a create variant
  that stamps it.
- [ ] `AccessPresentation::verify` (`device.rs:947-1055`): replace the
  holder-only gate (:955-965) with full op-P evaluation — `holder` entry must
  cover the access cert's holder; `requester` entry ⇒ assertion `req_origin`
  present and equal (invariant 13); `connection` entry ⇒ unsatisfiable ⇒ fail.
- [ ] `admission.rs` (`ValidatedRecord.binding` :46, `matches_login` :171-180):
  op-A evaluation over the set — `requester` unsatisfiable ⇒ fail; holder /
  connection as today.
- [ ] Compile-fix call sites that pattern-match `Binding::Connection`:
  `browserid-registrar/src/consent.rs:559-582, 834-835, 899-917`;
  `browserid-broker/src/verifier.rs` (v2 paths incl. `/validate-record`
  :509-528).
- [ ] Tests: `device/tests.rs` + `admission.rs` inline — singular shorthand
  round-trip, array form, unknown kind rejected, multi-entry-on-delegated
  rejected, requester-without-`req_origin` fails, `req_origin` mismatch fails,
  connection entry fails op P, requester entry fails op A, scope-entry object
  parse/reject.
- [ ] `test-vectors/`: add a v2 vectors file (today only `device-cert-v1.json`
  exists) — binding-set positive + the negatives above.

## Phase 2 — SBO verifier side (deploy BEFORE the broker flips)

Repos: `~/src/sbo`, then mingo's pin bump. Old daemon + new warrant = every
write rejected (fail-closed scope grammar), so this phase is a hard
prerequisite for phase 3 going live.

- [ ] sbo-core: bump `browserid-core` rev (`sbo-core/Cargo.toml:27`, currently
  2582555) — binding-set parsing and the `req_origin` ↔ requester match arrive
  via `AccessPresentation::verify` for free.
- [ ] sbo-core `scopes_authorize` (`authorize.rs:245-262`): learn the `sign`
  dimension — `sign:sbo:<action>` contributes `<action>` to the action
  dimension; object scope entries accepted with identity = scope string;
  `mode` recognized (wallet-enforced attenuation; verifier treats it as the
  wallet's word, per design §5) and unknown parameters still fail closed.
  Empty-scopes v1 warrants (today's popup output) keep working during the
  transition.
- [ ] sbo-daemon: **implement warrant/access/config status-ref checking,
  fail-closed** — fetch + cache the status lists named by
  `verified.{access,config,warrant}_status` in `validate.rs` (pattern:
  `browserid-ng/browserid-rp/src/lib.rs:142-268`, `require_status_checks`).
  Without this, revocation is a no-op and the /account Revoke button lies.
- [ ] mingo: bump the `sbo-core` git rev (`mingo/Cargo.toml:31`); deploy the
  daemon (`make deploy`, verify prod).
- [ ] Audit any other `verify_device_attribution` callers for status checks
  (`sbo-capture/src/lib.rs:539` is test-only; sweep for new ones).

## Phase 3 — broker: consent ceremony + wallet enforcement

The M9 fix proper. The popup loses warrant-authoring authority; the dialog
gains the standard-card ceremony that mints the durable record.

**Shared mint module**
- [ ] Extract `localConfig` + `signWarrantV2` from `consent.html:139-190` into
  `static/common/js/warrant-mint.js`; consent.html and the dialog consume it
  (authorize.html's duplicates can migrate opportunistically).
- [ ] CSP: any inline-script edits in dialog.html/consent.html need
  `INLINE_SCRIPT_HASHES` updated in `routes/mod.rs` (guard test prints the
  hash); run broker tests before deploying.

**Request protocol (RP declares audience/scopes at consent time)**
- [ ] `include.js:913` + the four dialog intake lanes
  (`dialog.js:2674/2903/2917/2934`): `sboSign` becomes
  `{ audiences: [...], scopes: [...] }` (boolean `true` no longer mints
  anything — pre-launch, mingo is the only caller). Carry the object through
  the `pending.dialog` persistence points (`dialog.js:1268/1567/1845` and
  re-reads at `:1430/1691/1968`) so it survives primary-IdP round trips.

**Consent card + record mint**
- [ ] `dialog.html:355-366` sbo-consent-screen → standard consent-card copy:
  "**{site}** will sign posts on the SBO network as **{email}**, to
  `<database>`", with per-scope verbs (posts silently, deletes with a prompt).
- [ ] Approve (`dialog.js:2662`): per audience — allocate a status idx +
  register via the registrar (`/wsapi/allocate_warrant_status`,
  `/wsapi/register_warrant`; verify they're callable from the dialog's session
  context, add a thin broker endpoint if not), sign one v2 record with the
  config key (binding `[{holder: <this device's holder>}, {requester:
  state.origin}]`, audience, scope entries with `mode`), store the JWS in
  `siteInfo[state.origin].signing_grants` (keyed by audience; `siteInfo` is
  the popup-visible first-party store, preserved by `keystore.js:128-130`).
- [ ] Registrar rendering: record kind `"signing"`; `list_warrants`
  (`consent.rs:882`) surfaces requester origin, audience, and scope entries
  for /account.
- [ ] Delete the `sbo_sign_granted` machinery (`dialog.js:2167-2186`) and wipe
  stale booleans from `siteInfo` (no migration — decided 2026-08-24).
  `buildResponse` (`dialog.js:2151-2162`) keeps the `sbo_sign_granted`
  response field name, now derived from record presence.
- [ ] Per-device: consent card shows whenever no covering record exists on
  this device (each device signs its own record — design §4 Notes).

**Wallet dispatch (`sbo-signer.js`)**
- [ ] Replace `grantedFor` with stored-record lookup: a record whose grantee
  == `d.email`, audience == `d.audience`, requester entry == `e.origin`,
  holder entry covers this device's holder, unexpired, and whose `sign:sbo:
  <envelope.action>` scope entry exists. Unclassifiable envelope ⇒ refuse.
- [ ] `mode: "prompt"` ⇒ render the envelope in the popup (sign.html gets an
  approve/decline surface) and wait; decline ⇒ `prompt_declined`.
- [ ] **Delete the fabrication block** (`sbo-signer.js:147-151`); assemble the
  presentation with the **stored** warrant JWS.
- [ ] Stamp `req_origin: e.origin` into the fresh assertion
  (`sbo-signer.js:153`).
- [ ] `sbo:grant-info` message: for the asking origin only, return
  `{email, audience, scopes (with parameters), exp}`; uniform empty reply
  otherwise (no oracle).
- [ ] Error vocabulary: `not_granted`, `scope_not_granted`,
  `prompt_declined` (plus existing `bad_request`/`sign_failed`); expired or
  revoked-at-mint records report `not_granted`.

**/account**
- [ ] `account.html:600-608` normalization + `permLineHtml:691-718`: render
  signing-grant rows — `mingo.example ↔ sbo+raw://avail:turing:506/ · sign
  posts as you · Revoke`; Revoke uses the existing `/wsapi/revoke_warrant`
  path (works once `status_idx` is surfaced). The consent copy ("take this
  back anytime") is finally true.
- [ ] Optional (v2nb posture): sign-out revokes this device's signing grants
  (bulk pattern at `account.html:1166-1169`).

## Phase 4 — mingo client

- [ ] `mingo-web/app.js:521` `ensureSigningReady`: request
  `sboSign: { audiences: [CONFIG.dbAudience], scopes: ["sign:sbo:post",
  {scope: "sign:sbo:delete", mode: "prompt"}] }`.
- [ ] Error handling around `signEnvelope` (app.js:620-661, 722-762):
  `not_granted` ⇒ clear signing-ready state and re-run consent;
  `prompt_declined` ⇒ user-facing "you declined" (no retry loop);
  `scope_not_granted` ⇒ surface plainly.
- [ ] Use `sbo:grant-info` to render capabilities honestly (e.g. "delete will
  ask you") — nice-to-have, can trail.

## Phase 5 — verification, deploy, closure

- [ ] Playwright e2e (new spec, pattern `connection-sharing.spec.ts`): consent
  card → record in /account → popup signs a post → delete prompts → revoke →
  next sign refused. Today **nothing** automates the popup path
  (`sbo-sign.test.mjs` covers only pure helpers). Warm the broker on :3000
  first; CI doesn't run e2e — run locally before deploying.
- [ ] Manual pass with `sbo-smoke-test.html`.
- [ ] Deploy order: registrar/broker (phase 1 parsing is compatible, can ride
  early), sbo-daemon (phase 2) **before** the broker consent/wallet flip
  (phase 3), then mingo web. `make deploy` per repo; verify prod after each.
- [ ] Close out: re-verify M9 against `docs/security-audit-2026-07-29.md`
  (popup can no longer author warrants; granted origin's reach = consented
  scope); flip `warrant-use-cases.md` case 5 to live; note the binding-set
  amendment as landed in bean rjmm; complete bean ttn3.

## Decisions taken in this plan (flag if wrong)

1. `sboSign` request param becomes an object; bare `true` is dead (mingo is
   the only caller, pre-launch).
2. `sign:sbo:<action>` maps onto sbo-core's existing action dimension inside
   `scopes_authorize` rather than a parallel checker.
3. The response field stays named `sbo_sign_granted` (client compat), derived
   from record presence.
4. Prompt-mode UI ships in phase 3 (the popup has an interactive surface;
   invariant 9 forbids silently honoring a prompt scope without one).
5. Registrar reuses `register_warrant`/`allocate_warrant_status` + a
   `"signing"` record kind — no new endpoints unless the dialog's session
   context can't reach them.

## Out of scope (per design + bean)

Scope parameters beyond `mode` (counts/rate caps — bean `eodu`), grantee-side
attenuation (bean `0ijs`), other `sign:` kinds, hosted-wallet adoption of the
record shape, host-matcher constraints on delegated records (rjmm §3.4 door).
