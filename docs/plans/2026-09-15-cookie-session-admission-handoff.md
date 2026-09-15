# Handoff: the issuer's cookie session must not reveal more than the registry admits

Written 2026-09-15 at the end of the session that shipped the add-a-device
bar (epic 0vdu, docs/plans/2026-09-14-account-authentication-policy-draft.md).
Resume from the bean named at the bottom; this note is the context.

## The problem

A sign-in at the issuer opens a browser cookie session on the account
(`auth_with_presentation` for a primary or bridged identity, or the
password) *before* the registry decides whether this device may join the
account. If the add-a-device step is then cancelled or abandoned, the
session outlives it. On the next open, the dialog saw an authenticated
session and listed every address on the account. Dan hit this in an
incognito window on 2026-09-15.

A client-side gate shipped the same day (commit "the account's address
list shows only on a browser the registry has admitted"): the dialog
lists addresses only when this browser holds a registry login key for the
session's account, remembers nothing otherwise, and a failed add-a-device
step ends the session it opened. That closes the visible hole but not the
real one: the issuer's cookie endpoints still answer any session that
proved one identity, admitted or not.

## The rule to build

**A cookie session reveals and manages the account only once it is bound
to a login key the registry has enrolled on that account.** Until then it
is an *identity session*: it can do issuer-role work for the identity it
proved, and nothing account-wide.

This is the same idea the account page already lives by (a keyless device
that logs in to the registry with its own key and signs out without one),
applied to the sessions themselves and enforced where the data is served.

## Design

1. **Session gains a binding.** `sessions` gets `login_key_id INTEGER NULL`
   (schema v47; `Session` model, both stores, `SessionContext.admitted`).
   Unbound sessions keep working for the identity-role calls below.

2. **A bind call.** `POST /wsapi/session_admit` with the registry's
   `Authorization: Bearer` + `Proof` header by the login key (the same
   §4.4 path `/device/issue` accepts since bean 73ok, via
   `state.registrar` and `verify_session_call`). Checks: the registry
   session's account is the cookie session's account; the key is live.
   Sets `login_key_id`. Idempotent. The dialog calls it right after
   `Registry.ensure()` succeeds (registry-session.js already has the
   token and key; add `Registry.admitSession()`), and the account page
   after its keyless login. `/wsapi/logout` and a revoked key (the
   registrar's `end_sessions_on_login_key` plus a new
   `unbind_sessions_on_login_key`) clear it.

3. **Gate the account-wide cookie endpoints on `admitted`.** Refuse with a
   new `403 not_admitted` (dialog and account page treat it like
   `login_required`):
   - `list_emails`, `parent_of`, `browser_holder`, `set_parent`,
     `set_public_name`, `remove_email`, `account_cancel`,
     `update_password`, `issuer_revoke_url`
   - `session_context`: keep `authenticated`, `csrf_token`, `domain`,
     `cookies`; return `account` and `email` only when admitted; add
     `admitted: bool`.
   - `address_info`: the owning-session disclosure of `state`
     (unverified / transition) only when admitted.
   - `stage_email` (adding a *new* address): admitted only. Re-verifying an
     address the session itself proved stays open (see 4).

4. **Keep the identity-role endpoints keyless, but scoped to the proven
   identity.** Record on the session which identities it proved
   (`proved_emails TEXT` JSON on `sessions`; `authenticate_user` records
   every broker-vouched address since the password proves them all;
   `auth_with_presentation` records the presented one; bridge claims
   record theirs). Then:
   - `/device/issue` (cookie form) issues only for a proved identity when
     unadmitted; any identity of the account when admitted (today's
     behaviour). The hosted-primary issuance path (`hosted_idp`) is a
     separate session model; leave it.
   - `stage_email` / `complete_email_addition` for a re-verify of a proved
     identity stay open; `set_password` (first password on a passwordless
     account) stays open, since it is the thing that lets the device pass
     the bar.
   The mint chokepoint (`mint.rs`) is unchanged; this is ownership scope,
   not provenance.

5. **The dialog's order of operations.** Today the primary flow is
   `ensureBrokerSession → recordParentHint → reconcileBrowserHolder →
   finishSignIn (registry step)`. `reconcileBrowserHolder` calls
   `browser_holder`, which will need admission. Move the registry step
   ahead of it: `finishSignIn`'s `Registry.ensure()` then `admitSession()`,
   then reconcile. Check the same for the bridge and password paths (six
   `API.listEmails` call sites in dialog.js, two in account.html). The
   pick-email screen and the remembered-chooser cache then key off
   `session_context.admitted`, replacing the `Registry.hasLoginKey()`
   client gate added on 2026-09-15 (keep the gate until the server one
   lands; remove it in the same change).

6. **Spec.** fallback-idp-api-v1 §3.2 gains a sentence: an issuer that is
   also the registry MUST NOT let an issuer session read or manage the
   account beyond the identity it proved until the device is enrolled;
   registry-api-v1 §4.3 already says the registry session is the whole
   check. Note the `session_admit` call as broker-private (`/wsapi`),
   consistent with the API-surface principle.

## Tests to expect to touch

- 12 Rust and Playwright files call `/wsapi/list_emails` under a bare
  cookie session (`grep -rl list_emails browserid-broker/tests
  e2e-tests/tests`). Most create a user with the password and read the
  roster; give the shared helpers a `admit_session` step (a login key +
  registry login + bind) or read the roster through the registry session
  (`GET /api/v1/…` in `registry_api_test.rs` has `session_call`).
- New Rust tests: an `auth_with_presentation` session cannot list, issue
  for a sibling identity, or stage a new address; can issue for its own
  identity and re-verify it; after `session_admit` it can do all of it;
  logout and key revocation unbind.
- Playwright: the transition test already expects the email entry on an
  unadmitted session; add one where an admitted session shows the list.
- SqliteStore round-trip for the new columns (memory-store tests do not
  see schema; see memory note sqlite-only-constraints).

## Gotchas from this session

- Cargo runs through `ssh localtest`; strip ANSI before grepping.
- Editing `account.html`'s inline script changes its CSP hash; the guard
  test prints the new one.
- Playwright needs the local broker rebuilt and running on :3000 first
  (`cargo run` via ssh, poll `/.well-known/browserid`); the suite is at
  130 passed, 15 skipped. `primary-idp … iframe loading failure` and the
  `remove-email` specs flake under load; rerun with `--last-failed`.
- Multi-identity accounts in tests: reset and identity-proof logins now
  wait for a second proof; pin `set_account_policy(uid, {"proofs":1})` or
  drive the second proof.

Size: two to three days including the test migration. Bean: see the
epic 0vdu status; the bean is **160l**.

## Outcome (2026-09-15, bean 160l built)

Built as designed, with three deliberate departures:

- **`browser_holder` stays open** to any authenticated session. The
  browsers-namespace prefix is an opaque id an identity session learns
  anyway from the holder of the cert it is issued, and issuing under it
  *before* the registry step is what keeps one browser one device — a
  gate here gave every pre-admission password sign-in a fresh
  broker-assigned holder. The dialog also caches a broker-assigned holder
  under its prefix on first contact.
- **`session_context.account` stays visible** to an unadmitted session.
  It is the handle the device logs in to the registry with — the very
  step that admits it — and reveals nothing else. `admitted` and
  `proved_emails` were added instead of an `email` field.
- **`address_info` discloses `state` to the session that proved the
  address**, admitted or not: the unverified / transition lanes for a
  proved identity are issuer-role work (rule 4), and the dialog's
  set-password chain reads the passwordless state from there now.

`session_admit` answers 401 (no cookie session) as "nothing to admit" on
the client; the dialog's init binds a not-yet-bound session silently by
the stored key (`Registry.admitSession({ storedOnly: true })`), never
interactively. Test helpers: `create_user` now admits; `create_user_unadmitted`
and `registry::admit_session` / `admit_with` cover the rest. The Rust
coverage is `session_admission_test.rs`.
