---
# browserid-ng-kts0
title: Google (OIDC) claim is never offered outside the dialog's new-address path
status: completed
type: bug
priority: normal
created_at: 2026-08-19T16:20:30Z
updated_at: 2026-08-19T21:16:43Z
---

Report (owner, 2026-08-19): Google addresses are not triggering the OIDC flow. Preexisting — predates the shyj epic.

## Diagnosis (verified against prod + code)

The server side is fully healthy:
- /wsapi/address_info?email=x@gmail.com on prod returns proof:"oidc" + claim:"https://browserid.me/oidc/claim" (state.oidc configured, gmail needs no MX probe).
- /oidc/claim on prod 303s to accounts.google.com with correct client_id/redirect_uri/PKCE.

The gap is that the OIDC ceremony (qer8) was only ever wired into the DIALOG, and only into its unknown/transition_no_password/unverified branches. Surfaces that never offer it:

1. **/account signed-out sign-in — siDiscover (account.html:1506+)**. Checks only info.type==='primary' and state; never reads proof==='oidc'. A gmail address → 'create' (password + SMTP code) or, for an existing passwordless account, a mailed reset code. The broker root (/) redirects to /account, so this is the PRIMARY entry point — likely the reported repro. Note siDiscover already routes primary addresses through the dialog (rp_redirect=1&login_hint=…&state=acct) because the page's strict CSP can't run the ceremony; the same routing works for proof==='oidc'.

2. **/account add-address — ae-send (account.html:1242)**. Checks info.proof==='atproto' (openHandleClaim popup) but not 'oidc'. A gmail add runs the SMTP loop → the record lands proof=Smtp — which post-epic (shyj) permanently classifies it E3: password-gated mints, 90d broker certs, unverified on password reset. Proven by Google it would be E2: bridge-delegated, ~7d voucher TTL, untouched by reset. The ceremony choice now changes the address's durable provenance class, so this gap has real security/UX weight it didn't have pre-epic.

3. **Dialog, state==='known'** (gmail account that already has a password — e.g. every grandfathered proof=Smtp gmail record): shows the password screen by qer8 design ("a 'known' identity with a password still gets the password screen"). Combined with 1+2, this means an EXISTING gmail user is never offered Google sign-in by any surface — and since attach_verified sets proof=Oidc on a fresh claim ("freshly proven, whatever its history"), the missing offer is also the missing E3→E2 upgrade path for grandfathered records.

## Constraint for the fix
The OIDC callback's resume leg is dialog-only (oidc.rs RESUME_PATH = /dialog/dialog.html?resume=oidc_claim; result broadcast on OIDC_RESUME_CHANNEL which only dialog.js joins). So either route /account entries through the dialog (the existing primary-address pattern in siDiscover), or give /account an atproto-style popup+BroadcastChannel listener (openHandleClaim is the template; attach_verified already attaches to the signed-in session when the callback carries the session cookie).

## Suggested fix shape
- siDiscover: if info.proof==='oidc' (and state unknown/transition_no_password/unverified — arguably also passwordless-known), route through the dialog like primaries.
- ae-send: if info.proof==='oidc' && info.claim, run an openHandleClaim-style popup to /oidc/claim?email=… with an /account-side OIDC_RESUME_CHANNEL listener, then reloadAccount.
- Optional (design decision): offer "Sign in with Google instead" on the dialog's known-with-password screen for proof==='oidc' addresses, which would also upgrade grandfathered E3 gmail records to E2 on first use.

## Tests to add with the fix
- No OIDC e2e spec exists at all (needs mocked Google); at minimum, unit-test the /account routing decisions and an integration test that attach_verified upgrades proof Smtp→Oidc on re-proof (already implicitly covered) plus the account-side listener wiring.

## Summary of Changes (2026-08-19)

All three surfaces fixed, plus a server-side reclaim-table rework the investigation surfaced.

**Server — attach_verified cold-claim arm (oidc.rs), the load-bearing piece**
- Same Google subject as before → sign in (unchanged; the E2 no-password experience).
- PASSWORD-BACKED account → refuse with PasswordRequired (callback maps it to the stable resume reason 'password required'). Previously this arm TRANSFERRED the address to a fresh account — which, combined with pr3a's bridge-first dialog routing, would have orphaned a grandfathered Smtp-proven gmail on the owner's own sign-in attempt. Mailbox proof alone neither signs in nor re-binds; a genuinely new mailbox holder's channel stays the reset flow (kgb9).
- PASSWORDLESS + Smtp-proven record → sign into the owning account and upgrade the proof (mailbox continuity — same authority, stronger ceremony) instead of orphaning the account.
- Oidc record under a different subject (passwordless) → transfer to fresh account (unchanged: identifier changed hands).
- Deliberately NOT mirrored to handle_claim: for handle domains the DID binding outranks the broker password (tsqk/xcy6 — mailed resets are refused there, the bridge is the only re-proof channel), so a new DID holder must take the identity even from a password-backed account. Documented in the cold arm; the existing a_new_holder_gets_the_identity test pins it.

**Dialog (case 3 + step-up)**
- email-form 'known' branch now mirrors the chooser: proof oidc/atproto → bridge-first (cached device pair short-circuits).
- passwordStepUpForClaim: a claim refused with 'password required' (popup AND redirect lanes) shows the password screen with an explanatory hint ('confirm your password once to link Google…'); after auth, state.pendingClaimAfterAuth re-runs the claim under the session → attach arm links the record (Smtp→Oidc, E3→E2), records the bridge grant, and completeSignIn mints with the bridge's 7d TTL. Stale step-up state cleared on every fresh email flow.

**/account (cases 1 + 2)**
- siDiscover: proof oidc/atproto routes through the dialog (the existing primary-address rp_redirect hop) — the dialog owns claim/step-up/link for every state and returns with the broker session.
- ae-send: new openOidcClaim popup (mirror of openHandleClaim) — /oidc/claim with the session cookie riding along attaches to THIS account as proof=oidc (E2), instead of an SMTP code that would freeze the address as E3; completion via the dialog resume page's BroadcastChannel with gmail-normalized email matching. INLINE_SCRIPT_HASHES updated.

**Tests** (oidc_claim_test.rs +4; full suite green)
- Cold claim of a password-backed Smtp record → 'password required', record untouched (pre-fix: transferred).
- Password-confirmed claim → record upgrades to Oidc on the same account, and /device/issue mints with the 7-day bridge TTL end-to-end (the owner's requested upgrade path).
- Cold claim of a passwordless Smtp record → signs into the owning account, proof upgraded (pre-fix: transferred/orphaned).
- Cold reclaim, password-backed + new Google subject → refused, record + subject untouched.

## Follow-up (2026-08-19, evening): upgrade never triggered under a LIVE session

Owner repro post-v2nb: typed gmail in the dialog → instant sign-in, no Google, no password. Deployed code verified byte-identical to source; every cold path would have shown Google or the password screen — so the browser holds a live broker session (from the /account password sign-in earlier; 30d TTL). Under a session the flow is: 'known' → cached pair → completeSignIn → authenticated → mint from cached cert. Correct per v2nb (session exists), but the E3→E2 upgrade only lived on the COLD path — under a session, cached pre-epic certs (or plain full-session E3 issuance) suppress the upgrade until cert expiry.

Fix (the upgrade nudge):
- list_emails now exposes per-address proof methods to the owning session (proofs: [{email, proof}]).
- completeSignIn's authenticated path: when the DOMAIN ceremony is oidc/atproto but the RECORD proof is smtp (and the address is not an agent/derived identity — those ride their parent), drop the cached pair and run the bridge claim under the session. No password prompt — the session already owns the account; the attach leg links the record (E3→E2) and the re-entry issues fresh E2 certs redeeming the bridge grant. Self-extinguishing: record reads oidc/atproto after the first upgrade.
- Verified: broker suite green (+ list_emails proofs test); full Playwright e2e 105/105.

## Follow-up 2 (2026-08-19, night): certs must never outlive their provenance class

Owner repro #3: picked gmail from the chooser → instant sign-in. Server access-log forensics (nginx:access-logs is a ~20-line tail — earlier 'no /oidc/ hits ever' reasoning was void): the nudge RAN (its address_info+list_emails calls are in the trail) and DECLINED, meaning the record already read oidc — a silent Google hop (live Google session → no visible OAuth screen) had already upgraded it in an earlier attempt. The cached pre-upgrade 90d cert then kept signing in: 'valid credential until expiry' by the letter of the model, but exactly the cached-cert-outlives-policy surprise the owner called out.

Structural fix (round 4):
- **Revoke on provenance-class upgrade**: attach_verified / complete_handle_claim revoke the address's existing broker certs (revoke_user_certs_for_email) whenever an owned record's proof class changes to the bridge class (Smtp→Oidc / non-Atproto→Atproto). Same-class re-proofs leave certs alone; transfers already revoke (hg2j). With hg2j (transfer), v2nb (sign-out), and this (upgrade), every event that changes a cert's authority now kills the cert.
- **Dialog self-heal**: completeSignIn catches a mint refusal matching revoked/expired, drops the dead cached pair, and re-enters once — issuance then runs the correct ceremony for the address's current provenance.
- Test: the upgrade test now issues a pre-upgrade E3 cert first and asserts it is refused 'revoked' at /access/mint after the claim. Cargo suite + e2e 105/105 green.

Note for the owner's browser: the record upgrade already happened, but the stale cert on that machine predates revoke-on-upgrade — one /account sign-out (which now revokes, v2nb) or manual cert revocation clears it; after that every sign-in is the pure E2 ceremony.

## Follow-up 3 (2026-08-19, late): swap-at-next-use — certs checked against the record's CURRENT class

Owner requirement: when an address's class upgrades E3→E2 (record upgrade, or broker gaining OAuth support for a domain followed by a re-proof), existing E3-era certs must be SWAPPED at their next use — never left valid until expiry, never manually cleared.

Mechanism:
- New optional `prov` claim on DeviceCertClaims (browserid-core): the proof class the identity was verified under at issuance. skip_serializing_if None → golden wire vectors unchanged; old certs parse fine and read as "smtp". New create_with_provenance constructor; create() delegates with None.
- Broker issuance stamps it: /device/issue (owned_mintable_email now also returns the record's proof class) and /auth/device_cert. Tenant-primary (/idp/*) certs stay unstamped — the tenant is the voucher; broker classes don't apply.
- **/access/mint provenance-freshness gate**: for an identity whose record is E2 (Secondary + Oidc/Atproto), a broker cert whose issued-under class doesn't match is refused with 'predates this address's current verification method and is now revoked — sign in again to reissue' AND its status bit is flipped (sticky). The dialog's existing revoked/expired self-heal drops the pair and re-issues via the bridge — the automatic swap. E3/agent records and unknown identities skip the gate.
- This retro-covers every legacy cert (incl. the owner's) with zero manual steps: legacy = no prov = smtp-class → dies at next mint once the record reads E2.

Also fixed during this round: a blind spot in my own verification — cargo's COLORED 'error[...]' lines don't match grep '^error', so a compile failure had read as a green suite. All checks now run CARGO_TERM_COLOR=never and got a positive green count (59 suites ok). hosted_idp/device tests literal fixes for the new field.

Tests: stale_class_cert_is_refused_and_revoked_at_next_mint (E3 cert mints → store-direct upgrade to Oidc → next mint 403 revoked+reissue → stays dead); bridge cert stamped prov='atproto' and passes the gate (bridge_mint_test); golden vectors unchanged. Workspace 59 suites green; Playwright e2e 105/105.
