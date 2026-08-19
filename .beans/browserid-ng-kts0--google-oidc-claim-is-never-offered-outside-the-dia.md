---
# browserid-ng-kts0
title: Google (OIDC) claim is never offered outside the dialog's new-address path
status: todo
type: bug
created_at: 2026-08-19T16:20:30Z
updated_at: 2026-08-19T16:20:30Z
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
