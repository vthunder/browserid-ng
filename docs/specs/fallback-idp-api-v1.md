# Fallback-IdP API v1 (draft skeleton)

Status: **draft**, 2026-08-27. Flows and shapes for review; wire
examples and machine reasons come after the §6 questions are settled.
Same family as `registry-api-v1.md`: same error taxonomy, same
independently-implementable bar. No cookies, no CSRF, no sessions.

**What this is.** How a native wallet gets a secondary identity's
device + config certs from the broker (acting as fallback IdP)
without driving the web dialog. Primaries never touch this API —
their issuance belongs to their own IdP (the device-authorize hop).

**The one rule everything follows.** Issuance requires BOTH:

    a fresh email proof   — "I control this mailbox right now"
    + the password        — "I am the account root"

Certs and registry tokens are *derived* from the password, so they
can never substitute for it here — otherwise a stolen cert could
mint more certs (privilege loop). Registry tokens are refused on
every endpoint in this spec.

## 1. The flows

Four flows cover the whole lifecycle. A, B, and D are three entries
into the same last step; C is the handoff case.

### A. New user — first wallet setup

1. `GET  address_info?email=`            → `type: "secondary"` (else: primary hop, not this API)
2. `POST idp/stage    {email, pass}`     → 204 — a 6-digit code is mailed
3. `POST idp/complete {email, code}`     → `{email_proof}` — account created
4. `POST idp/issue    {email, pass, email_proof, device_pubkey, config_pubkey}`
                                         → `{device_cert, config_cert}`
5. Wallet silently joins the registry (registry-api-v1 §3). Done.

One code ceremony total: `complete` proves the mailbox, so it hands
back the same `email_proof` artifact the standalone ceremony (flow B)
produces.

### B. Existing user, knows the password — new device

1. `GET  address_info?email=`             → secondary
2. `POST idp/email/send   {email}`        → 204 — code mailed
3. `POST idp/email/verify {email, code}`  → `{email_proof}`
4. `POST idp/issue …`                     → certs (same call as A.4)

### C. Bridge-proofed address (gmail via OIDC, atproto handle)

These accounts have no password; their root credential is the bridge
ceremony, which is a top-level browser navigation by construction.
v1 keeps them browser-side: `idp/issue` answers
`403 reason: "bridge_required"` and the client opens the `claim` URL
from discovery (§4). Native bridge issuance is a later revision.

### D. Forgot password — recovery

Identical to flow A: `stage` + `complete` reset the password when the
account exists (and the responses never reveal which case occurred —
anti-enumeration). Known side effects, kept normative: every session
dies and sibling SMTP addresses are un-verified (kgb9). Then A.4.

## 2. The endpoints

Six, all under `/api/v1/idp/`. Legacy siblings stay mounted for the
browser; both lanes share one core each so the bars cannot drift
(the bw9q pattern).

| Endpoint | Auth | Does | Legacy sibling |
|---|---|---|---|
| `GET address_info` | none | classify: primary / secondary / bridge-proofed | `/wsapi/address_info` (blessed subset) |
| `POST stage` | none | mail a code; stage account-create-or-password-reset | `/wsapi/stage_signin_code` |
| `POST complete` | code | create account / reset password; returns `email_proof` | `/wsapi/complete_signin_code` (which returns nothing) |
| `POST email/send` | none | mail a code (no account changes) | `/auth/send` |
| `POST email/verify` | code | returns `email_proof` | `/auth/verify` (which sets a cookie instead) |
| `POST issue` | `email_proof` + `pass` | mint the device + config cert pair | `/device/issue` (session+csrf) and `/auth/device_cert` (cookies) — superseded by one call |

Rules that carry over unchanged (normative in the full draft):
existing rate limits (code sends, guess-burning, login-failure
throttle), uniform anti-enumeration responses, per-key status refs on
issued certs, `authorize_mint` as the unchanged chokepoint behind
`issue`.

`issue` details to pin during review: client-supplied `holder`
(§6 Q3) and the config-cert identity set (§6 Q4).

## 3. The `email_proof` artifact

The signed claim today's `fb_email` cookie carries
(`browserid-fb-email-v1`: `email`, `exp`), returned in the response
body instead of a cookie. Stateless; verified by signature at
`issue`. Proposed lifetime: **≤ 1 hour** (the cookie's 30 days is a
browser convenience that has no business in a portable artifact —
§6 Q1).

## 4. Browser handoff (fills registry-api-v1 §5.5's `browser` object)

What a native client opens in the system browser, discovered from the
support document:

| Key | Opens | Used by |
|---|---|---|
| `account` | the account page | menu shortcut; email add/remove, cancel — browser-only in v1 |
| `claim` | bridge-proof ceremony | flow C |
| `recover` | guided recovery page | optional human-friendly wrapper around flow D |

Clients MUST ignore unknown keys; a missing key means "ceremony not
offered here".

## 5. Errors

Registry-api-v1 §7 verbatim. New `reason` values (enumerated fully
later): `credentials_invalid` (one uniform answer for wrong password
/ no account / wrong state — no oracles), `email_proof_invalid`,
`password_required`, `bridge_required`, `delegate_to_primary`.

## 6. Open questions

1. **`email_proof` lifetime** — lean ≤ 1h, refresh by redoing the
   ceremony.
2. **Password handling at `issue`** — per-call (lean: the whole
   lifecycle is ≤ 2 credentialed calls) vs minting a short-lived
   issuance token after one proof.
3. **Client-supplied `holder` on `issue`** — lean yes, with
   `/device/issue`'s validation (browsers-namespace or pending-move
   target); absorbs bean kmvm and gives wallets holder continuity.
4. **Config-cert identity set** — `/device/issue` grants
   `[email, local+*@domain]`, `/auth/device_cert` grants the exact
   address only. Pin one for both lanes.
5. **Re-issuance invariant (confirm)** — another device on an
   existing account always re-runs the full bar (proof + password);
   no shortcut via existing certs or tokens.
