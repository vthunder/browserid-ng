# Fallback-IdP API v1 (SKELETON — for review)

Status: **draft skeleton**, 2026-08-27. Structure and decisions-to-make;
wire examples and machine-reason enumerations follow once the §10
questions are resolved. Companion to `registry-api-v1.md` — same API
family, same §7 error taxonomy, same independently-implementable bar.

## 1. Overview

The **fallback IdP** is the role that vouches for identities whose
domain runs no IdP of its own: it verifies control of the mailbox
(or of a bridged account) and issues the device + config certs a
holder presents everywhere else (core §4). Today that role is
reachable only through the browser dialog's cookie surface; a native
wallet holding a secondary identity stands on reverse-engineered
`wsapi` calls and a borrowed session (bean d0xb).

This spec defines the fallback IdP's **standalone API**: how a native
client drives the account lifecycle — classify an address, prove the
mailbox, create or recover the account, authenticate, and obtain
device + config certs — with no cookies, no CSRF machinery, and no
weakening of the mint-authorization chokepoint. It also defines the
`browser` object of the support document's `registry` key
(registry-api-v1 §5.5): the ceremony URLs a native client opens for
the steps it cannot, or should not, perform natively.

Primaries never touch this API: a primary identity's issuance surface
is its own IdP's, discovered via `address_info` / DNS (the
device-authorize hop). Only the broker-as-fallback-IdP serves it.

**Relationship to registry-api-v1.** The registry API authenticates
with a presentation→token exchange — usable only once you *have*
certs. This spec covers the step before that: first issuance
necessarily rests on the email-verification ceremony (the
chicken-and-egg is real and this is its floor). After first issuance
a wallet uses the registry API for registry operations; it does NOT
get to use registry tokens for issuance (§3.3, the per-scope gate).

## 2. Actors and terminology

- **Fallback IdP** — the issuing service (the broker today).
- **Client** — a native wallet or agent driving the lifecycle. The
  trusted-user-agent obligations (principle 8) apply to it.
- **Email proof** — a short-lived signed artifact proving a recent
  mailbox-control ceremony for one address (the API sibling of
  today's `fb_email` cookie claim, `browserid-fb-email-v1`).
- **Account credential** — the account's root credential: the
  password (secondaries with `proof=smtp`), or a bridge grant
  (`proof=oidc|atproto`). Derived artifacts (certs, registry tokens)
  are never account credentials.

## 3. Authentication model

Issuance is the most security-sensitive operation in the protocol —
a config cert mints warrants. The model keeps exactly today's bar
(`authorize_mint`, mint chokepoint):

    issue = email proof (mailbox is fresh-verified)
          + account credential (the caller is the account root)

Neither alone suffices; token-lane artifacts never substitute for
either.

### 3.1 Email proof — `POST /api/v1/idp/email/send` + `/verify`

The `/auth/send` + `/auth/verify` ceremony, API-shaped: `send` mails
a 6-digit code (same rate limits and burn-on-guess rules, made
normative here); `verify` returns the signed email-proof **in the
response body** instead of setting a cookie:

    { "email_proof": "<base64(claims).base64(sig)>", "expires_in": … }

Claims: `typ: "browserid-fb-email-v1"`, `email`, `exp`. Stateless,
verified by signature on later calls. OPEN(1): proof lifetime — the
cookie's 30 days is a browser-session convenience; an API artifact
handed to arbitrary native processes should likely live minutes to
hours, not weeks.

### 3.2 Account credential presentation

For `proof=smtp` accounts, the password accompanies the sensitive
calls directly (§5.3) — the API mints **no session**: every
credentialed call carries the credential, is rate-limited like
`authenticate_user` (10 failures / IP / 300s), and anti-hammering
responses are uniform (no oracle for "right password, wrong email
state"). For bridge-proofed accounts the browser ceremony is the
credential (§5.4) — a native client hands off.

OPEN(2): whether to also mint a short-lived *issuance session token*
after one password proof (ergonomics for multi-call flows), or keep
strictly per-call credentials (simpler, no new bearer artifact). Lean:
per-call; the lifecycle is 2–3 calls at most.

### 3.3 Relationship to the registry token family (the per-scope gate)

Registry-api-v1 §10.7 accepted self-issued presentations for the
`registry` scope because that scope excludes every root operation.
This spec's operations ARE root operations, so the gate lands here
with the opposite answer:

- **Registry tokens (any scope) are NOT accepted** for issuance,
  password ops, email add/remove, or account cancel. A derived
  credential must never mint root control: certs derive from the
  password; a cert-derived token that could re-issue certs or change
  the password would close a privilege loop.
- Consequently this spec defines **no new scopes** in the token
  family. If a future revision adds one (e.g. read-only account
  introspection), it must re-justify self-issued acceptance
  individually, per the gate.

## 4. Common conventions

Registry-api-v1 §4 applies wholesale (JSON bodies, no `success`
boolean, unknown-field rejection, pure GETs, RFC 3339, §7 error
envelope). Additions:

- **Anti-enumeration is normative.** Responses on the unauthenticated
  lanes are byte-identical whether or not an account exists
  (`stage`-shaped calls always succeed; `verify`-shaped calls fail
  only on code mismatch). The M7 posture carries over as a MUST.
- **No cookies.** Nothing in this API sets or reads cookies; the
  cookie lanes remain as browser siblings sharing the same cores.

## 5. Endpoints (inventory — shapes after review)

### 5.1 Address classification — `GET /api/v1/idp/address_info`

The existing unauthenticated `address_info`, blessed as the API entry
point with a normative response subset: `type`, `issuer`, `disabled`,
`proof`, and (primaries) `device_auth` / `access_mint`. OPEN(3):
whether to also normatively add `issue` (this API's §5.3 URL) and
`browser` hints here, or leave all discovery to the support document.

### 5.2 Account ceremony — create, recover

The signin-code lane (`stage_signin_code` / `complete_signin_code`)
adopted as `POST /api/v1/idp/stage` + `/complete`: it is already
cookie-free, CSRF-free, enumeration-safe, and folds creation and
password reset into one ceremony. Normative here: the reset side
effects (all sessions evicted; sibling SMTP addresses unverified —
kgb9) and the code-guard rules. `complete` returns `204`; the client
then proceeds with §5.3 using the password it staged.

OPEN(4): adopt-as-is under `/api/v1` (lean — shared cores, two
mounts, like bw9q), or spec the existing `/wsapi` paths as-is and
skip the re-mount?

### 5.3 Issuance — `POST /api/v1/idp/issue` (the chokepoint, API-shaped)

Request: `{ email, pass, email_proof, device_pubkey, config_pubkey,
holder? }`. Semantics — the union of today's two lanes, at the
stricter bar of each:

- Gates in order (uniform errors, no oracles): email proof verifies
  and names `email` → account exists and holds `email` verified →
  password verifies (rate-limited) → `authorize_mint` (primary → 403
  delegate; bridge-proofed → 403 with the `browser` handoff reason;
  no password on account → 401 with the set-password handoff reason).
- Issues the device (authentication) + config (authorization) cert
  pair with one holder and per-key status refs, exactly as today.
- OPEN(5): client-supplied `holder` — `/device/issue` accepts one
  (namespace-validated against the account's `browsers` prefix +
  pending-move targets); `/auth/device_cert` always assigns. Lean:
  accept with `/device/issue`'s validation rules (this absorbs bean
  kmvm), because gxi9-style wallets need holder continuity across
  re-issuance.
- OPEN(6): config-cert identity set — `/device/issue` grants
  `[email, local+*@domain]` (sub-address wildcard); `/auth/device_cert`
  grants the exact address only. One behavior must win; the spec
  should pin it and say why.

### 5.4 Browser handoff — the `registry.browser` keys (fills the §5.5 reservation)

The ceremonies a native client MUST NOT replicate natively open in
the system browser at URLs discovered under the support document's
`registry.browser` object. Proposed key set (each optional; a client
treats a missing key as "ceremony unavailable"):

| Key | Ceremony | Why not native |
|---|---|---|
| `account` | Account management page (`/account`) | Full account surface; already exists |
| `claim` | Bridge-proof ceremonies (OIDC / atproto claim) | Top-level navigation + third-party auth by construction |
| `set_password` | First password on a no-password account | OPEN(7): today needs a session (`set_password` + csrf); native alternative would be email-proof + new password over this API — decide native vs browser |
| `recover` | Guided recovery for locked-out states | Wraps §5.2 with human explanation |

Email add/remove and account cancel stay browser-side (via `account`)
in v1 — deliberate scope cut; revisit on demand.

### 5.5 Explicitly NOT issuance-adjacent

`access/mint` (per-login access certs) is core §5 and already
API-shaped with its own replay guard; unchanged and out of scope.
Same for `/verify` and the status list (public, core §6).

## 6. Out of scope (and why)

- **Primary issuance** — the primary's own IdP's business
  (device-authorize hop, core §4/§7).
- **Registry operations** — registry-api-v1.
- **Session/cookie lanes** — remain the browser siblings, sharing
  cores so bars cannot drift; nothing here retires them.
- **Email add/remove, account cancel, OIDC directory sync** — browser
  ceremonies in v1 (§5.4).

## 7. Errors

Registry-api-v1 §7 taxonomy verbatim (envelope, status codes,
`reason` field, 429 + `Retry-After`). New machine reasons to
enumerate after review, expected set: `email_proof_invalid`,
`email_proof_expired`, `credentials_invalid` (uniform across
wrong-password/no-account — anti-enumeration), `password_required`
(no-password account → `set_password` handoff), `bridge_required`
(bridge-proofed account → `claim` handoff), `delegate_to_primary`.

## 8. Versioning and conformance

Same rules as registry-api-v1 §8. Conformance classes: **issuer**
(serves §5.1–§5.3 + discovery) and **client**. The `browser` object
(§5.4) is advertised by the issuer's support document; clients MUST
ignore unknown keys.

## 9. Legacy endpoint mapping (appendix, to complete)

| Legacy | This spec | Notes |
|---|---|---|
| `POST /auth/send` / `/auth/verify` | §3.1 `email/send` / `email/verify` | cookie → body artifact |
| `POST /wsapi/stage_signin_code` / `complete_signin_code` | §5.2 `stage` / `complete` | OPEN(4) |
| `POST /wsapi/authenticate_user` | (none) | The API mints no sessions; §3.2 |
| `POST /device/issue` | §5.3 `issue` | csrf+session → proof+password |
| `POST /auth/device_cert` | §5.3 `issue` | superseded; both legacy lanes remain as browser siblings |
| `GET /wsapi/address_info` | §5.1 | blessed subset |
| `GET /wsapi/browser_holder` | (none) | holder continuity via §5.3 `holder` + registry §5.4 assignment |

## 10. Open questions (the review agenda)

1. **Email-proof lifetime** (§3.1): minutes–hours vs the cookie's 30
   days. Lean: short (≤1h), refreshable by redoing the ceremony.
2. **Per-call password vs short-lived issuance token** (§3.2). Lean:
   per-call.
3. **Discovery placement** (§5.1): all in the support document vs
   also inline in `address_info`.
4. **Mount**: re-mount signin-code lane under `/api/v1/idp/*` with
   shared cores, vs blessing existing paths. Lean: re-mount (family
   coherence, one auth/error taxonomy, bw9q precedent).
5. **Client-supplied holder** on issue (absorbs kmvm). Lean: yes,
   with `/device/issue`'s validation.
6. **Config-cert identity set**: `+*` wildcard or exact-only — pin
   one for both lanes.
7. **Set-password**: native (email-proof + new password) vs browser
   handoff. Security note for the discussion: making it native means
   "mailbox control ⇒ can set the password on a no-password account",
   which is already true via the browser ceremony — but the API makes
   it scriptable.
8. **Re-issuance policy**: issuing an additional device for an
   existing account always re-runs the full §3 bar (email proof +
   password). No cert- or token-derived shortcut — confirm as an
   invariant (it is the anti-privilege-loop rule of §3.3).
