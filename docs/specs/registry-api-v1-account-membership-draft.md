# Account membership over the token lane — review draft

Status: DRAFT for review, 2026-08-30 (bean 1sb3). Lands as
registry-api-v1 §5.6 (+ §5.1 request kinds, §7.1 reasons) once agreed.
Replaces §3.1's "no linking in the token lane" (annotated under review).

**The one rule everything below follows:** a token can *raise* a
membership request; only a **client-signed consent record** can
*complete* one. The registry records consent, it never manufactures it —
the same invariant §5.1 already holds for warrants.

Terms: the **anchor pair** is any device pair for an identity the
account already owns; an **anchor token** is a §3 token minted from it.

## 1. The flows

### Flow A — add a second identity to your account (attach)

The wallet holds an anchor pair for `a@one.com` (account **A**). The
user adds `b@two.com`, which no account owns yet.

1. Wallet runs issuance at `b`'s issuer (its sign-in page, fallback-IdP
   spec §3) → a fresh device pair for `b`. Control of `b` is now
   issuer-attested by the certs.
2. Wallet, authed by the **anchor token**:
   `POST /api/v1/account/attach { device_cert, config_cert }` (the new
   pair). The registry verifies both certs to the §5.3 bar (issuer
   acceptance, expiry, fail-closed status, shared holder). `b` unowned ⇒
   a **pending attach** is created and a `kind: "attach"` request
   appears in A's §5.1 inbox. Response: `{ code, expires_at }`.
3. A human approves on a trusted surface of A (another wallet's inbox,
   the account page — or this wallet itself, see Q1): approval signs an
   **attach record** (§3 below) with an account config key.
4. Registry completes: `b` joins A; the new pair's rows are recorded
   with full `devices/register` semantics (healing, labels, idempotent).
5. The wallet polls `GET /api/v1/account/attach/status?code=` (anchor
   token) → `pending | granted | denied | expired`. On `granted`, a
   token minted from the `b` pair now resolves to A.

Without step 3–4, nothing changed: an anchor token alone never grows an
account. (First-ever bootstrap is unchanged: the §3.1 exchange still
creates a fresh account for a never-seen identity — attach is only for
joining an existing one.)

### Flow B — the identity belongs to another account (transfer)

Same steps 1–2, but `b@two.com` is owned by account **B** (the user is
pulling their email into a new account; they proved mailbox control to
the issuer, so certs exist regardless of registry bookkeeping).

- The request raises in **B's** inbox as `kind: "release"`: "Release
  `b@two.com` to another account?" — completing it needs B's signed
  **release record**. The raising call itself is A's admit (it carried
  A's anchor token and the verified pair), so no second A-side ceremony
  (Q4).
- On release: `b` leaves B — B-side registry rows for `b` are dropped
  and every warrant with grantor `b` under B is revoked (status bits
  flipped; B no longer speaks for `b`) — then joins A as in Flow A.
- Refused outright when `b` is B's **last** identity (`last_identity`,
  409): release would strand the account. B empties it deliberately or
  the transfer waits.
- Denial and expiry leave B untouched; requests are code-bound,
  rate-limited per target identity, and carry only what B needs to
  decide (the identity + requesting device's holder label — not the
  requester's other identities).

### Flow C — remove an identity (detach)

1. Wallet (any of the account's tokens):
   `POST /api/v1/account/detach { identity }` → a `kind: "detach"`
   request in the account's own inbox (even self-service is a signing
   ceremony, per the one rule).
2. Approval signs a detach record; the registry then revokes the
   identity's device certs it is authority for, revokes warrants with
   that grantor, and removes the identity.
3. Refusals: `last_identity` (409); `has_derived_identities` (409 — an
   identity with live agent children detaches only after they go, v1).

## 2. Endpoints

| Endpoint | Auth | Body → response |
|---|---|---|
| `POST /api/v1/account/attach` | anchor token | `{device_cert, config_cert}` → `200 {code, expires_at}`; §5.3 cert bar, else `422 invalid_cert` |
| `GET /api/v1/account/attach/status?code=` | anchor token | → `{state: pending\|granted\|denied\|expired}` |
| `POST /api/v1/account/detach` | any account token | `{identity}` → `200 {code, expires_at}` |
| approvals | §5.1 `requests` / `requests/respond` | new kinds `attach` / `release` / `detach`; respond carries the signed record + `config_cert` |

Pending TTL: RECOMMENDED **1 hour** (approval may mean walking to
another device; a 15-minute code window is too tight — Q3). One pending
attach per (account, identity); re-raising replaces it.

## 3. The consent records

Same JWS discipline as everything else (`typ`-separated, client-signed,
config-key-rooted). One record type, three actions:

```json
{ "typ": "browserid-membership-v1",
  "action": "attach" | "release" | "detach",
  "iat": …, "exp": …,
  "grantor": "an identity the APPROVING account owns",
  "subject": "b@two.com",
  "subject_config_key": "<the new pair's config pubkey (attach/release); absent on detach>",
  "code": "<the pending request's code>" }
```

Validation at respond: signature verifies against the supplied config
cert; that cert is `purpose: authorization`, unexpired, unrevoked, and
authorizes `grantor`; `grantor` is owned by the approving account
(A for attach/detach, B for release); `subject`, `subject_config_key`,
and `code` match the pending request exactly. `exp` short (≤ 1 h) — the
record is consumed once, never stored for reuse.

## 4. Threats and the self-issued gate

- **Stolen config key (no password).** The thief can already act within
  registry scope; the danger attach adds is a foothold that *survives
  revoking the stolen device* (their own identity, their own certs).
  The signing ceremony alone doesn't stop them — they hold a signing
  key. Proposed bar (Q1): when the account has **≥ 2 active devices**,
  the attach record MUST be signed by a *different* config key than the
  anchor pair's — a second device is the second factor. Single-device
  accounts allow self-approval (there is no second factor to demand;
  the ceremony still stops drive-by/CSRF-shaped abuse), accepting that
  a single-device key theft can grow the account until the theft is
  noticed and the device revoked — at which point the attached identity
  is visible on the account page and detachable.
- **Thief detaches identities (lockout).** Bounded by `last_identity`,
  and recoverable: the owner re-proves the mailbox at the issuer and
  re-attaches. Detach therefore keeps the plain signing-ceremony bar
  (Q2).
- **Transfer phishing.** A release request proves the requester holds
  fresh issuer certs for the identity — i.e. current mailbox/bridge
  control. B's decision is "is that me, migrating?"; the card says so
  plainly. Rate-limited, code-bound, expires.
- **Self-issued presentations** (the §3.1 per-scope gate): acceptable
  for *raising* requests — raising mutates nothing. Completion rests on
  the signed record plus (attach, multi-device) key independence, so
  the token's provenance is never load-bearing. Password and email
  root ops remain IdP-side and untouched.

## 5. §7.1 additions

With `conflict` (409): `identity_owned_elsewhere` is **not** emitted —
attach of a foreign-owned identity silently becomes a release request
(existence must not leak; the response is the same `{code}`). New:
`last_identity`, `has_derived_identities`, `attach_pending` (duplicate
raise while one is live — returned with the existing code).
With `invalid_warrant` (422, respond): `record_key_not_independent`
(the Q1 rule), `record_mismatch` (subject/key/code drift),
`record_expired`.

## 6. Decision points (Dan)

1. **Attach approval independence:** ≥2-device rule as proposed / always
   allow self-approval / completion delay window instead?
2. **Detach bar:** plain signing ceremony (proposed) or the attach rule?
3. **Pending TTL:** 1 h?
4. **Transfer:** is the raising call sufficient as A's admit, or should
   A also approve in its own inbox (two approvals total)?
5. **Merge:** deferred to v2 as bulk transfer — agreed?
6. **Cookie-lane parity:** once this lands, the account page's
   add/remove-email UI should route through the same pending-request
   machinery (one bar everywhere) — sequencing with 71vt/ig9p.
