# Account membership over the token lane — review draft

Status: DRAFT r2, 2026-08-30 (bean 1sb3). Lands as registry-api-v1 §5.6
(+ §5.1 request kinds, §7.1 reasons) once agreed. Replaces §3.1's "no
linking in the token lane" (annotated under review). r2 applies Dan's
ruling: **transfer-on-proof — no release consent** (decision log, §6).

**Two rules everything below follows:**

1. A token can *raise* a membership request; only a **client-signed
   consent record** completes one — the registry records consent, it
   never manufactures it (§5.1's invariant).
2. **Ownership follows the identity's voucher.** Fresh issuer-attested
   proof of an email is proof of *current* ownership; a registry
   account that used to hold the identity cannot block its rightful
   owner — it is **notified**, never asked. (Persona per-email
   semantics, carried over from the shipped implementation — §7 P1.)

Terms: the **anchor pair** is any device pair for an identity the
account already owns; an **anchor token** is a §3 token minted from it.

## 1. The flows

### Flow A — add an identity to your account (attach)

The wallet holds an anchor pair for `a@one.com` (account **A**). The
user adds `b@two.com`.

1. Wallet runs issuance at `b`'s issuer (its sign-in page, fallback-IdP
   spec §3) → a fresh device pair for `b`. Control of `b` is now
   issuer-attested by the certs — the freshest statement of who owns
   the email that exists anywhere.
2. Wallet, authed by the **anchor token**:
   `POST /api/v1/account/attach { device_cert, config_cert }` (the new
   pair). The registry verifies both certs to the §5.3 bar (issuer
   acceptance, expiry, fail-closed status, shared holder). A pending
   attach is created and a `kind: "attach"` request appears in A's §5.1
   inbox. Response: `{ code, expires_at }` — identical whether or not
   the identity currently sits on another account (no existence leak).
3. A human approves on a trusted surface of A (another wallet's inbox,
   the account page — or this wallet itself, Q1): approval signs an
   **attach record** (§3) with an account config key.
4. Registry completes: `b` joins A; the new pair's rows are recorded
   with full `devices/register` semantics (healing, labels, idempotent).
   If `b` was owned by another account, the §1.1 transfer effects run
   first, atomically.
5. The wallet polls `GET /api/v1/account/attach/status?code=` (anchor
   token) → `pending | granted | denied | expired`. On `granted`, a
   token minted from the `b` pair resolves to A.

Without steps 3–4, nothing changed anywhere: raising disturbs no one —
denial and expiry leave every account untouched. (First-ever bootstrap
is unchanged: the §3.1 exchange still creates a fresh account for a
never-seen identity; attach is only for joining an existing one.)

### 1.1 When the identity is owned by another account (transfer)

Same flow — the difference is entirely in step 4's effects. `b@two.com`
sits on account **B**; the prover holds fresh issuer certs, so they own
the email *now* (their mailbox / bridge / primary login — however `b`'s
issuer verifies). On A's approval, atomically:

- **B loses `b`**: its device certs naming `b` for which this registry
  is the revocation authority are revoked — status bits flipped,
  precisely scoped to the (B, `b`) pair (hg2j) — and every warrant with
  grantor `b` under B is revoked. B's tokens bound to those certs die
  fail-closed on next use (the token lane's H2).
- **B is notified, not asked**: an actionless `kind: "notice"` entry in
  B's inbox — "`b@two.com` was claimed into another account" — plus,
  SHOULD, out-of-band notification to B's remaining addresses. The
  previous owner cannot prevent the claim; the registry's job is to
  make it visible immediately.
- **An emptied B is deleted**: if `b` was B's last identity, B's
  remaining devices/warrants are revoked-then-dropped and the account
  removed (shipped behavior; the "migrate my only email to a new
  account" case must work).

Note the E3 fence is upstream and unchanged: the broker's own sign-in
page only issues certs for a mailbox-verified address under a session
that owns it, so control of a password-backed account's inbox alone
cannot produce the pair this flow needs — that channel remains the
reset ceremony (kgb9 + H2), exactly as shipped.

### Flow B — remove an identity (detach)

1. Wallet (any of the account's tokens):
   `POST /api/v1/account/detach { identity }` → a `kind: "detach"`
   request in the account's own inbox (self-service is still a signing
   ceremony, rule 1).
2. Approval signs a detach record; the registry revokes the identity's
   device certs it is authority for, revokes warrants with that
   grantor, and removes the identity.
3. Refusals: `last_identity` (409 — detach has no destination; deleting
   the whole account is `account_cancel`'s job, IdP-side);
   `has_derived_identities` (409 — live agent children first, v1).

## 2. Endpoints

| Endpoint | Auth | Body → response |
|---|---|---|
| `POST /api/v1/account/attach` | anchor token | `{device_cert, config_cert}` → `200 {code, expires_at}`; §5.3 cert bar, else `422 invalid_cert` |
| `GET /api/v1/account/attach/status?code=` | anchor token | → `{state: pending\|granted\|denied\|expired}` |
| `POST /api/v1/account/detach` | any account token | `{identity}` → `200 {code, expires_at}` |
| approvals | §5.1 `requests` / `requests/respond` | new kinds `attach` / `detach` (+ actionless `notice` items); respond carries the signed record + `config_cert` |

Pending TTL: RECOMMENDED **1 hour** (approval may mean walking to
another device — Q3). One pending attach per (account, identity);
re-raising replaces it. Raises are rate-limited per target identity
(C1 spirit: request codes are unguessable, single-target, TTL'd).

## 3. The consent records

Same JWS discipline as everything else (`typ`-separated, client-signed,
config-key-rooted). One record type, two actions:

```json
{ "typ": "browserid-membership-v1",
  "action": "attach" | "detach",
  "iat": …, "exp": …,
  "grantor": "an identity the approving account owns",
  "subject": "b@two.com",
  "subject_config_key": "<the new pair's config pubkey (attach; absent on detach)>",
  "code": "<the pending request's code>" }
```

Validation at respond: signature verifies against the supplied config
cert; that cert is `purpose: authorization`, unexpired, unrevoked, and
authorizes `grantor`; `grantor` is owned by the approving account;
`subject`, `subject_config_key`, and `code` match the pending request
exactly. `exp` short (≤ 1 h); consumed once, never stored for reuse.

## 4. Threats and the self-issued gate

- **Stolen config key (no password).** The thief can already act within
  registry scope; attach adds a foothold that *survives revoking the
  stolen device*. The ceremony alone doesn't stop a key-holder.
  Proposed bar (Q1): with **≥ 2 active devices**, the attach record
  MUST be signed by a *different* config key than the anchor pair's.
  Single-device accounts allow self-approval (no second factor exists
  to demand; parity note — the shipped cookie lane allows a session
  thief the same attach today, §7 P7). Residual risk is visible and
  reversible: the attached identity appears on the account page and
  detaches.
- **Transfer abuse.** Taking an identity requires fresh certs from its
  issuer — current control of the mailbox/bridge/primary login. That IS
  ownership (rule 2); the defense for the previous holder is
  *immediacy of visibility* (inbox notice + out-of-band, revocations
  landing at once), never a veto. An attacker who controls the email
  itself is outside the registry's threat model to stop — same as
  shipped.
- **Thief detaches identities (lockout).** Bounded by `last_identity`;
  recoverable by re-proving at the issuer and re-attaching. Detach
  keeps the plain signing-ceremony bar (Q2).
- **Self-issued presentations** (the §3.1 per-scope gate): fine for
  *raising* — raising mutates nothing anywhere. Completion rests on the
  signed record (+ Q1 independence), so token provenance is never
  load-bearing. Passwords and verification stay IdP-side, untouched.

## 5. §7.1 additions

With `conflict` (409): `last_identity`, `has_derived_identities`
(detach only), `attach_pending` (duplicate raise — returns the live
code). Deliberately absent: any reason distinguishing "identity owned
elsewhere" — attach behaves identically either way (no existence leak;
the transfer happens at completion).
With `invalid_warrant` (422, respond): `record_key_not_independent`
(Q1), `record_mismatch` (subject/key/code drift), `record_expired`.

## 6. Decision log and open points

Resolved (Dan, 2026-08-30):

1. **No release consent — transfer-on-proof.** Fresh issuer attestation
   is proof of current ownership; the previous owner is notified and
   cannot block ("they don't own that email anymore — the best we can
   do is make that visible"). Release request kind deleted.
2. **A-side consent for transfer** is just Flow A's attach approval;
   B-side approval does not exist (falls out of 1).
3. **hg2j + empty-account deletion carried over** (§7 P3/P4): transfer
   revokes the loser's certs for the address, and an emptied account is
   deleted, not protected.

Open (Dan):

- **Q1** Attach approval independence: ≥2-device different-key rule
  (new strictness beyond parity — §7 P7), always-self-approve (exact
  parity), or a completion-delay window?
- **Q2** Detach bar: plain signing ceremony (proposed) or the Q1 rule?
- **Q3** Pending TTL: 1 h?
- **Q4** Merge: deferred to v2 as bulk transfer — agreed?
- **Q5** Agent children on transfer-out: shipped `transfer_email` moves
  the parent and leaves derived agent rows behind on the loser; carry
  that over as-is, or revoke/transfer the children with the parent?
- **Q6** Cookie-lane parity: route the account page's add/remove-email
  UI through this same request machinery once it lands (one bar
  everywhere) — sequencing with 71vt/ig9p.

## 7. Parity with the shipped implementation

Decision-by-decision against the code (`oidc.rs attach_verified`,
`handle_claim.rs`, `primary.rs`, `signin_code.rs`, `email.rs`,
`code_guard.rs`):

- **P1 — Transfer-on-fresh-proof, per provenance** (Persona per-email
  semantics, mingo-z8im): the voucher adjudicates; the losing account
  is never asked. **Adopted as rule 2** (ruled 2026-08-30); r1's
  release-consent design deleted.
- **P2 — The E3 password fence lives at issuance** (kts0/shyj): certs
  for a mailbox-verified address only mint under an owning session, so
  inbox compromise cannot feed this flow; the reset ceremony (kgb9
  sibling-unverification + H2 eviction) remains the only door into a
  password-backed account. Carries over with no spec text here.
- **P3 — hg2j**: every shipped transfer arm revokes the former
  account's certs for the departed address, precisely scoped. Adopted
  in §1.1; kills the loser's bound tokens fail-closed (H2 for free).
- **P4 — Emptied accounts are deleted** (primary.rs). Adopted;
  `last_identity` survives only on detach.
- **P5 — Enumeration hygiene** (M7/dw35, C1): owner-only disclosure,
  target-bound attempt-burned completions, branch-indistinguishable
  responses. Adopted: attach responds identically for owned/unowned
  targets; request codes unguessable, single-target, TTL'd,
  rate-limited.
- **P6 — kgb9 blast radius**: a transfer touches exactly one identity's
  certs and warrants at the loser, never a sibling's. Preserved by
  P3's scoping.
- **P7 — No second-factor precedent**: the cookie bar for adding an
  email is session + mailbox code; a session thief can attach today.
  Q1's rule is an upgrade on its own merits, not parity.
