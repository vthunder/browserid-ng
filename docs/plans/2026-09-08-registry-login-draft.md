# Registry accounts, login, and login certificates — review draft

Replaces registry-api-v1 §4.2 (the guard), the guard fields on §4.5,
§5.2.1–§5.2.3, and the `guard_kinds` discovery key. Everything else in
the spec stands. Draft for Dan's ruling before any code changes.

## The model in one paragraph

An account is created explicitly and discovered by proof of an identity.
A wallet **logs in** to an account by a method the registry offers, and
a login yields a **session**. Every other operation runs under a session.
Under a session a wallet may have a login key of its own signed into a
**login certificate**, which later logs it in headlessly. Attaching an
identity's certs is an ordinary write under a session, checked for
validity like any other write.

## Flows

**First use, new account.**
1. Wallet obtains identity certs from the issuer (unchanged).
2. `POST /api/v1/accounts` with proof of the identity → the account is
   created holding that identity, and the response is a session on it.
   The registry MAY require a password to be set in the same call.
3. Under the session: `POST /api/v1/login-keys` with a fresh login key →
   a login certificate; `POST /api/v1/account/attach` with the identity
   certs → recorded.

**Returning device (headless).**
1. `POST /api/v1/login { account, method: "stored_key", proof }` — the
   proof is signed by the login key and names the login cert by `kid`.
2. Session. No human step, no identity cert involved.

**New device, existing account.**
1. Wallet obtains identity certs (unchanged).
2. `POST /api/v1/accounts/lookup` with proof of the identity → the
   account id (`404` when no account holds it; then it is first use).
3. `POST /api/v1/login { account, method: "login_page" }` answers
   `403 forbidden/login_required` with the page URL. The wallet opens
   `url#account=…&return_url=…&return_origin=…`; the page authenticates
   the user however this registry chooses (the broker: the account
   password) and ends with `return_url#login=<one-time token>`. The
   wallet posts `{ account, method: "login_page", token }` → session.
4. Under the session: a login cert for this wallet, then attach.

**Session expiry.** Log in again by `stored_key`. A wallet with no login
cert (it never asked for one, or the registry revoked it) logs in by a
human method.

**Signing a device out.** `POST /api/v1/login-keys/revoke { id | kid }`
under any session with a config-cert member, or the login key's own
session. Its sessions end. Identity certs are untouched — that is the
issuer's business (`certs/revoke`, unchanged).

**Takeover / transfer / detach / delete.** As today (§4.1 rule 3, hold,
notice), but every one of them runs under a session: the account you are
logged in to is the one you act on. A takeover is `accounts` with
`confirm_takeover`; a transfer is `attach` under the destination's
session with `confirm_takeover`. The old device's login cert on the old
account stays valid, so it can still log in there, see the notice, and
restore within the hold. The guard token's one-shot binding is gone.

## Endpoints

| Call | Auth | What |
|---|---|---|
| `POST /api/v1/accounts` | proof by a fresh config cert | Create an account around the identity. If another account holds it: `409 conflict/identity_held`; the same call with `confirm_takeover: true` (config cert, fresh) creates the account and the identity leaves the old one (§4.1 rule 3). Response: session body. |
| `POST /api/v1/accounts/lookup` | proof by a cert naming the identity | `{ "account" }` for the account on which the identity is active, else `404`. Never lists identities. |
| `POST /api/v1/login` | method-specific | `{ "account", "method", … }` → session body. `login_page` without a token answers `403 forbidden/login_required` + `{ "url" }`. Rate-limited per source and per account. `403 forbidden/login_rejected` on any failure, one reason, no oracle. |
| `POST /api/v1/login-keys` | session | `{ "pubkey", "label"? }` → `{ "id", "kid", "cert" }`: a registry-signed login cert (JWS, `typ: browserid-login-cert-v1`, `iss` the registry, `sub` the account, `kid`, `exp`, status ref on the registry's list). |
| `GET /api/v1/login-keys` | session | The account's login certs: `id, kid, label, issued_at, expires_at, revoked`. |
| `POST /api/v1/login-keys/revoke` | session (own key, or config) | `{ id \| kid }`. Sticky. Ends its sessions. |
| `POST /api/v1/session/end` | session | Unchanged. |
| `POST /api/v1/account/attach` | session, **config** for identity-changing cases | Records identity certs (validity bar, holder rule, retired-key rule, possession proofs — unchanged). Cases: identity already on this account → record; suspended here → restore (fresh); held by no account → join (fresh, config); held elsewhere → transfer (fresh, config, `confirm_takeover`). No `account`, no `guard` field. |
| `POST /api/v1/account/detach`, `delete` | session, config | Unchanged minus the `guard` field. |

**Login methods (v1 defines two; a registry offers both):**

- `login_page` — a page the registry runs, opened by the wallet with the
  fragment above. What it checks is the registry's business: a password,
  approval from another logged-in device, proof of another identity
  through the login mediator — and that is where those later kinds live,
  with no API change. The page MUST require an explicit user action and
  MUST validate `return_origin` (same-origin with `return_url`). The
  token it returns is one-time, short-lived, bound to the account.
- `stored_key` — `{ "proof" }`: a §4.4 proof signed by a login key whose
  login cert on this account is unexpired and unrevoked.

Discovery: `login_methods: ["login_page", "stored_key"]` and
`browser.login` (the page URL) replace `guard_kinds` and `browser.guard`.

## Sessions (§4.5, amended)

A session is opened only by `login` or `accounts`. Its **members** are
the login key that opened it, when any, plus the identity certs the
wallet proves on later calls — today's per-call member re-check stays as
the rule for identity certs (an identity cert that fails drops out of the
session's authority for its identity; the session itself lives on). The
config-cert rule (§4.3) is unchanged: writes that sign for the account
need a config-cert member, which a wallet adds by attaching or proving
its config cert under the session.

The `Proof` header on every call is signed by a member: the login key or
an identity cert key. `kid` resolves against both.

## What the broker does

- Password = the broker account password. `accounts` for a broker-issued
  identity reuses the existing account (the sign-up created it).
- The web dialog logs in by `stored_key` when it has a login cert for
  this browser; otherwise it is on the registry's own origin, so it posts
  the password the user just typed to the login page's backend directly
  and never renders the page. No approval screen, no second prompt.
- The native wallet asks for a login cert at bootstrap; the guard window
  goes away. The broker's `/guard` page and `/wsapi/guard` are deleted.

## Rulings (Dan, 2026-09-08)

- Creation refuses a held identity overridably (`identity_held` +
  `confirm_takeover`).
- Methods are `login_page` and `stored_key`; passwords and the later
  kinds live inside the page.
- Login cert lifetime is registry policy, RECOMMENDED 90 days.
