# Registry API + real wallet: build handoff (2026-08-28)

> **Status (end of build session, 2026-08-27):** agenda items 1–3 are DONE
> and deployed — token exchange + DPoP proofs + inbox/respond/claim + the
> §5.2 warrant group live on browserid.me; the real wallet exists at
> `wallet/` (gxi9 email-first bootstrap, safeStorage custody, registry-API
> inbox, .app packaging), e2e green locally; lbla shipped as the UA
> product-token labeler. Remaining on bw9q: §5.3 devices + §5.4 holders
> over the token lane. The wallet's PRIMARY-identity lane needs a human
> walk on Dan's machine. Next design task: d0xb.

Purpose: start the build in a fresh session with zero re-deliberation.
The design phase is DONE: `docs/specs/registry-api-v1.md` is complete,
adversarially reviewed, and committed (8fb461b) with every decision
resolved (§10 decision log). This note carries the build decisions and
implementation pointers; the beans carry the work items. Read this,
the spec, then `beans show bw9q gxi9 ig9p lbla`.

## Build order (agreed with Dan)

1. **Registry API implementation** — `POST /api/v1/token` (presentation
   → sender-constrained token), the DPoP-proof verification layer, and
   `GET /api/v1/requests` (inbox) as the first authed endpoint. First
   consumer: the wallet approvals inbox, killing borrowed-cookie
   polling. Remaining §5 endpoints follow incrementally; bw9q tracks.
2. **The real wallet, starting now** (Dan's call — NOT further
   prototype iteration): a production app skeleton with **gxi9
   single-login bootstrap as its first feature**. That means packaging
   as a real .app (solves the macOS 26 LaunchServices tray issue
   properly), Keychain/secure-enclave key custody replacing the 0600
   JSON file, and the prototype (branch `proto/menubar-wallet`,
   `prototypes/menubar-wallet/`) demoted to reference material — mine
   it (extension pairing, e2e harness, ceremony code), don't extend it.
3. **Wallet registry client** — inbox over the token lane, then device
   listing/labeling (`lbla` rides along).

## Frontloaded decisions

- **API home: the registrar crate.** Token/proof machinery and the
  `/api/v1` router live in `browserid-registrar`; the `RegistrarHost`
  trait grows the device/holder operations the broker's stores own
  today; the broker mounts the router. This matches the spec's framing
  (the registrar IS the registry role; the broker is merely its first
  host) and keeps the self-hosted-registry escape hatch real.
- **Token storage**: a new `api_tokens` table implemented in BOTH
  `InMemoryUserStore` and `SqliteStore`, with an explicit
  SqliteStore-backed test — memory-store tests cannot see sqlite
  constraints (the 2026-08-14 FK-500 lesson).
- **`jti` replay cache**: in-memory with TTL ≥ the ±300s window, keyed
  by proof key. Single-process; no table.
- **Long-poll `wait`**: deferred. Plain polling first; the spec makes
  ignoring `wait` conformant.
- **ig9p phase 1 folds in from day one**: the wallet (and dialog.js)
  mint `scopes: [{"scope": "registry"}]` on broker-audience warrants
  immediately; the broker's `auth_with_presentation` starts LOGGING
  scopeless presentations now, enforcement later (bean ig9p).
- **lbla**: UA product-token convention (`Name/Version` → label in
  `maybe_label_holder_from_ua`) — zero protocol change; do it when the
  wallet registers its device.
- **Self-issued presentations are ACCEPTED at the token exchange**
  (spec §3.1) — do NOT copy `auth_with_presentation`'s
  issuer-is-self rejection into `/api/v1/token`. The cookie lane keeps
  its rejection.

## Implementation pointers (recon already done — don't re-dig)

- **No shared auth middleware exists.** Legacy handlers each call
  `RegistrarHost::resolve_session` (registrar) or
  `get_session_from_cookies` (broker), and legacy POSTs read a `csrf`
  body field. The token lane should be an axum extractor that verifies
  `Authorization: DPoP` + `DPoP:` headers and yields an
  `AuthedUser`-equivalent; API request structs are the legacy ones
  minus `csrf`.
- **Exchange verification**: reuse `verify_access_with_dns`
  (`browserid-verifier/src/verify.rs:661`) with audience = the public
  origin, exactly as `primary::auth_with_presentation`
  (`browserid-broker/src/routes/primary.rs:40`) does — then add the
  spec's extra checks: warrant scopes cover the requested token scope,
  `grantor == grantee`, token exp capped by config-cert exp.
- **Account resolution is SIMPLER than the cookie lane** (spec §3.1):
  identity known → that account; unknown → create; no linking,
  transfer, or merge in the token lane.
- **Inbox**: back with `store.list_pending_warrant_requests` /
  `PendingRequestInfo` (registrar `consent.rs:110`). The API GET is
  pure — the legacy GET's `surface_record_request` side effect is the
  separate `POST /api/v1/requests/claim`.
- **Testing**: broker integration tests default to the in-memory store
  (add the sqlite test per above). CI does not run Playwright — run
  e2e locally before deploying dialog/static changes, with a warm
  broker on :3000 first.
- **Wallet dev on this box**: GUI apps hang under `ssh localtest` (no
  WindowServer) but cargo must run through it (Gatekeeper stalls);
  tray apps need `open -n`; the dev box display is unobserved — push a
  branch for Dan to run GUI demos on his machine.

## Bean map

- `bw9q` — registry API (in-progress; implementation is the last
  unchecked item). Update its checklist as endpoints land.
- `gxi9` — single-login bootstrap; now scoped as the real wallet's
  first feature (venue decision recorded on the bean).
- `ig9p` — cookie-lane scope migration (phase 1 folds into the above).
- `lbla` — device labels rider.
- `d0xb` — fallback-IdP spec: NEXT design task after the build starts;
  carries the account-ceremony scope, `registry.browser` discovery
  keys, and the per-scope self-issued re-review gate.
- Deferred discussions: `d51o` (forget guard-rails), `9mfw`
  (agent-lane spec placement / reparenting), `hd63` (PQ alg review).

## Suggested agenda for the build session

1. Registrar crate: token store + exchange endpoint + proof extractor,
   with sqlite-backed tests; mount `/api/v1` in the broker; add the
   `registry` key to the support document; broker logs scopeless
   `auth_with_presentation` (ig9p phase 1).
2. `GET /api/v1/requests` + `/respond` over the token lane; e2e
   against a warm local broker.
3. Real wallet skeleton (packaging + Keychain custody) with gxi9 as
   the first flow; wire its inbox to the new API; `lbla` UA
   convention when the device registers.
