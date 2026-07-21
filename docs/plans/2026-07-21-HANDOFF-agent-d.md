# HANDOFF — agent/D phase (merged provisioning + server-side posting)

Read this, then the two design docs in §4. The holder-authorization migration is
**done, deployed, and verified across every service**; this handoff scopes the
remaining feature phase: **agents/services** — merged one-approval provisioning,
mingo-poster server-side posting (D), and the mingo handle bootstrap.

## 1. Where things stand (2026-07-21)

The holder model (opaque broker-assigned `holder` replacing `subject: user|agent`,
warrants binding via `*` / `<ns>.*` / `<id>` matchers) is live end-to-end:

- **browserid.me** (dokku app `id`, repo `~/src/browserid-ng`, branch
  **`holder-authorization-model`** — NOT yet merged to `main`; deployed from the
  branch, currently rev d19fc31-ish). Core/broker/registrar/rp/agent all
  holder-based; account UI iterated: unified "Devices & services" card
  (namespace tree, UA-derived labels, identity chips, per-identity trust in
  holder detail), "Authorized sites" card (audience→matcher rollup, site detail
  w/ revoke; broker's own origin filtered), login warrants **registered at
  sign-in** (status-backed; FedCM lane registers server-side too), one holder
  per browser (cold-login prefix adoption + localStorage holder cache).
- **sandmill.org** (PHP primary IdP, `~/src/sandmill`, **deploys from `main`**):
  issues holder-passthrough certs; `/browserid/demo` rewritten to the device
  model (watch/request + pinned server-side verify relay at
  `POST /api/browserid/demo-verify`).
- **mingo.place** (`~/src/mingo`, mingo-idp): holder-passthrough primary IdP for
  `@mingo.place` handles; browser SBO posting (A) **verified on-chain**.
- **sbo / da.sandmill.org**: `DeviceAttribution.holder` (no subject); daemon on
  sbo rev 55314e9 via CI.
- Verified live: primary login (danmills@sandmill.org) via dialog + /account;
  browser SBO posting on mingo; warrant registration → Authorized sites.
- `id.sandmill.org` alias REMOVED from the `id` app (it silently broke
  session-dependent flows from a second origin; DNS record may still exist).

## 2. The work: agent/D phase

### 2a. Merged one-approval agent provisioning
Spec: `docs/plans/2026-07-21-broker-assigned-holder-deep-dive.md` §"Agent /
service path" (settled with Dan: **one URL, one approval, one pickup**).
Today device-cert provisioning (`/agent-provision/request|complete|poll`,
`browserid-registrar/src/agent_provision.rs`) and warrant issuance
(`/warrant/request|respond|poll`, `consent.rs`) are **two separate flows**.
Merge them: the agent's request carries pubkey + handle + namespace hint
(`agents`/`services`) + grant(s) `audience[+scopes]`; the consent page approves
once (device cert issued with a broker-assigned namespace holder — already
works — AND warrant(s) signed client-side with the user's config cert, matcher
`<id>` default / widenable `<ns>.*` — the consent widen UI exists); one poll
returns both. Holder assignment for agents already routes through the broker
namespace registry (`get_or_create_namespace` via RegistrarStore).

### 2b. D — mingo-poster server-side posting
The poster (mingo server posts on your behalf) is **stubbed 503** (classic-era;
see bean `browserid-ng-3b8m`). Rebuild it on the holder model: the poster is a
**service holder** (user's `services` namespace), provisioned + warranted via
2a — warrant `(its <id>) → sbo+raw://avail:turing:506/ [scopes]` (memory note:
use the BARE audience form). Writes stay owner=you, attributed to you, isolated
per service. **Blocker to clear first:** mingo's `Cargo.toml` pins
`sbo-core = { git = ...sbo, rev = "a92886c" }` — an OLD sbo rev pulling
pre-holder browserid-core. Bump to sbo `main` (55314e9+) so the posting path
verifies holder presentations; mingo-idp itself doesn't use sbo attribution
(verified), but the poster will.

### 2c. mingo handle bootstrap (dan@mingo.place)
Signing in AS `dan@mingo.place` directly fails: mingo-idp only acts as its IdP
once you have a mingo session (via danmills@sandmill.org) — recursive. Fix
direction (Dan's framing): mingo **pre-positions** the handle identity into
browserid when the handle is claimed (or on login), so browserid knows the
relationship before it's needed. Related old context: the 2026-07-20 handoff §3
(deferred-handle provisioning bug — the flow exists but is deferred/lazy).

### Also queued (smaller, independent)
- fallback_idp `/auth/device_cert`: accept the client-supplied holder param
  (still self-assigns server-side).
- Second-browser-cold `browsers`-prefix reconciliation (edge case, documented).
- adopt-after-wipe + re-categorize UI (needs client re-provisioning flows).
- Move user-login demo RPs off the broker origin (e.g. demo.browserid.me).
- Merge `holder-authorization-model` → `main` in browserid-ng when convenient.

## 3. Deploy mechanics (corrections matter)

- browserid.me: `cd ~/src/browserid-ng && git push dokku HEAD:main` (~9 min host
  Rust build). Deploy lock: `ssh dokku@sandmill.org apps:unlock id`.
- sandmill: `git push dokku HEAD:main` — **`main`, not `master`**; a `master`
  push "succeeds" but silently doesn't deploy (bit us: old code kept serving
  "subject mismatch").
- mingo-idp: `GIT_SSH_COMMAND="ssh -i ~/.ssh/donotuse_id_ed25519_service" git
  push dokku@sandmill.org:mingo main:main`.
- sbo-daemon: bump `SBO_REV` in `~/src/mingo/deploy/sbo-daemon/Dockerfile`, push
  mingo to GitHub → CI builds + dokku pulls (~11 min), `gh run watch`.
- DB wipe (test resets): `ps:stop id` → `run id rm -f /data/browserid.db*` →
  `ps:start id` (migrations recreate; users must clear browser state too:
  localStorage `browserid:holder:*`, IndexedDB keystore, cookies).
- Prod smoke: `ADMIN_TOKEN=$(ssh dokku@sandmill.org config:get id ADMIN_TOKEN)
  node scripts/e2e/smoke-prod-dc.mjs` (holder chain, green).

## 4. Key pointers

- Holder model: `docs/plans/2026-07-20-holder-authorization-model.md` (red-penned,
  settled). Holder assignment + merged agent flow spec:
  `docs/plans/2026-07-21-broker-assigned-holder-deep-dive.md`. Protocol overview
  (holder-current): `docs/design/browserid-end-to-end-flow.md`.
- Agent provisioning: `browserid-registrar/src/agent_provision.rs` (namespace
  hint on CompleteBody, broker-assigned holder). Warrant flow + validation:
  `browserid-registrar/src/consent.rs` (`respond` checks matcher covers the
  agent's holder, rejects bare `*`; `register_warrant` for the dialog path).
  Consent UI: `browserid-broker/static/consent.html` (signs `<id>`, widen
  checkbox).
- Dialog login-warrant registration: `browserid-broker/static/dialog.js`
  `buildPresentation` (status alloc → sign → register; `noRegister` for session
  join; failures console.warn). FedCM lane registers in `routes/fedcm.rs`.
- Account UI: `browserid-broker/static/account.html` (+ CSP hash in
  `routes/mod.rs` `INLINE_SCRIPT_HASHES`).
- mingo: `mingo-idp/src/{device,verify,routes}.rs`, `static/device-authorize.html`,
  `mingo-web/app.js`; poster stub — search mingo-idp for the 503/"poster".
- Beans: `browserid-ng-ykjk` (holder model — running log + queue),
  `browserid-ng-3b8m` (A done; D is the remainder), epic `browserid-ng-oup3`.

## 5. Gotchas (earned this session)

- **Client JS is not cargo-tested.** Every latent breakage this migration hid in
  static JS (`account.html`, `consent.html`, `dialog.js`, `sbo-signer.js`).
  `node --check` + reading the diff is the only net. Registration failures now
  console.warn — keep that pattern.
- **CSP hash guard**: editing any inline `<script>` in account/consent/agents
  pages requires updating `INLINE_SCRIPT_HASHES`; `cargo test -p
  browserid-broker --lib csp` prints the needed hash **only when it fails** —
  do NOT script hash extraction off the failure output (an HTML-only change
  passes the guard, greps nothing, and an empty substitution shipped a broken
  CSP once). Gate commits on the guard passing.
- Disk on the host runs ~90%+: `rm -rf ~/src/*/target` frees space; never run
  parallel cargo builds.
- Stale browser state causes ghost bugs: old localStorage broker URLs, cached
  include.js/dialog.js, pre-wipe device certs. Fresh incognito for clean tests.
- Warrant audience for the SBO db must be the bare form
  `sbo+raw://avail:turing:506/`.
- `holder` in `status_entries.subject` / `warrant_status_subject` is a
  DIFFERENT "subject" (status-list key) — never rename those.
