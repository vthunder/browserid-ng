# Adversarial review — device-cert migration ROLLOUT & DATA hazards

Scope: attack the rollout/data-migration of `2026-07-18-device-cert-model-migration-plan.md`
against live prod (browserid.me) + real consumers (mingo CLI, sbo). Verified against code.

---

## BLOCKER 1 — mingo CLI silently/hard-breaks: on-disk credential + retired endpoints

**Evidence:**
- mingo stores `~/.mingo/credential.json` = `AgentCredential { secret_key, delegation,
  broker, idp }` (browserid-agent `lib.rs:95-105`), loaded via bare
  `serde_json::from_str` with **no `#[serde(default)]`** on any field (`lib.rs:108-109`).
  P7 redefines the struct to `{ device_key, agent_device_cert, idp }` — dropping
  `secret_key`/`delegation`/`broker`. Old files then **fail to deserialize** (missing
  now-required `device_key`/`agent_device_cert`) → `load_login_credential()` errors
  (mingo `login.rs:113-127`). Every existing mingo login dies at next command.
- Even before that, mingo's mint path calls `endorse()` → broker `/provision/endorse`
  then `/provision/mint` (`lib.rs:654,680`). P2 REMOVES `/provision/endorse`
  (`registry.rs:318`) and changes `/provision/mint` semantics. The moment the broker
  ships P2, mingo's `mint()` gets a 404/verification failure — a live outage for the
  mingo CLI even if the on-disk file still parsed.
- The stored `~/.mingo/identity.json` warrants are tied to the old agent identity/cert
  and become unusable.

**Blast radius:** every mingo CLI user (the `mingo-cli-auth` flow) must re-provision
from scratch; stored warrants lost. Not graceful — a parse error, not a re-login prompt.

**Mitigation:** (a) make new `AgentCredential` fields `#[serde(default, Option)]` and
detect legacy files, printing "re-run `mingo login`" instead of a serde panic; (b)
keep `/provision/endorse` + old `/provision/mint` alive as a deprecated shim through
one release so old CLIs degrade with a message; (c) coordinate a mingo release that
lands BEFORE the broker retires the endorse path, and announce forced re-login.

---

## BLOCKER 2 — DB migration is destructive + irreversible; no rollback path

**Evidence:**
- The migration framework is **forward-only**: monotonic `SCHEMA_VERSION` (now **11**,
  not "v1–v10" as the plan repeatedly states — `sqlite.rs:17`), `INSERT OR REPLACE INTO
  schema_version` (`sqlite.rs:100`), and no down-migrations anywhere.
- P3 does `DROP` of `provisioning_certs` (`sqlite.rs:238`) and `api_keys`
  (`sqlite.rs:213`). Once the broker restarts on the new binary, the migration runs
  at `open()` (`sqlite.rs:42`) automatically. A DROP is **unrecoverable** — if P3/P4
  need to be rolled back (e.g. P6 verifier bug found in prod), the prior binary sees
  `schema_version=12`, and the dropped tables/columns are gone. Rollback = restore
  from DB backup only, losing everything written since deploy.
- `provisioning_certs` is **live data**, not legacy: it backs every agent's endorse
  path today. Dropping it orphans in-flight agent identities server-side.

**Note the plan contradicts the codebase's own stated caution:** the v5 migration
comment (`sqlite.rs:234-235`) deliberately did NOT drop the dead `api_keys` table
because "a DROP is riskier than an unused table." The plan blithely says REMOVE
`api_keys` — low data risk (it's empty) but it reverses an explicit engineering
decision without acknowledging it.

**Mitigation:** take a verified DB snapshot immediately pre-deploy; stage the DROPs a
release LATER than the code that stops using the tables (deprecate-then-drop), so a
fast rollback doesn't hit missing tables; consider soft-retire (rename/ignore) instead
of DROP for `provisioning_certs` until the mingo fleet has migrated.

---

## BLOCKER 3 — "warrants mandatory on every login" is a HARD CUTOVER → login outage window

**Evidence:**
- Today user login is a 1-part backed assertion (`cert~assertion`), warrant is
  **agent-only** (div-rp-verifier §TL;DR; core `Warrant` only exists for agents,
  `warrant.rs:114` rejects agent parent certs, `TYP_AGENT_WARRANT`). P6 makes the
  verifier require a warrant + config cert on **every** login (4-object bundle).
- include.js passes an **opaque token** with no version tag (div-rp-verifier §1:
  "the shim is agnostic... just carries more segments"). So the verifier **cannot
  distinguish** an old 2-segment bundle from a new 4-object one except by parse
  failure. A new verifier rejecting old bundles = every not-yet-updated client's
  login fails.
- There is a deploy skew guaranteed: the live www static bundle, the sandmill.org
  PHP iframe pages (`routes/web.php:194-266`, P10), and cached include.js in RP pages
  all emit OLD bundles until each is independently redeployed/cache-expired. During
  that window old clients hit the new verifier → **all logins broken**, including the
  guestbook and mingo web login.

**Blast radius:** total auth outage for any RP whose client half hasn't cut over,
for the full duration of client rollout + CDN/browser cache TTL. This is the single
biggest coexistence hazard.

**Mitigation:** verifier MUST accept BOTH old (`cert~assertion`, no warrant) and new
(4-object, warrant-mandatory) bundles during a transition release — i.e. "warrant
mandatory" ships as verifier-tolerant first, enforced only after clients are fully
cut over and old-bundle traffic drops to ~0 (measure it). Do not enforce and cut over
in one deploy. Version-tag the bundle so the verifier branches deterministically
instead of by parse failure.

---

## MAJOR 4 — sbo historical verification breaks; core Warrant format change is lockstep

**Evidence:**
- sbo verifies warrants **offline, directly against `browserid-core`** — not via the
  hosted `/verify` (`sbo/crates/sbo-core/src/attribution.rs:40,205-256`, `Warrant`
  imported from `browserid_core`). It pins the warrant **at message inclusion time**
  (`agent_write.rs:101-106`: "Warrant survives serialize→parse", "inclusion-time
  gated"). Already-written sbo messages carry OLD-format warrants embedded in the log
  **forever**.
- P1/P2 re-cut `Warrant`: drop the embedded `parent-cert` (`warrant.rs:68-69,131`),
  switch signer from the identity key to a config cert, change `typ` from
  `TYP_AGENT_WARRANT`. `parse()` hard-rejects a wrong/missing `typ` (`warrant.rs:144`).
  A verifier on new-core can no longer validate the old warrants sitting in the sbo
  log → historical attribution breaks.
- Because sbo compiles `browserid-core` in-process, core is a **breaking semver bump**
  that forces an sbo code+redeploy in lockstep; there's no server it can lag behind.

**Blast radius:** every already-included agent write in sbo (mingo's backing store)
loses verifiable attribution unless core keeps backward-compatible `parse()` for the
old `typ`/shape. The `mingo-warrant-audience` invariant lives here too.

**Mitigation:** keep the old `TYP_AGENT_WARRANT` parse path in core as a legacy
verifier (don't delete, only stop issuing); version the warrant `typ`; coordinate
the sbo bump with the `3b8m` SBO signing relocation the plan already flags as a gate
(plan line 153/180). Confirm old sbo-logged warrants remain verifiable post-bump
before shipping.

---

## MAJOR 5 — existing `warrants` rows become unverifiable (config-cert ref cannot be backfilled)

**Evidence:**
- Live `warrants` rows (`sqlite.rs:317`, rebuilt v10 `:366`; `WarrantRecord`
  `sqlite.rs:434`) store an identity-key-signed `warrant` blob embedding `parent-cert`.
  P4 requires warrants to be **config-cert-signed** and adds `subject` + a config-cert
  reference column. `subject` is backfillable (infer agent-ness from
  `agent_email`/`EmailType::Agent`, div-agents-db §warrants). **The config-cert ref is
  NOT** — no config cert existed when these were signed → column is NULL and the stored
  blob's signature type doesn't match the new RP join. Those warrants are dead weight
  under the new verifier.
- The warrant-table rebuild will follow the v10 rename→copy→backfill pattern
  (`sqlite.rs:357-408`) inside `BEGIN IMMEDIATE`; on a large table that's a full-table
  copy holding a write lock during broker startup. WAL + 5s busy_timeout
  (`sqlite.rs:38`) means concurrent writers get `SQLITE_BUSY` if the copy exceeds 5s.

**Blast radius:** every previously-issued warrant in the registry (cross-browser
review data users rely on) silently stops authorizing; users must re-consent. Plus a
possible startup stall/lock on the live warrants table during the migrating deploy.

**Mitigation:** treat old warrants as revoked/expired and force re-issue rather than
pretending they migrate; surface "re-authorize" in the account UI (P8). Time the
table-copy against a prod-sized DB before deploy; if large, do it out-of-band, not in
the startup migration.

---

## MAJOR 6 — cross-repo deploy ordering has no safe order without dual-support

**Evidence / ordering:** core → broker → sandmill.org PHP → verifiers → mingo/sbo.
Because the verifier change (BLOCKER 3) and the endorse-removal (BLOCKER 1) are both
hard breaks, **every** ordering has a broken window unless servers dual-support:
- Broker/verifier first → old clients (www, PHP iframe, cached include.js, old mingo)
  all fail (Blockers 1 & 3).
- Clients first → they emit 4-object bundles / call the new mint API before the broker
  understands them → also fail.
- sandmill.org PHP (P10) is a **separate language + separate dokku deploy**
  (`dokku@sandmill.org:sandmill`) with cross-language JWS byte-compat risk (plan
  lines 141-147, 175-177). It cannot be atomically deployed with the broker; there is
  necessarily a skew window where `@sandmill.org` primary logins are half-migrated.
  Until P10 lands, `@sandmill.org` MUST be rejected (plan 176-177) — meaning real
  `danmills@sandmill.org` logins are DOWN for the P6→P10 gap.

**Mitigation:** ship servers in **tolerant** mode (accept old+new) for a full release
before any client cutover; only remove old-path support once telemetry shows old-bundle
/ endorse traffic ≈ 0. Sequence sandmill.org P10 conformance to land+verify (byte-compat
golden tests against browserid-core) BEFORE the broker starts rejecting `@sandmill.org`,
to avoid a primary-login blackout.

---

## MINOR 7 — RegistrarStore trait break ripples to any external host impl

`RegistrarStore` (`browserid-registrar/src/store.rs:12-45`) exposes 6 provisioning-cert
methods. P3/P4 remove them and the `ProvisioningCertRecord` model. That's a compile
break for `BrokerRegistrarStore` (expected) but also for any out-of-tree host
implementing the trait (the trait's docstring anticipates "a self-hosting IdP"). Low
blast radius today (only the broker impls it) but worth a deprecation note.

## MINOR 8 — plan's schema-version bookkeeping is wrong

The plan repeatedly cites "migrations v1–v10", warrants at "v8", status at "v9", etc.,
but the live schema is at **v11** (`sqlite.rs:17,95,411` — v11 added `warrant_requests.external`).
Any migration author following the plan's numbers will mis-target. New work must add
**migrate_v12+** and bump `SCHEMA_VERSION` to 12. Minor, but it's the exact off-by-one
that causes a missed migration.

---

## What SURVIVES cleanly (no data hazard) — for balance

- `users`, `emails` (+`email_type`/`parent_email`), `sessions`, `pending_verifications`
  are untouched (`sqlite.rs:143-205`). **Live browserid.me accounts/sessions/email data
  survive** the migration — the account layer is not in blast radius.
- `warrant_requests` are 15-min ephemera (`sqlite.rs:287`) — safe to drop/rebuild.
- `status_entries` gains additive `device`/`access` kinds — additive, safe.
- FK `ON DELETE CASCADE` from `users` means dropping `provisioning_certs` needs no FK
  cleanup.

---

## Top recommendations (sequencing)

1. **Dual-support, don't cut over.** Verifier + broker must accept old AND new bundles
   for ≥1 release; enforce "warrant mandatory" only after old-bundle traffic ≈ 0.
2. **Deprecate-then-drop** the DB tables: stop using `provisioning_certs`/`api_keys` in
   code one release before DROP; keep a verified snapshot; there is no down-migration.
3. **Version-tag** the RP bundle and the warrant `typ` so verifiers branch
   deterministically and sbo's historical warrants stay parseable (keep legacy parse).
4. **mingo credential compat:** Option/default the new fields + a clear "re-login"
   message; ship the mingo release before the endorse endpoint is removed.
5. **sandmill.org P10 gating:** land + byte-compat-verify PHP conformance before the
   broker rejects `@sandmill.org`, else primary logins black out.
6. Fix the v11→v12 numbering before anyone writes the migration.
