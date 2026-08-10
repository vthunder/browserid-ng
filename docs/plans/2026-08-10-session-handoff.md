# Session handoff — 2026-08-10

Resume point for the distribution/adoption work. Everything below is committed
on `main` unless noted. Deploys use the CI-image path (CI builds+pushes GHCR;
release manually with `ssh -i ~/.ssh/mini-ops dokku@<host> git:from-image <app>
<image>:<sha>` — the CI ssh step is still unauthorized, bean o7ip).

## Shipped + live this session

- **Hosted-primary IdP** (epic `g5qt`, build `0j6l`) — any domain delegates via
  one DNSSEC record; live. Onboarding = one admin question; tenant delete;
  revoke-prior-certs on verify. `idp.browserid.me`.
- **DNSSEC verifier conformance** (`0p5f`) — extracted `browserid-dnssec`
  crate; broker + `browserid-rp` + **mingo** all resolve issuer keys from the
  `_browserid` record, never `.well-known`. mingo deployed; sandmill.org tenant
  login verifies. SBO/on-chain verifier reviewed — already conformant (`k3rg`).
- **mcp-auth** (`4w3n`) — `@browserid-ng/mcp-auth` (7521 AS + fail-closed
  per-call status) + reference server live at `mcp-demo.browserid.me`.
- **NextAuth adapter** (`bla3`) — `@browserid-ng/nextauth` built + tested
  (8 tests) + reference app. Library, nothing to deploy. **Ready to npm-publish.**

## Built but NOT finished / not published

- **OIDC bridge core** (`qer8`, commit a2d2bc4) — `browserid-broker/src/oidc/`
  built + 12 tests, **inert** (unconfigured = no effect). REMAINING is a
  SUPERVISED step (needs a Google OAuth client id/secret + review of production
  login routing): routes `/oidc/claim` + `/oidc/callback`, the authority-
  hierarchy Google-domain arm, `address_info` `proof:"oidc"`, the dialog lane,
  env config. Exact wiring handoff is in bean `qer8`.
- **npm publishes deferred (supervised):** `@browserid-ng/mcp-auth`,
  `@browserid-ng/nextauth`.

## Specced only (need the user)

- **GitHub flagship** (`v8ll`) — warrant-gated GitHub MCP server on mcp-auth.
  Gated on the user registering a "BrowserID Agent" GitHub App (App id + private
  key) and installing it on a test repo. Spec:
  `docs/plans/2026-08-10-github-flagship-build-spec.md`. Recommend building it
  local/controlled first (it holds a GitHub App key).

## Build specs written (docs/plans/2026-08-10-*)

`oidc-bridge-build-spec`, `nextauth-adapter-build-spec`,
`github-flagship-build-spec`, `mcp-auth-flight-build-spec`.

## Infra notes

- Two dokku hosts: **id-host** (`browserid.me`, 159.89.230.185 — broker `id`,
  `www`, `guestbook-mcp`, `browserid-wallet`, `mcp-demo`) and **hobby**
  (`sandmill.org`, 198.199.110.160 — `mingo`, `sbo-daemon`, `sandmill`, …).
- `~/.ssh/mini-ops` now authorizes dokku on **both** hosts (added to hobby via
  `thunder@sandmill.org` + sudo this session). Never use
  `~/.ssh/donotuse_id_ed25519_service` — purged from mingo's deploy scripts.
- Hobby host still needs a rebuild with the new provision scripts (separate
  infra bean) — mini-ops was added manually as an interim.
- Tenant onboarding envs on `id`: `IDP_HOST=idp.browserid.me`,
  `TENANT_KEYSTORE_KEY` — set in dokku config; still to be folded into
  `sandmill-infra/secrets/id.env.age` for durability.

## Next-up candidates (mostly autonomous — see the chat discussion)

1. Hosted-primary **self-claim** (`j91f`) — SMTP roster enrollment; makes
   hosted-primary self-serve. Fully autonomous, deployable.
2. More **RP adapters** off the NextAuth core (Express, Remix/SvelteKit).
3. **Python/FastMCP** port of mcp-auth.
4. Security-hardening backlog / conformance-suite extraction (credibility).
5. e2e environment health (`dk6d`/`tnwb`).

## Update (later 2026-08-10) — more autonomous work shipped

- **Security (deployed to prod, broker sha 0dcadc4):** M1/`mmnp`+`7ydv`
  fail-closed device-cert revocation gate at the fallback `/access/mint`;
  `zexp` — the served `.well-known` no longer advertises a key (DNSSEC is the
  sole root). Both tested, broker suite green.
- **`@browserid-ng/express`** — Passport strategy + middleware (7 tests).
- **`@browserid-ng/hono`** (edge/serverless) + **`@browserid-ng/fastify`** — RP
  adapters off the same core (6 + 5 tests). NextAuth+Express+Hono+Fastify now
  cover the dominant JS server frameworks.
- **`browserid-mcp-auth` (Python/FastMCP)** — port of mcp-auth (14 tests).
- **Directory-sync exploration** (`mhvi`) — Workspace tenants auto-provision via
  OIDC (JIT), avoiding the self-claim UX. Design note written.

Remaining autonomous candidates: Remix/SvelteKit adapters (off the same core);
a FastMCP reference server; more security-backlog items. Still user-gated: OIDC
wiring (Google creds), GitHub flagship (App), all npm/PyPI publishes.

## Manual steps for when you land (credential/decision-gated)

These need your login/creds or a product decision; once done, the rest is
autonomous. Ordered by leverage.

### 1. OIDC bridge — Google OAuth client (unblocks bean `qer8`)
Google Cloud Console → APIs & Services → Credentials → Create OAuth client ID:
- Type **Web application**.
- Authorized redirect URI: **`https://browserid.me/oidc/callback`**
  (add `http://localhost:3000/oidc/callback` for local dev).
- OAuth consent screen: scopes `openid`, `email` (external, or internal if a
  Workspace test). Note the **client ID** + **client secret**.
Then set on the `id` app: `OIDC_GOOGLE_CLIENT_ID`, `OIDC_GOOGLE_CLIENT_SECRET`
(`ssh -i ~/.ssh/mini-ops dokku@browserid.me config:set id …`) and fold both
into `sandmill-infra/secrets/id.env.age`. → then I wire the routes/authority/
address_info/dialog (the code handoff is in bean `qer8`; the core is built +
tested + inert) and we test the live gmail claim.

### 2. GitHub flagship — register the App (unblocks bean `v8ll`)
GitHub → Settings → Developer settings → GitHub Apps → New:
- Name "BrowserID Agent"; permissions **Contents: read**, **Issues: read &
  write**; no webhook needed for v1.
- Generate a **private key** (PEM); note the **App ID**; install on a test repo.
Provide `GITHUB_APP_ID` + the PEM. → I build the warrant-gated server
(recommend running local/controlled first — it holds the App key and writes to
real repos). Spec: `docs/plans/2026-08-10-github-flagship-build-spec.md`.

### 3. Publishes (need registry auth)
`npm publish` (public): `@browserid-ng/mcp-auth`, `@browserid-ng/nextauth`,
`@browserid-ng/express` (and confirm `@browserid-ng/verify` is current).
`PyPI`: `browserid-mcp-auth` (needs a PyPI token). I can prep everything;
publishing needs your `npm login` / token.

### 4. Durability + infra (supervised)
- Fold `IDP_HOST` + `TENANT_KEYSTORE_KEY` into `sandmill-infra/secrets/
  id.env.age` (currently only in dokku config; deliberately not edited
  unattended — the age re-encryption is risky to do blind).
- Rebuild the **hobby host** with the new provision scripts (mini-ops was
  added manually as an interim) — separate infra bean.

### 5. Directory-sync decisions (unblocks a Depth-1 build of `mhvi`)
Confirm in `docs/plans/2026-08-10-tenant-directory-sync-design.md`:
auth_method `{password, oidc, both}` (recommend `both`); JIT provisioning
policy (recommend auto-create any valid `@domain` Google login); whether
"next-login-blocked + certs age out" deprovisioning is sufficient for v1.

### 6. Demo capture (needs a human approval)
The mcp-demo / GitHub "revoke kills the agent mid-conversation" screen capture —
needs a real warrant approval through the wallet; record it as the distribution
artifact.

## Deferred backlog (not blocking; from the specs/beans)

- **OIDC:** Microsoft + Apple providers; the bridge-shape secret isolation.
- **NextAuth/RP:** Remix + SvelteKit adapters off the same core (Express done);
  the OAuth-against-wallet-service path as a package; a generic hosted
  authorization-code AS ("Login with BrowserID", zero RP backend).
- **MCP:** a live FastMCP reference server; MCPB/DXT desktop bundle + registry
  listings; the scope-conventions public registry; per-call attestation hook
  for high-value tools; remote-wallet identity portability.
- **GitHub flagship:** per-repo path scopes; install→identity multi-tenant
  mapping; an upstream PR to a popular OSS GitHub MCP server; webhook-driven
  revocation reactions; more tools (PRs, actions).
- **Directory sync:** Entra + Okta SCIM (Depth 2); Google groups → scopes/roles;
  a tenant "connect your directory" onboarding step; near-real-time push.
- **Security backlog (self-contained, autonomous next time):** `bls2` (exact
  identity match at mint — no subaddressing on the auth path); `oawf`
  (rate-limit, enumeration, fallback pw-bypass); `ya11` low-severity hygiene
  batch; `o92d` fallback-abuse guardrails.
- **e2e health:** `dk6d` / `tnwb` (34 pre-existing failures + untrustworthy
  summaries) — fixing the harness unblocks confident shipping.
- **Hosted-primary recovery/transfer guardrails, admin recent-strong-auth,
  roster-vs-self-claimed collision, tenant branding** (g5qt follow-ups, bean
  `0j6l`).

## Product decisions to make (after landing)

Calls only you can make — each shapes or gates a build. My recommendation is
noted so you can quickly agree or override. Grouped by area.

### Hosted-primary — provisioning strategy
- **Self-claim vs directory sync.** You're ambivalent on self-claim (`j91f`)
  because its UX resembles the fallback. Decision: **drop self-claim in favor
  of directory sync** (`mhvi`) for Workspace tenants, keep admin-managed roster
  for the rest? *(Recommend: yes — directory sync is the tighter answer;
  revisit self-claim only for mail-domains with no directory.)*
- **Directory sync — `auth_method`** per tenant ∈ `{password, oidc, both}`.
  *(Recommend `both`: Workspace users sign in with Google, but the admin can
  still create password users for service/shared accounts.)*
- **Directory sync — JIT policy.** Auto-provision a roster entry on any valid
  `@domain` Google login (hd-matched), or require a per-user admin approval the
  first time? *(Recommend auto-provision — that's the whole point.)*
- **Directory sync — deprovisioning bar.** Is "suspended-in-Google ⇒
  next-login blocked + certs age out" enough for v1, or must v1 include Depth-2
  directory sync for immediate cutoff? *(Recommend v1 = next-login-blocked;
  Depth-2 as the enterprise follow-up.)*

### Hosted-primary — hardening (g5qt / 0j6l follow-ups)
- **Domain re-claim / transfer ceremony:** hold-down window length before a
  re-claim over an ACTIVE tenant activates; notify existing admins (yes);
  roster on re-claim = **clean** (new owner) with export for the outgoing
  admin, vs inherited. *(Recommend clean-with-export — inheriting leaks the old
  owner's user list.)*
- **Admin recent-strong-auth gate** on destructive console actions (delete
  domain, disable users, rotate)? *(Recommend yes — cheap, closes the
  "admin identity is the keys to the kingdom" gap.)*
- **Roster vs. self-claimed collision:** if an admin creates a roster entry for
  a local part that already self-claimed — adopt, or block until the admin
  confirms takeover? *(Security-sensitive; recommend block-until-confirm.)*
- **Tenant branding** on the §7 auth pages (logo/name, "via browserid.me")?
  *(Product/GTM call; not blocking.)*

### GitHub flagship (v8ll)
- **Server↔GitHub credential:** GitHub App (per-repo human consent, bot
  attribution) vs OAuth user-token vs a service PAT. *(Recommend GitHub App —
  a service PAT undercuts the "no PAT" message.)*
- **Build our own reference server** vs fork/PR a popular OSS GitHub MCP
  server. *(Recommend build-our-own first, upstream PR as a follow-up.)*
- **Single-install demo** for v1 vs the multi-tenant install→identity mapping
  up front. *(Recommend single-install v1.)*
- **Hosting:** local/controlled for the recorded demo first vs host
  `github-mcp.browserid.me` (holds an App private key + writes real repos).
  *(Recommend local-first, host after review.)*

### MCP distribution
- **Hosted authorization-code AS** ("Login with BrowserID" / a hosted AS for
  MCP servers that want zero AS code) — offer it *in addition* to the
  in-middleware AS? It re-centralizes *redemption* (not authority), a
  convenience/decentralization trade. *(Recommend defer; the in-middleware AS
  is the clean default.)*
- **Scope-conventions public registry** (documented `repo:`/`path:`/`action:`
  families so approval cards render legibly) — stand one up? *(Cheap,
  compounding; recommend yes, low priority.)*

### Security / policy calls (deferred pending your decision)
- **`bls2` — subaddressing at the mint.** Keep the current by-design behavior
  (`user@domain` authorizes `user+tag@domain`; the verifier enforces the real
  binding via the warrant grantee) vs tighten to exact-identity on the auth
  path. *(Recommend keep — tightening breaks agent identities, which are
  `+tags`; the verifier already binds.)* Flagged, not touched.
- **`7ww7` — fallback `/auth/device_cert` password-bypass.** Audit item
  deferred "for product decisions": confirm the intended gate for fallback
  device-cert issuance. *(Needs your read on the intended policy before I
  change anything.)*
- **`dw35` — account enumeration** on the *staging/reset* flows (login itself
  is already non-enumerating): make those flows uniform at the cost of some UX
  clarity? *(Recommend yes, carefully; has a UX trade-off worth your call.)*
- **`jaa1` — identifiers changing hands / revoke-on-flip:** should the broker
  revoke on an identity flip (handle move/takedown), like the bridge does, or
  stay user-or-expiry-only? *(Open DECISION bean; multi-broker world needs it
  on paper.)*

### RP-side reach
- **Which frameworks next** after NextAuth + Express: Remix, SvelteKit,
  Fastify, Hono? *(All thin off the same core; recommend by your users'
  stacks — I can build whichever you name.)*
