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
