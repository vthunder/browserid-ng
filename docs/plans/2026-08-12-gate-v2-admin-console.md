# gate v2 — the admin console (multi-server gateway appliance)

**Date:** 2026-08-12
**Parent:** epic `browserid-ng-81s6`. Supersedes the single-server CLI shape
of M2 (kept as a secondary/library mode). Folds in `dwqa` (multi-mount) and
`k2rz` (management UI).

**One line:** `npx @browserid-ng/gate --admin you@example.com` stands up a
self-hosted gateway with a **BrowserID-gated admin console** where you add MCP
servers by name + mount path + command + allowlist, each published as its own
warrant-gated endpoint at `https://<host>/<mount>/mcp` — one process, one 443
funnel, N servers.

## Target UX (from the user)

```
1. npx @browserid-ng/gate --admin danmills@sandmill.org
   → picks a free local port, sets up the tailscale funnel on 443,
     provisions the gateway agent identity (once), prints:
     "configure at https://mac-mini.hamster-ayu.ts.net/"
2. Load that URL → "Sign in with BrowserID" → sign in as danmills@sandmill.org
   → admin console (only danmills gets in).
3. "Add an MCP" → dialog: name, mount path, command, allowlist.
4. gate spawns the command and publishes it at /<mount>/mcp
   (e.g. "Dan's Notes" at /notes/mcp running the filesystem server on ~/notes).
5. Add https://<host>/notes/mcp to Claude.
```

CLI shrinks to `--admin <email>` (no --port, no --name, no --allow, no
wrapped command). Auto-port, auto-funnel. The old one-shot form
(`--allow … -- <cmd>`) stays supported for the library/tests, not the headline.

## Architecture

### One HTTP server, path-routed
A single Node HTTP server on the auto-picked local port (funnel 443 → it).
The router dispatches by path prefix:
- `/` and `/admin/*` → the **admin console** (login + config UI + config API).
- `/<mount>/*` → that mount's **gated MCP endpoint** (its own mcp-auth + lane).

### Per-mount = a self-contained OAuth resource, for free
Each configured MCP is one `createMcpAuth` + `createAuthCodeLane` whose
**`resource` = `https://<host>/<mount>`**. Because mcp-auth builds every URL
as `${resource}/…`, its advertised endpoints become correctly path-prefixed
with ZERO mcp-auth changes:
- protected-resource metadata: `https://<host>/<mount>/.well-known/oauth-protected-resource`
- AS metadata / token / authorize / register: `…/<mount>/token`, etc.
- the `/<mount>/mcp` 401 `WWW-Authenticate` points at the prefixed metadata.
The router strips/matches the `/<mount>` prefix and calls that mount's handlers
(the existing gate `/mcp` proxy + lane handlers, parameterized by mount).

One shared **gateway agent identity** (provisioned once, `~/.browserid-gate`)
backs every mount's Lane B warrant requests; audiences differ per mount, so
warrants and revocation stay per-mount. Attribution is Option A
(gateway-as-agent), as today.

### Config store + STAGED changes (restart to apply) — a safety property
`~/.browserid-gate/config.json`: `{ mounts: [{ id, name, mount, command:[…],
allow:[…], enabled }] }`. On startup, spawn + mount every enabled entry AND
print each command to the terminal (the review point). 

**Config changes from the console are STAGED, not applied live.** The console
API writes the config file; it does NOT spawn/kill children or add/remove
router mounts. The running set of child commands is fixed at startup and only
changes on a restart (`Ctrl-C` + rerun). This is deliberate defense-in-depth:
the console runs arbitrary commands, so a login bypass must NOT be an
immediate RCE — a bypasser can only edit config *data*; the malicious command
doesn't execute until the admin restarts, and a web attacker can't trigger a
restart (needs terminal access). The restart is a human-gated, out-of-band
checkpoint.

Consequences:
- The console shows BOTH the **running** mounts (from the live process) and the
  **saved** config, with a clear "N pending changes — restart to apply" banner
  when they differ (and which mounts are new/changed/removed).
- A newly-added mount's tool→scope map is derived at startup when its child is
  actually spawned (nothing runs from web input before then).
- Emergency stop is `Ctrl-C` (kills everything now). (A future refinement MAY
  allow immediate *stop* of a running mount — reducing privilege is always safe
  to do live — but v1 stages everything for a single simple model.)
- Later (not v1): summarize config changes since last restart so the admin can
  spot dangerous additions at a glance — the terminal command-print is the v1
  stand-in.

### Auto-port + auto-funnel
Bind the HTTP server to port 0 (OS picks free), read back the actual port,
then `ensureFunnel(port)` on 443 (reuse `src/tunnel.mjs`; error with guidance
if 443 is occupied). The public host comes from the funnel; the console prints
`https://<host>/`.

## The admin console

### Auth — Sign in with BrowserID, gated to `--admin`
The console is a **BrowserID RP**. Login flow:
1. Console page (unauthenticated) shows "Sign in with BrowserID".
2. Browser: `requestBrowserID({ broker, siteName })` (from
   `@browserid-ng/nextauth`'s client, or inline equivalent) drives the broker
   dialog → returns a **presentation** for audience = the console origin
   (`https://<host>`).
3. `POST /admin/login {presentation}` → server verifies with
   `verifyPresentation(presentation, "https://<host>")` (`@browserid-ng/verify`),
   REQUIRES the verified identity `email === --admin` (exact match), then sets
   a **signed, httpOnly, Secure, SameSite=Lax session cookie** (HMAC over a
   random session id with a per-process secret; short TTL, renewable).
4. Every `/admin/*` API call requires a valid session; `/admin/logout` clears
   it. Fail closed: no session → 401, wrong identity → 403.

### Security model (REVIEW-CRITICAL — the console is public + runs commands)
The console is exposed on the public funnel and can spawn arbitrary commands,
so its safety rests entirely on the admin login:
- Verify the presentation's **audience is exactly the console origin** (no
  audience confusion) and **email is exactly `--admin`** — never a substring/
  domain match, never a `+tag` widening.
- Session cookie: unguessable, HMAC-signed with a secret generated per process
  (persisted 0600 in `~/.browserid-gate` so restarts don't log everyone out),
  httpOnly + Secure + SameSite=Lax, bounded TTL.
- CSRF: state-changing `/admin/*` calls require the session cookie AND a
  double-submit CSRF token (the config API is same-origin fetch).
- The command field is **arbitrary code execution by the admin, by design**
  (a homelab appliance) — acceptable because only the `--admin` identity can
  reach it. Spawn with `execFile`-style arg arrays (no shell string
  interpolation); show the exact argv on the confirm step.
- Consider (v1 option, note in README): `--console-local` to bind the console
  to 127.0.0.1 only (configure from the machine; only `/<mount>/*` is
  funneled) for admins who don't want a public console. Default per the UX is
  public-with-BrowserID-login.

### The UI (static, served by the gate; keep JS external — no CSP inline churn)
- **Signed out:** brand + "Sign in with BrowserID".
- **Signed in (admin):** a list of mounts (name, `/<mount>/mcp` URL with a
  copy button, running/stopped, allowlist count, tool count) + per-row
  enable/disable/remove; an **"Add an MCP"** dialog: name, mount path (slug,
  validated unique + safe), command (argv), allowlist (emails). On save →
  `POST /admin/mounts` → spawn + mount → the row appears with its shareable
  URL. In-content confirms for remove (never `window.confirm`).

## Config API (all session-gated)
- `GET /admin/whoami` → `{ admin, host }`.
- `GET /admin/mounts` → the mounts (+ live status).
- `POST /admin/mounts` `{name, mount, command:[…], allow:[…]}` → create+spawn.
- `PATCH /admin/mounts/:id` `{enabled?, allow?, name?}` → update.
- `DELETE /admin/mounts/:id` → unmount + kill child + persist.

## Build order
1. **Multipmount core:** refactor the M2 gate so a "mount" (mcp-auth + lane +
   child + allowlist + scopes, resource=`https://host/<mount>`) is a unit; one
   HTTP server routes `/<mount>/*` to the right mount. Prove two mounts serve
   independently (discovery + a gated call each) with a mock broker.
2. **Config store + STAGED changes:** persist mounts; console writes config
   only. Startup reads config, spawns+mounts, and PRINTS each command. NO live
   spawn/kill from the console — restart applies changes. Console surfaces a
   "pending changes — restart to apply" diff (running vs saved).
3. **Auto-port + auto-funnel** wired into the `--admin` launch.
4. **Admin auth:** `/admin/login` (verify presentation, email===admin, session
   cookie) + session middleware + CSRF. Tests: right identity in, wrong
   identity 403, no session 401, forged cookie rejected.
5. **Admin UI:** the static console (external JS), the add/remove flows.
6. **README + the demo runbook** (single command → console → add Dan's Notes →
   Claude at /notes/mcp).

## Tests
- Multi-mount routing (two mounts, independent discovery + gated calls), mock
  broker (github-mcp idiom).
- Admin auth: presentation-verified login gated to the admin email; session
  enforcement; CSRF; forged/expired cookie rejected. Mock the verifier.
- Config lifecycle: add → mount live → child reachable; remove → unmounted +
  child killed; persistence across restart.
- Path-prefix correctness: each mount's advertised OAuth URLs carry its prefix.

## Out of scope (v1)
Per-friend scope caps (owner policy — fold into the mount's allowlist UI as a
fast follow, `k2rz`); multi-admin; non-tailscale auto-tunnel; hot-reload of
the wrapped server's tool list.
