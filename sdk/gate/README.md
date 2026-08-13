# @browserid-ng/gate

**Wrap any stdio MCP server as a remote, BrowserID-gated HTTP endpoint.** One
command turns a local MCP server (your notes vault, an Obsidian server, Home
Assistant, a SQLite file) into a remote endpoint that:

- speaks MCP **Streamable HTTP** to hosts (claude.ai, Claude Desktop, Cursor, a
  phone) — they run their stock OAuth client and never learn BrowserID exists;
- runs the wrapped server as ONE shared **stdio child** and proxies JSON-RPC;
- gates **every** tool call on a human's short-lived, scoped, **revocable**
  BrowserID warrant (fail-closed per call);
- enforces **who may connect, by email** — **roles with per-server, per-tool
  grants**, managed in the web console;
- **auto-maps** the child's tools to `tool:<name>` scopes, so approval cards
  render legibly with zero config;
- prints **one attribution line per call** — who acted, for whom, which tool.

No static token pasted into everyone's config. Revoke one person at
`browserid.me/account` and their agent dies on its next call — no key rotation,
no config surgery for anyone else.

Built on [`@browserid-ng/mcp-auth`](../mcp-auth) — both auth lanes (see below).

---

## The console (the only mode)

```
npx @browserid-ng/gate --admin you@example.com
```

Stands up a self-hosted gateway: it picks a free local port, claims a
**Tailscale funnel on 443**, provisions the gateway's identity once, and prints
a console URL, e.g. `https://mac-mini.hamster-ayu.ts.net/`. Open it, **Sign in
with BrowserID** (only `--admin` gets in), and manage everything from the web —
three tabs:

- **Servers** — add an MCP by **name + mount path + command**; it's published
  at `https://<host>/<mount>/mcp` — one process, one funnel, N servers, each
  its own warrant-gated OAuth resource. Copy the URL straight into your agent.
- **People** — an address book (name + email). Being in it grants nothing.
- **Roles** — **the only way in**: a role = members (people) + per-server,
  **per-tool** grants. People in the role get exactly those tools; a tool call
  outside the grant is `ACCESS_DENIED` before it reaches the child, and
  `tools/list` is filtered to the granted set. The built-in **Full access**
  role grants every tool on every server (including future ones) and can't be
  deleted; the `--admin` identity is implicit and never appears in a role.

Tool lists are discovered from each server's `tools/list` at startup, so a
just-added server shows "tools unknown until restart" — restart once to
discover, grant, then restart again to enforce. (v1 per-mount `allow` configs
are migrated automatically: each becomes a role granting every tool on that
mount.)

**No tailscale? It still runs.** Without a tunnel the gateway starts on
`http://127.0.0.1:<port>` and prints a warning: the URL works locally, but to
share it publicly you need a tunnel in front — **tailscale is recommended**
(install it with Funnel enabled and rerun; gate claims
`https://<your-machine>.ts.net` automatically), or run any other tunnel (e.g.
cloudflared) and pass its URL as `--resource`.

### Flags

| flag | meaning |
| --- | --- |
| `--admin <email>` | **required** — the one identity allowed into the console |
| `--console-local` | bind the console to `127.0.0.1` only (still funnel `/<mount>/*`) |
| `--handle <slug>` | the gateway agent's identity handle (default `mcp-gateway`) |
| `--port <n>` | local listen port (default: auto-pick) |
| `--resource <url>` | public URL = the OAuth audience (default: tailscale funnel on 443; localhost fallback) |
| `--broker <url>` | BrowserID broker (default `$BROWSERID_BROKER` or `https://browserid.me`) |

> One-shot mode (`--allow … -- <cmd>`) was removed in v0.5 — the console is the
> only mode. Embedding a single allowlist-gated server is still available as a
> library via `createGateService` (below).

### One-command demo runbook (share "Dan's Notes")

```
1. npx @browserid-ng/gate --admin danmills@sandmill.org
   → approve the printed provisioning link once (first run only)
   → "Configure at https://mac-mini.hamster-ayu.ts.net/"
2. Open that URL → Sign in with BrowserID as danmills@sandmill.org
3. Servers → "+ Add an MCP":
     name:      Dan's Notes
     mount:     notes
     command:   npx -y @modelcontextprotocol/server-filesystem /Users/dan/notes
   → saved ("1 staged"). Restart the gate (Ctrl-C + rerun) to publish + discover tools.
4. People → add friend@gmail.com. Roles → create "Friends", check the tools to
   grant on Dan's Notes, toggle the Friends chip on the friend's row.
   → staged again; restart once more to enforce.
5. Add   https://mac-mini.hamster-ayu.ts.net/notes/mcp   to Claude.
6. The friend connects, approves with their own identity, acts — attributed and
   limited to their granted tools; revoke just them at browserid.me/account →
   next call fails closed.
```

### Staged config (a deliberate safety property)

The console can spawn **arbitrary commands**, so config edits are **staged, not
applied live** — every mutation (server add/edit/remove/enable, role
create/delete/member/grant change) only **writes
`~/.browserid-gate/config.json`**; the console never spawns or kills a child.
The running set of commands AND the enforced role set are fixed at **startup**
— each command is printed to the terminal (`[gate] starting mount /notes → …`),
which is the **review checkpoint** — and change only on a **restart** (Ctrl-C +
rerun). So a console login bypass is *not* immediate remote code execution: an
attacker could edit config data, but the injected command doesn't run until the
operator restarts at a terminal, which a web attacker can't trigger. The
header's **"N staged" pill** opens a diff popover (`+`/`~`/`−` per change) with
"restart to apply" whenever the saved config differs from what's running.

### Console security model (the console is public — its safety IS the login)

- **`POST /admin/login`** verifies the presentation with `verifyPresentation(p,
  origin)` where the audience is **exactly the console origin** and the verified
  `email` **exactly equals `--admin`** (no substring / domain / `+tag`
  widening). Anything else → `403`.
- **Session cookie**: a random nonce, **HMAC-signed** with a per-install secret
  persisted `0600` in `~/.browserid-gate/session-secret` (so restarts don't log
  you out), `httpOnly` + `Secure` + `SameSite=Lax`, bounded TTL. Forged /
  tampered / expired cookies are rejected.
- **CSRF**: every state-changing `/admin/*` call needs the session cookie **and**
  a double-submit CSRF token (`x-csrf-token`, derived from the session).
- **Commands spawn via an argv array** (`execFile`-style, no `sh -c`, no shell
  interpolation) — the command field is admin-supplied argv.
- Fail closed everywhere: no session → `401`, wrong identity → `403`.

### `--console-local` (safer option)

```
npx @browserid-ng/gate --admin you@example.com --console-local
```

Binds the **console** to `127.0.0.1` only (configure from the machine; the
console is never on the public funnel) while still funneling `/<mount>/*`. The
default per the UX above is the public console with BrowserID login.

---

## Reachability — tunnels

To be reachable from claude.ai or your phone, the gateway needs a **public**
https URL — that URL becomes the OAuth audience warrants bind to.

- **Tailscale Funnel (recommended, zero-config)**: with tailscale installed and
  [Funnel enabled](https://tailscale.com/kb/1223/funnel), the gateway claims
  `https://<your-machine>.ts.net` (port 443) automatically on every start —
  nothing to configure, and the URL survives restarts. If 443 already maps to
  gate's own previous run (a dead target), it's re-pointed silently; if 443 is
  serving a **live** app, gate never steals it — it takes the next funnel port
  (8443/10000) and warns that claude.ai requires 443, with the command to free
  it.
- **Any other tunnel**: run it yourself and pass its URL, e.g.

  ```
  cloudflared tunnel --url http://localhost:8787
  # → https://random-words.trycloudflare.com
  npx @browserid-ng/gate --admin you@example.com --port 8787 \
    --resource https://random-words.trycloudflare.com
  ```

- **No tunnel**: the gateway still runs, on `http://127.0.0.1:<port>`, and
  prints a warning — fine for trying it out locally; agents elsewhere can't
  reach it until you tunnel it.

Then share `https://<host>/<mount>/mcp` as a custom MCP/connector URL.

## Operator first run — the gateway identity

The gate holds **its own** provisioned BrowserID agent identity (design
decision "gateway-as-agent"): Lane-B warrants name the gateway as grantee and
the connecting human as grantor. On first run:

1. the gate raises a provisioning request and prints an **APPROVE link** as its
   last line;
2. you open it and approve once (this is the operator, not the connecting
   friend);
3. the device credential is written to `~/.browserid-gate/credential.json`
   (`0600`, in a `0700` dir; override the dir with `GATE_HOME`) and reused on
   every subsequent boot with no human in the loop.

To re-provision, delete that file.

## The two auth lanes (from `mcp-auth`)

The gate mounts both — a host uses whichever it supports:

- **Lane A — assertion grant.** A code-capable agent that already holds a
  BrowserID wallet POSTs its warrant presentation to `/token`
  (`grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`). The mingo /
  github-mcp path.
- **Lane B — authorization code.** A generic OAuth host (claude.ai, Cursor,
  a phone) does the ordinary redirect dance: discover → register (DCR) →
  `/authorize` (PKCE S256) → approve on the broker's consent page → code →
  `/token`. No wallet. **This is the "paste the URL into Claude and it just
  works" path.**

## HTTP routes mounted

```
GET  /.well-known/oauth-protected-resource      RFC 9728 discovery
GET  /.well-known/oauth-authorization-server     RFC 8414 discovery (both lanes)
POST /register                                   Lane B dynamic client registration (RFC 7591)
GET  /authorize                                  Lane B PKCE authorize → 302 broker consent
GET  /authorize/return                           Lane B post-approval bounce → 302 host redirect_uri
POST /token                                       Lane A (jwt-bearer) + Lane B (authorization_code)
POST /mcp                                          the MCP endpoint (bearer-gated, proxied to the child)
GET  /  /healthz                                  landing + probe
```

## Attribution log

One line per tool call:

```
[gate] grantor=friend@gmail.com grantee=claude@agents.example.com tool=read_text_file args={"path":"todo.md"}
```

A grantor no role reaches logs `[gate] REFUSED grantor=… (no role grants tools here)` and the wrapped tool never runs.

## Scopes

Each wrapped tool auto-maps to a single `tool:<name>` scope (queried from the
child's `tools/list` at startup) — approval cards then show exactly which tools
an agent is asking for. A warrant lacking `tool:<name>` is refused that tool
with `INSUFFICIENT_SCOPE`. On top of that, the grantor's **role** caps which
tools they can reach at all ("friend A read-only" = grant only the read tools).

## Library use

Embed a single allowlist-gated server (no console) with `createGateService`:

```js
import { createGateService } from "@browserid-ng/gate";

const svc = await createGateService({
  allow: ["you@example.com"],
  name: "Dan's Notes",
  child: { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem", "/home/dan/notes"] },
  credential,                     // the gateway's device credential (see credential.mjs)
  resource: "https://notes.example",
  broker: "https://browserid.me",
});
svc.server.listen(8787);
```

## Tests

```
npm test   # node --test — hermetic (mock broker + mock verifier, a real-fs stdio child fixture)
```

Coverage: the single-server library gate (discovery/both lanes, gated proxied
calls, allowlist, attribution, fail-closed revocation), the tunnel detector, the
**multi-mount** router (two mounts, path-prefixed discovery, independent gated
calls, separate bearer stores), the **admin** console (exact-audience +
exact-email login gating, session enforcement, CSRF, forged/expired/tampered
cookie rejection), the **roles model** (per-tool enforcement + filtered
`tools/list`, built-in role protections, people/roles CRUD + staged diffs, v1
allowlist migration), and the **staged config lifecycle** (add/remove persist
but don't spawn live; a restart applies the persisted config + role edits).

MPL-2.0.
