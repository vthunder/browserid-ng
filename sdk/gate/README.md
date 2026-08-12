# @browserid-ng/gate

**Wrap any stdio MCP server as a remote, BrowserID-gated HTTP endpoint.** One
command turns a local MCP server (your notes vault, an Obsidian server, Home
Assistant, a SQLite file) into a remote endpoint that:

- speaks MCP **Streamable HTTP** to hosts (claude.ai, Claude Desktop, Cursor, a
  phone) — they run their stock OAuth client and never learn BrowserID exists;
- runs the wrapped server as ONE shared **stdio child** and proxies JSON-RPC;
- gates **every** tool call on a human's short-lived, scoped, **revocable**
  BrowserID warrant (fail-closed per call);
- enforces a **grantor allowlist** — you decide by email whose humans may
  connect;
- **auto-maps** the child's tools to `tool:<name>` scopes, so approval cards
  render legibly with zero config;
- prints **one attribution line per call** — who acted, for whom, which tool.

No static token pasted into everyone's config. Revoke one person at
`browserid.me/account` and their agent dies on its next call — no key rotation,
no config surgery for anyone else.

Built on [`@browserid-ng/mcp-auth`](../mcp-auth) — both auth lanes (see below).

## Quickstart — share your notes vault

```
npx @browserid-ng/gate \
  --allow you@example.com,friend@gmail.com \
  --name "Dan's Notes" \
  -- npx -y @modelcontextprotocol/server-filesystem ~/notes
```

First run provisions the **gateway's own** BrowserID identity (Lane B needs
one): it prints an approval link as its **last line** and waits — open it,
approve once, and the credential is stored in `~/.browserid-gate` and reused on
every later boot. Then the gate listens (default `:8787`) and prints the URL to
add to a host: `<resource>/mcp`.

A friend on Gmail can be onboarded in one hop via the OIDC bridge; their
approval names them as the warrant's grantor, checked against your `--allow`.

### Flags

| flag | meaning |
| --- | --- |
| `--allow <emails>` | comma/space-separated grantor allowlist (required) |
| `--name <label>` | display name on consent cards + the landing page |
| `--port <n>` | listen port (default `8787`, or `$PORT`) |
| `--resource <url>` | public URL of this gate = the OAuth audience (default `http://localhost:<port>`) — **set this to your tunnel URL** |
| `--broker <url>` | BrowserID broker (default `$BROWSERID_BROKER` or `https://browserid.me`) |
| `-- …` | everything after `--` is the wrapped server command + args |

## Reachability — put a tunnel in front (not ours to build)

The gate binds a local HTTP port. To reach it from claude.ai or your phone, run
any tunnel; its **public** URL becomes the OAuth audience warrants bind to. The
gate builds no tunnel — but for **Tailscale** it detects yours automatically.

**Tailscale Funnel** — zero-config. If a funnel already maps to `--port`, the
gate finds it and uses its URL as `--resource` (no need to pass one); or let
the gate set the funnel up with `--tunnel tailscale`:

```
# the gate sets up the funnel (picks a free port: 443/8443/10000) and prints
# the exact claude.ai URL + a share link:
npx @browserid-ng/gate --allow you@example.com --tunnel tailscale \
  -- npx -y @modelcontextprotocol/server-filesystem ~/notes

# or if you already ran `tailscale funnel --https=8443 8787`, just:
npx @browserid-ng/gate --allow you@example.com --port 8787 \
  -- npx -y @modelcontextprotocol/server-filesystem ~/notes
# → detected tailscale funnel → https://your-machine.tailXXXX.ts.net:8443
```

**Cloudflare Tunnel**:

```
cloudflared tunnel --url http://localhost:8787
# → https://random-words.trycloudflare.com
npx @browserid-ng/gate --allow you@example.com \
  --resource https://random-words.trycloudflare.com \
  -- npx -y @modelcontextprotocol/server-filesystem ~/notes
```

Then add `<resource>/mcp` to your host as a custom MCP/connector URL.

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

A refused (non-allowlisted) grantor logs `[gate] REFUSED grantor=… (not on the allowlist)` and the wrapped tool never runs.

## Scopes

Each wrapped tool auto-maps to a single `tool:<name>` scope (queried from the
child's `tools/list` at startup) — approval cards then show exactly which tools
an agent is asking for. A warrant lacking `tool:<name>` is refused that tool
with `INSUFFICIENT_SCOPE`. (Per-friend scope *caps* — "friend A read-only" — are
a later milestone; today `--allow` is allow/deny.)

## Library use

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
npm test   # node --test — 8 checks, hermetic (mock broker, a real-fs stdio child fixture)
```

MPL-2.0.
