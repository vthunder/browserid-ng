# GitHub flagship — warrant-gated GitHub MCP server — build spec

**Date:** 2026-08-10
**Builds on:** `@browserid-ng/mcp-auth` + `mcp-demo` (bean 4w3n, shipped
2026-08-10) and the MCP-distribution design (`2026-08-02-mcp-distribution-
design.md` §2 "the killer demo").

**One line:** the most legible security argument the project has — replace the
long-lived GitHub PAT sitting in an agent's MCP config with a human's scoped,
attributed, **revocable** BrowserID warrant, and show the revoke killing the
agent's GitHub access mid-conversation with **no key rotation**.

## The contrast (why this is the flagship)

Today, to give an agent GitHub access you paste a **Personal Access Token**
into the MCP server's config. The agent effectively *owns* that credential:
unscoped (or coarsely scoped), unattributed (every action is just "you"),
and revocable only by rotating the key everywhere it's used.

With this server the agent holds **nothing durable** — only a short-lived
bearer it minted from the human's warrant. Authority is:
- **scoped** — the warrant grants exactly `repo:read` + `issues:create`;
- **attributed** — every action logs "agent X on behalf of human Y" (from
  the warrant's grantee/grantor);
- **revocable in one click** at `browserid.me/account → Authorized sites`,
  which kills the agent on its **next call** (mcp-auth's fail-closed status
  re-check) — with **no GitHub key touched**.

## Two auth layers (keep them distinct)

1. **Agent → server: the BrowserID warrant** (via `@browserid-ng/mcp-auth`).
   This is the revocable, scoped, attributed capability that replaces the
   PAT-in-config. Handled entirely by the middleware we already shipped.
2. **Server → GitHub: a GitHub App.** The human installs the "BrowserID
   Agent" GitHub App on the repos they choose (GitHub's own consent for
   *what* may be touched); the server mints a short-lived **installation
   access token** to make API calls. Actions appear as the App
   (`browserid-agent[bot]`) — GitHub-native bot attribution — and the server
   additionally records the browserid grantor/grantee.

These compose cleanly: GitHub App = *what the server may do to GitHub* (the
human's install choice); warrant = *which agent may drive it, with which
scopes, revocably* (the human's approval hop). Revoking the warrant does not
touch the App install and vice-versa.

## The server (`github-mcp/`, a new deployable)

A warrant-gated MCP server on `@browserid-ng/mcp-auth`, same skeleton as
`mcp-demo` (OAuth discovery + `/token` + bearer-gated `/mcp` Streamable
HTTP). Tools (v1):

| tool | required scope | GitHub call |
|---|---|---|
| `list_repos` | `repo:read` | installation repos |
| `read_file` | `repo:read` | contents API |
| `list_issues` | `repo:read` | issues API |
| `create_issue` | `issues:create` | create issue |
| `comment_issue` | `issues:create` | create comment |

Each tool: `requireWarrant(auth, tool)` (scope check + fail-closed status via
mcp-auth) → resolve the human's GitHub App installation → mint/cache an
installation token → call GitHub → return the result, logging
`{grantor, grantee, tool, repo}`.

**Scope grammar (v1 coarse):** `repo:read`, `issues:create`, using the
existing `action:`/`repo:` families. Per-repo restriction
(`repo:<owner>/<name>:read`) is a fast follow via the same grammar — the
tool matches the warrant's scopes against the target repo.

## Identity → GitHub installation mapping

The server must map the warrant's **grantor** (the human's browserid
identity) to *their* GitHub App installation.

- **v1 (single-tenant demo):** one App installed on the demo user's repos;
  the server uses that one installation for all requests. Fastest path to a
  live, shareable demo. (Safe because the warrant still scopes/attributes/
  revokes per agent; the demo just isn't multi-tenant.)
- **Productization (follow-up):** a real install→identity link. The App's
  install/callback flow records `installation_id ↔ browserid identity`
  (the human, signed in to browserid.me, connects their GitHub at install);
  the server looks up the grantor's installation per request. This is the
  multi-user version and is its own small design.

## The demo script (the artifact)

1. Human installs the BrowserID Agent GitHub App on a test repo.
2. Human approves a warrant for their agent — scopes `[repo:read,
   issues:create]`, audience = the server — at browserid.me/account.
3. Agent (in Claude/any MCP host) discovers the server's OAuth AS, exchanges
   the warrant for a bearer, and calls `create_issue` → the issue appears,
   authored by `browserid-agent[bot]`, server log: "by agent X for human Y."
4. Human clicks **Revoke** at browserid.me/account.
5. Agent's next `create_issue` **fails closed** — GitHub access gone
   instantly, no PAT rotated. Record this as a short screen capture; it is
   the distribution artifact.

## What the build needs from the user (not autonomous)

- **Register a GitHub App** ("BrowserID Agent"): permissions Contents:read,
  Issues:read+write; note the App ID, generate a private key, set the
  callback/webhook (webhook optional for v1). Install it on a test repo.
- Provide `GITHUB_APP_ID` + `GITHUB_APP_PRIVATE_KEY` (PEM) as server env
  (→ `sandmill-infra/secrets` if hosted). These are real secrets; the server
  that holds the App private key is sensitive — hence the deploy decision
  below.

## Reuse

- `@browserid-ng/mcp-auth` — the entire warrant/OAuth/status layer (no new
  auth code). `mcp-demo/src/server.mjs` — the HTTP + Streamable-HTTP skeleton
  to copy. GitHub App JWT→installation-token is standard (`@octokit/auth-app`
  + `@octokit/rest`).

## Decisions to confirm (build-blocking)

1. **Server↔GitHub credential** — GitHub **App** (recommended: proper
   per-repo human consent, bot attribution, short-lived installation tokens)
   vs an OAuth App user-token vs a service PAT (demo shortcut, undercuts the
   "no PAT" message). Recommend **GitHub App**.
2. **Build our own reference `github-mcp`** (recommended: clean, controllable,
   on our middleware) vs **fork/PR an existing popular OSS GitHub MCP server**
   to add warrant-gating (rides its users but couples to their code + auth).
   Recommend **build our own**, then pursue an upstream PR/writeup as a
   distribution follow-up.
3. **Multi-tenant now or later** — single-install demo for v1 (recommended)
   vs build the install→identity mapping up front.
4. **Deploy** — host at `github-mcp.browserid.me` (shareable, but the box
   holds a GitHub App private key + can write to real repos) vs run
   locally/controlled for the recorded demo first, host after review.
   Recommend **local/controlled first**, host once the App + scopes are
   reviewed (this server is more sensitive than mcp-demo).
5. **Tool set v1** — the five above, or trim to `read_file` + `list_issues` +
   `create_issue` for the tightest demo? Recommend the **five**.

## Deferred (follow-ups)
Per-repo path scopes; install→identity multi-tenant mapping; the upstream
OSS-server PR; webhook-driven revocation reactions; more tools (PRs, actions).
