# @browserid-ng/github-mcp

The GitHub flagship: a **warrant-gated GitHub MCP server** built on
[`@browserid-ng/mcp-auth`](../sdk/mcp-auth).

## What it demonstrates

Today, giving an agent GitHub access means pasting a long-lived **Personal
Access Token** into the MCP server's config. The agent effectively owns that
credential: coarsely scoped, unattributed (every action is just "you"), and
revocable only by rotating the key everywhere it's used.

Here the agent holds **nothing durable** — only a short-lived bearer minted
from its human's BrowserID warrant. Authority is:

- **scoped** — the warrant grants exactly `repo:read` and/or `issues:create`;
- **attributed** — every tool call logs "agent X on behalf of human Y" (from
  the warrant's grantee/grantor), and GitHub-side actions appear as the App
  bot, not as a person;
- **revocable in one click** at `browserid.me/account → Authorized sites`,
  which kills the agent's GitHub access on its **next call** (mcp-auth's
  fail-closed status re-check) — with **no GitHub key touched**.

Two auth layers, kept distinct:

1. **Agent → server:** the BrowserID warrant, via `@browserid-ng/mcp-auth`
   (OAuth discovery + RFC 7521 assertion-grant `/token` + bearer-gated
   `POST /mcp`). This replaces the PAT-in-config.
2. **Server → GitHub:** a **GitHub App**. The human installs it on the repos
   they choose (GitHub's own consent for *what* may be touched); the server
   mints short-lived installation access tokens. Revoking the warrant doesn't
   touch the App install, and vice-versa.

## Tools

| tool | required scope | GitHub call |
|---|---|---|
| `list_repos` | `repo:read` | list installation repositories |
| `read_file` | `repo:read` | contents API (`repo`, `path`, optional `ref`) |
| `list_issues` | `repo:read` | list issues (`repo`, optional `state`) |
| `create_issue` | `issues:create` | create issue (`repo`, `title`, `body`) |
| `comment_issue` | `issues:create` | create comment (`repo`, `issue_number`, `body`) |

`repo` is always `"owner/name"`. Every call logs one attribution line:

```
[github-mcp] grantor=dan@example.com grantee=claude@agents.example.com tool=create_issue repo=acme/widgets
```

## Setup

One-time (not automatable): register a GitHub App — permissions
**Contents: read** and **Issues: read+write** — note the App ID, generate a
private key, and **install the App on a test repo**. v1 is single-install:
the server uses the first installation it finds (or `GITHUB_INSTALLATION_ID`).

Environment:

| var | meaning |
|---|---|
| `GITHUB_APP_ID` | the App ID (required) |
| `GITHUB_APP_PRIVATE_KEY` | the App private key PEM (or…) |
| `GITHUB_APP_PRIVATE_KEY_FILE` | …a path to it (wins when both are set) |
| `GITHUB_INSTALLATION_ID` | pin an installation (default: first found) |
| `GITHUB_API_URL` | GitHub API base (default `https://api.github.com`; tests point it at a mock) |
| `PORT` | listen port (default 3400) |
| `MCP_RESOURCE` | this server's public URL — the warrant audience (default `http://localhost:$PORT`) |
| `BROWSERID_BROKER` | broker origin (default `https://browserid.me`) |
| `MCP_STATUS_CACHE_S` | max seconds to trust a status check (default 5 — keeps the revoke demo snappy) |

## Run locally

```sh
npm install
GITHUB_APP_ID=... \
GITHUB_APP_PRIVATE_KEY_FILE=/path/to/app.private-key.pem \
PORT=3400 MCP_RESOURCE=http://localhost:3400 npm start
```

Tests (GitHub and the broker fully mocked, no credentials needed):

```sh
npm test
```

## The demo script

1. Human installs the BrowserID Agent GitHub App on a test repo.
2. Human approves a warrant for their agent — scopes `[repo:read,
   issues:create]`, audience = this server — at browserid.me/account.
3. Agent (in Claude or any MCP host) discovers the server's OAuth AS,
   exchanges the warrant for a bearer, and calls `create_issue` → the issue
   appears, authored by the App bot; the server log reads "agent X on behalf
   of human Y".
4. Human clicks **Revoke** at browserid.me/account.
5. Agent's next `create_issue` **fails closed** — GitHub access gone
   instantly, no PAT rotated.

Design: [`docs/plans/2026-08-10-github-flagship-build-spec.md`](../docs/plans/2026-08-10-github-flagship-build-spec.md).
