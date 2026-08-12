---
# browserid-ng-v8ll
title: 'GitHub flagship: warrant-gated GitHub MCP server (stop putting PATs in your MCP config)'
status: completed
type: feature
priority: high
created_at: 2026-08-10T04:37:02Z
updated_at: 2026-08-12T09:43:54Z
parent: browserid-ng-4w3n
---

The killer demo for MCP distribution: replace the long-lived GitHub PAT in an agent's MCP config with a human's scoped, attributed, REVOCABLE browserid warrant — revoke at browserid.me/account kills the agent's GitHub access mid-conversation, no key rotation.

Build spec: docs/plans/2026-08-10-github-flagship-build-spec.md. Builds on @browserid-ng/mcp-auth + mcp-demo (bean 4w3n, shipped).

Two auth layers: (1) agent->server = browserid warrant via mcp-auth (scoped/attributed/revocable, replaces the PAT); (2) server->GitHub = a GitHub App (human installs on chosen repos, server mints installation tokens, actions appear as browserid-agent[bot]). Tools v1: list_repos/read_file/list_issues (repo:read), create_issue/comment_issue (issues:create).

Needs from user (not autonomous): register a GitHub App + private key + install on a test repo.
Decisions pending (in spec): GitHub App (recommended) vs OAuth/PAT; build-our-own (recommended) vs fork an OSS server; single-install v1 vs multi-tenant mapping; local-first (recommended, holds an App private key) vs host github-mcp.browserid.me; tool set.

## Build started 2026-08-11

App registered by user: **BrowserID Agent**, App ID **4563190**, permissions contents:read + issues:write (+metadata:read). Verified live via App JWT (GET /app). Private key at ~/browserid-agent.2026-08-11.private-key.pem (chmod 600, stays local — local/controlled deploy per spec decision 4). Installation on a test repo still pending (installations_count=0).

Build delegated to a worktree agent: github-mcp/ per docs/plans/2026-08-10-github-flagship-build-spec.md, spec recommendations adopted (GitHub App; own server; single-install v1; local-first; all five tools).

Installation verified 2026-08-11: id 153029791 on vthunder, repository_selection=selected, repo vthunder/bud2. Full chain smoke-tested by hand: App JWT -> installation token -> GET /installation/repositories returns exactly bud2.

Progress 2026-08-12 (build agent): github-mcp/ built — mcp-demo skeleton on @browserid-ng/mcp-auth (OAuth discovery + 7521 /token + bearer-gated /mcp), five tools (list_repos/read_file/list_issues @ repo:read; create_issue/comment_issue @ issues:create), per-tool scope gate + fail-closed status re-check (MCP_STATUS_CACHE_S default 5s), one attribution log line {grantor,grantee,tool,repo} per call. Server->GitHub: hand-rolled GitHub App auth on node:crypto (no octokit; deps stay at mcp-demo's 3): RS256 App JWT -> installation token, cached, refresh near expiry + one-shot re-mint on surprise 401. v1 single-install (first of GET /app/installations, GITHUB_INSTALLATION_ID to pin). GITHUB_API_URL env makes GitHub mockable. Tests: 23 green (node --test), GitHub + broker fully mocked. Live sanity check ran: App JWT -> GET /app = 200 (BrowserID Agent, contents:read/issues:write) — key read in place, not copied. NOT done yet: App has no installation; live end-to-end demo (install -> warrant -> create_issue -> revoke) still to run.

CORRECTION (from the user, same session): the browserid agent MCP server does NOT run on the human's machine — it's a remote connector. Fix #1 (local auto-open) only worked in this demo because the agent host (Claude Code) happened to have shell access on the human's laptop; it is not generalizable. The primary fix must be host-independent: the wallet push channel (#2) — a pending-approval should surface in the wallet the human already has open (browserid-wallet web, claude.ai wallet MCP), not depend on the requesting agent's host UI at all. The APPROVE_URL in tool output stays as fallback only.

## DEMO RAN SUCCESSFULLY 2026-08-12

Full end-to-end, live:
- Agent danmills+claude-gh@sandmill.org (managed hosted-tenant identity, per-audience access cert), warrant repo:read+issues:create for the local github-mcp server, attributed to danmills@sandmill.org.
- create_issue → **vthunder/bud2#18**, authored by browserid-agent[bot] (GitHub App bot attribution, no PAT). Server log: 'grantor=danmills@sandmill.org grantee=danmills+claude-gh@sandmill.org tool=create_issue repo=vthunder/bud2'.
- Human revoked the warrant at browserid.me/account → the SAME (unexpired, 1h) bearer's next create_issue returned HTTP 401 invalid_token. Fail-closed on the per-call status re-check, no GitHub key touched.

Getting here surfaced + fixed a chain of real hosted-tenant+agent gaps (all deployed): serving-host mint origin (registrar), +tag roster resolution at the mint, actionable pre-managed-credential error, and the ACTUAL blocker — @browserid-ng/agent per-audience mint was never published (0.3.0 stale); shipped agent 0.4.0 + wallet 0.4.5. Also the wallet approval-link UX contract fix.
