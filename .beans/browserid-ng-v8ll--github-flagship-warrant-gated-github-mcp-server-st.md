---
# browserid-ng-v8ll
title: 'GitHub flagship: warrant-gated GitHub MCP server (stop putting PATs in your MCP config)'
status: in-progress
type: feature
priority: high
created_at: 2026-08-10T04:37:02Z
updated_at: 2026-08-11T21:55:11Z
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
