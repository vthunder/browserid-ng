---
# browserid-ng-v8ll
title: 'GitHub flagship: warrant-gated GitHub MCP server (stop putting PATs in your MCP config)'
status: draft
type: feature
priority: high
created_at: 2026-08-10T04:37:02Z
updated_at: 2026-08-10T04:37:02Z
parent: browserid-ng-4w3n
---

The killer demo for MCP distribution: replace the long-lived GitHub PAT in an agent's MCP config with a human's scoped, attributed, REVOCABLE browserid warrant — revoke at browserid.me/account kills the agent's GitHub access mid-conversation, no key rotation.

Build spec: docs/plans/2026-08-10-github-flagship-build-spec.md. Builds on @browserid-ng/mcp-auth + mcp-demo (bean 4w3n, shipped).

Two auth layers: (1) agent->server = browserid warrant via mcp-auth (scoped/attributed/revocable, replaces the PAT); (2) server->GitHub = a GitHub App (human installs on chosen repos, server mints installation tokens, actions appear as browserid-agent[bot]). Tools v1: list_repos/read_file/list_issues (repo:read), create_issue/comment_issue (issues:create).

Needs from user (not autonomous): register a GitHub App + private key + install on a test repo.
Decisions pending (in spec): GitHub App (recommended) vs OAuth/PAT; build-our-own (recommended) vs fork an OSS server; single-install v1 vs multi-tenant mapping; local-first (recommended, holds an App private key) vs host github-mcp.browserid.me; tool set.
