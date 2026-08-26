---
# browserid-ng-lxj5
title: 'Explore: agent-framework integrations — one-line identity in OpenAI Agents SDK / LangChain / Vercel AI / Pydantic AI'
status: draft
type: feature
priority: low
created_at: 2026-08-26T23:22:01Z
updated_at: 2026-08-26T23:27:01Z
---

## Idea

The site-side adoption story is covered (mcp-auth, NextAuth adapter). The agent-side story currently assumes an MCP-capable host (Claude etc.) talking to the wallet MCP server. But most production agents are *code* — written against frameworks like the OpenAI Agents SDK, LangChain, Vercel AI SDK, Pydantic AI — and those agents today authenticate with whatever API key or password got pasted into their config.

The exploration: thin adapters for each major framework wrapping @browserid-ng/agent (and a Python port of it), so that "this agent has its own identity and holds warrants" is one line in the stack developers already use — the same move the NextAuth adapter made for sites, aimed at agent builders instead. Provisioning UX rides the existing device-grant pairing flow (74u1).

Principle 6: giving an agent its own identity must be *easier* than handing it yours — that has to be true inside the frameworks where agents are actually built, not just in MCP hosts.

Feeds the HTTP-attribution exploration: a framework that holds an identity can sign its outbound HTTP requests.

## Open questions

- Which framework first (where are agents that touch third-party services actually built)?
- Python agent SDK doesn't exist yet — port of sdk/agent is the prerequisite for half the list.
- What the integration surface is per framework: a tool? middleware on outbound calls? both?

## First steps

- [ ] Survey the top 3 frameworks' auth/tool extension points
- [ ] Python port of the agent SDK (device model) — likely the real gating work
- [ ] One reference integration + a "give your agent an identity in one line" quickstart

**2026-08-27 (Dan):** concept makes sense and is worth doing, but not the highest priority yet. Stays draft/low until the agent lane's core pieces land.
