---
# browserid-ng-mzy8
title: 'Design: browserid-enabled APIs (generic service access pattern for agents)'
status: completed
type: feature
priority: normal
created_at: 2026-07-29T15:21:42Z
updated_at: 2026-07-29T15:22:54Z
---

Define the repeatable pattern that lets any service author make their API accessible to browserid-carrying agents: the HTTP 401 challenge contract, a warrant-gated wallet fetch tool, presentation header placement, and the MCP composition story (per-call presentation, session-bind, connect-time OAuth). First deliverable: design doc in docs/design/ to anchor ongoing discussion.

- [x] Write design doc (docs/design/browserid-enabled-apis.md)

## Summary of Changes

Wrote docs/design/browserid-enabled-apis.md: service-author contract (401 challenge, verify, scopes), new Authorization: BrowserID header placement, warrant-gated call_service wallet tool with audience-origin pinning + SSRF guards, and a three-level composition model (Level 0 fetch-only floor, Level 1 MCP veneer with per-call or session-bind presentation, Level 2 connect-time OAuth with the agent-warrant-semantics limitation noted). Includes notebook.example.com worked example, fallback error contract, and open questions. Implementation work intentionally not beaned yet — design still under discussion.
