---
# browserid-ng-a70d
title: Approval links get lost in agent-host UIs — auto-open + push the APPROVE_URL
status: todo
type: bug
created_at: 2026-08-12T06:17:47Z
updated_at: 2026-08-12T06:17:47Z
---

Observed live (github-mcp demo, 2026-08-12): the browserid MCP tools return APPROVE_URL in tool results and tell the agent to relay it, but agent hosts (Claude Code, claude.ai) collapse tool calls — the human sees 'Called browserid 11 times' and experiences the flow as a hang. Users cannot be expected to expand tool output to find approval links.

Fixes to consider, complementary:
1. LOCAL agents (browserid-agent MCP server runs on the human's machine): open the APPROVE_URL in the default browser directly (macOS 'open', xdg-open) when a display is available — the human just sees the approve page appear. Highest leverage, tiny change.
2. Wallet push: the wallet (browserid-wallet / claude.ai wallet MCP) could receive a pending-approval notification so approvals surface in a channel the human actually watches, independent of the requesting agent's host UI.
3. Keep the URL in the tool result as fallback (headless/remote agents), but shorten the polling message and make it explicitly instruct the AGENT to display the link as user-facing text, not just keep polling silently.
