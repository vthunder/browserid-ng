---
# browserid-ng-9i8l
title: 'Homepage: Claude.ai tab in guestbook demo setup (from mockup review)'
status: completed
type: task
created_at: 2026-07-29T12:15:11Z
updated_at: 2026-07-29T12:15:11Z
---

From '~/BrowserID refresh mockup review.zip' (design_handoff_claudeai_connector_tab): add a Claude.ai tab to the wallet-setup tab group in the guestbook demo, between Codex and Other — hint 'No terminal needed — Settings → Connectors → Add custom connector:' with the hosted wallet URL https://wallet.browserid.me/mcp.

## Summary of Changes

Implemented by the mockup-review agent, reviewed + deployed by main session: marketing/index.html — new data-tab=web button + tabs-map entry. Existing .mcp-tabs CSS already matched the mockup spec; generic tab handler needed no JS changes. Deliberately kept the live site's 'claude mcp add -s user' flag over the mockup's reference command.
