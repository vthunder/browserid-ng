---
# browserid-ng-z5id
title: 'www homepage refresh: dark/light redesign with live guestbook wall (design 0bfc3a2e)'
status: in-progress
type: feature
created_at: 2026-07-26T20:21:47Z
updated_at: 2026-07-26T20:21:47Z
---

Implement 'Homepage refresh.dc.html' from the claude.ai/design project 0bfc3a2e: full rebuild of marketing/index.html — sticky nav, interactive replayable hero (the real v2 approval cards: check → permission → approved/denied/stopped), problem section, sequenced try-it journey (guestbook w/ copyable prompt + MCP setup tabs for Claude Code/Codex/Cursor/Other + LIVE wall from browserid.me/guestbook/feed; Bluesky feature block; demo cards incl. FedCM), For apps / For agents code samples, For everyone, Why, Get started, footer.

Aligned decisions (2026-07-26):
- grantee added to /verify-access + @browserid-ng/verify so the RP sample's who.grantee is honest (additive)
- ship BOTH themes: design's dark palette + a derived light palette, CSS variables, nav toggle persisted in localStorage, prefers-color-scheme default
- agent sample uses real API names; placeholders filled with real links; PostHog/config.js wiring preserved
- journeyMode=sequenced, showFedcm=true

Todos:
- [ ] broker: verify-access response gains grantee (warrant grantee); tests
- [ ] sdk/js: pass through + types + version bump (publish is manual)
- [ ] marketing/index.html rebuilt from the design (both themes, hero state machine, live wall, tabs, copy buttons)
- [ ] links + analytics preserved; guestbook.html untouched
- [ ] deploy broker (CI) + www (subtree)
