---
# browserid-ng-z5id
title: 'www homepage refresh: dark/light redesign with live guestbook wall (design 0bfc3a2e)'
status: completed
type: feature
priority: normal
created_at: 2026-07-26T20:21:47Z
updated_at: 2026-07-26T20:38:55Z
---

Implement 'Homepage refresh.dc.html' from the claude.ai/design project 0bfc3a2e: full rebuild of marketing/index.html — sticky nav, interactive replayable hero (the real v2 approval cards: check → permission → approved/denied/stopped), problem section, sequenced try-it journey (guestbook w/ copyable prompt + MCP setup tabs for Claude Code/Codex/Cursor/Other + LIVE wall from browserid.me/guestbook/feed; Bluesky feature block; demo cards incl. FedCM), For apps / For agents code samples, For everyone, Why, Get started, footer.

Aligned decisions (2026-07-26):
- grantee added to /verify-access + @browserid-ng/verify so the RP sample's who.grantee is honest (additive)
- ship BOTH themes: design's dark palette + a derived light palette, CSS variables, nav toggle persisted in localStorage, prefers-color-scheme default
- agent sample uses real API names; placeholders filled with real links; PostHog/config.js wiring preserved
- journeyMode=sequenced, showFedcm=true

Todos:
- [x] broker: verify-access response gains grantee (warrant grantee, VerifiedAccess pass-through); verifier test asserts it
- [x] sdk/js: grantee passed through (defaults to email), typed, @browserid-ng/verify 0.2.0 (publish is manual)
- [x] marketing/index.html rebuilt from the design (dark canonical + derived light on CSS vars, pre-paint theme script, hero state machine w/ 3 outcomes, live wall from /guestbook/feed, MCP tabs, copy buttons)
- [x] links + analytics preserved (PostHog wiring, data-auth-href, hero-actions/btn classes for existing captures + a prompt_copy event); guestbook.html untouched
- [x] deployed: www subtree a6cc520 pushed; broker CI on the same commit ships the grantee field

## Summary of Changes

Implemented and deployed. Verified locally via playwright: both themes render (pixel-brightness-checked), the hero card walks check→permission→all three outcomes and replays, no horizontal overflow at 360/390/768/1280 (fixed the grid min-width:auto trap + small-screen nav), scripts parse, all JS-referenced ids present. Production /guestbook/feed is currently EMPTY (entries: []) so the wall shows its empty state — it fills as agents sign. Design deviations, agreed with Dan: light palette derived (not in the design), toggle persisted in localStorage with dark canonical; code samples use real API names; grantee added to the verifier so the RP sample is honest.
