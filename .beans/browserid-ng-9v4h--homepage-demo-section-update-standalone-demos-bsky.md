---
# browserid-ng-9v4h
title: 'Homepage demo section update: standalone demos + bsky CTA (design 0bfc3a2e rev 2)'
status: completed
type: task
priority: normal
created_at: 2026-07-28T22:24:38Z
updated_at: 2026-07-28T22:32:12Z
---

The claude.ai/design project 0bfc3a2e's 'Homepage refresh.dc.html' was revised; only the Try-it/demo section (and one Get-started card) changed vs the shipped marketing/index.html (implemented in browserid-ng-z5id). Implement the diff:

- [x] Try-it header: 'See it working, live.' + standalone-demos lede (drop the sequenced 'three demos, each builds on the last' framing)
- [x] Badges: step 1/2/3 -> demo / featured demo / build
- [x] Bluesky block: heading '...— or let it post to yours.', human-first lede (connect or mint your handle), replace the copyable bskyPrompt row with a gold CTA button to https://bsky.browserid.me/ + 'any email or your Bluesky handle' note, add the sign-in-gets-you-a-prompt checklist bullet, live-verified-account link -> bsky.app/profile/danmills.bsky.social
- [x] Get-started demo-path card copy: '...or put your agent on Bluesky at bsky.browserid.me. One approval from you either way.'
- [x] analytics.js: explicit bsky_cta_click capture for the new CTA (bskyPrompt's prompt_copy event disappears with the element)
- [x] Verify: both themes render, no horizontal overflow, scripts parse; commit

Note: removing bskyPrompt supersedes bean browserid-ng-2wmh (its target element is gone; bsky.browserid.me now hands the user the prompt after sign-in).

## Summary of Changes

Implemented the demo-section diff from design 0bfc3a2e rev 2 in marketing/index.html: standalone-demos header ('See it working, live.'), badges demo/featured demo/build, bsky block reframed human-first with a gold CTA to https://bsky.browserid.me/ replacing the copyable bskyPrompt (new #bskyCta id), added the grantor-prompt checklist bullet, live-verified-account link now danmills.bsky.social. Get-started card copy updated. analytics.js gains bsky_cta_click. Verified via playwright: both themes at 360/390/768/1280, zero horizontal overflow, no page errors, all new elements present; scripts node --check clean. Kept intentional deviations from the mockup: -s user on the claude mcp add command, real hrefs for Verify any post / The labeler / Full guestbook, live wall fetch. Scrapped browserid-ng-2wmh (its target element no longer exists). Deployed: www subtree e696385 pushed to dokku-www main; verified live at https://www.browserid.me (new header/badges/CTA present, bskyPrompt gone, analytics has bsky_cta_click).
