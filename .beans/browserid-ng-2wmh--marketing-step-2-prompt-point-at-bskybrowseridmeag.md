---
# browserid-ng-2wmh
title: 'Marketing step-2 prompt: point at bsky.browserid.me/agent'
status: scrapped
type: task
priority: normal
created_at: 2026-07-28T21:25:10Z
updated_at: 2026-07-28T22:28:32Z
---

The bsky bridge UX revamp moves the agent guide from / to /agent and the canonical prompt becomes 'Read https://bsky.browserid.me/agent and follow it so you can post to Bluesky for me.' Update the step-2 prompt in marketing/index.html (id=bskyPrompt, currently points at /). Old prompts keep working (/ still serves markdown to non-HTML fetches), so this is not urgent.

## Reasons for Scrapping

Superseded by browserid-ng-9v4h (homepage demo-section update from design 0bfc3a2e rev 2): the id=bskyPrompt element this task targeted was removed entirely — the bsky block now sends users to https://bsky.browserid.me/ via a CTA button, and the site hands them the canonical prompt (naming them as grantor) after sign-in.
