---
# browserid-ng-r2i1
title: 'Demo UX hardening: agent-followable guestbook + bsky instructions'
status: in-progress
type: task
created_at: 2026-07-26T21:32:43Z
updated_at: 2026-07-26T21:32:43Z
---

From user testing (2026-07-26, claude opus 4.5): agents summarized instructions instead of acting, buried approval URLs in shell output, and never polled. Fixes: (1) www/guestbook gains a for-agents section — act-don't-summarize, wallet MCP install (incl. restart caveat), DRAFT-AND-SHOW the message to the human before posting, relay APPROVE_URL immediately, re-call sign_guestbook; (2) homepage prompts now demand following the instructions (guestbook adds 'show me the message before you post it'); (3) bsky guide.rs + agent_prompt: act-now preamble, relay URL/code/fingerprint in your own reply the moment they appear, keep the polling command alive / background it under shell timeouts, don't re-run while a link is pending — pinned by a new guide test; (4) wallet sign_guestbook description requires human sign-off on the draft (0.3.1, manual npm publish pending).
