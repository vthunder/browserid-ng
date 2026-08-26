---
# browserid-ng-r2i1
title: 'Demo UX hardening: agent-followable guestbook + bsky instructions'
status: completed
type: task
priority: normal
created_at: 2026-07-26T21:32:43Z
updated_at: 2026-08-26T23:07:58Z
---

From user testing (2026-07-26, claude opus 4.5): agents summarized instructions instead of acting, buried approval URLs in shell output, and never polled. Fixes: (1) www/guestbook gains a for-agents section — act-don't-summarize, wallet MCP install (incl. restart caveat), DRAFT-AND-SHOW the message to the human before posting, relay APPROVE_URL immediately, re-call sign_guestbook; (2) homepage prompts now demand following the instructions (guestbook adds 'show me the message before you post it'); (3) bsky guide.rs + agent_prompt: act-now preamble, relay URL/code/fingerprint in your own reply the moment they appear, keep the polling command alive / background it under shell timeouts, don't re-run while a link is pending — pinned by a new guide test; (4) wallet sign_guestbook description requires human sign-off on the draft (0.3.1, manual npm publish pending).

## Summary of Changes

All four hardenings shipped 2026-07-26/27: 20fe6e4 (browserid-ng) added the guestbook for-agents section, hardened the homepage prompts, and made the wallet's sign_guestbook description require human sign-off on the draft plus immediate APPROVE_URL relay; cec92ad (browserid-bsky) hardened the bsky guide with immediate URL/code/fingerprint relay and keep-the-poll-alive advice, pinned by guide_gives_url_relay_and_polling_advice. Two pieces were later consciously revised: the "don't summarize" framing was dropped from the bsky guide as prompt-injection-shaped (e083a70; the test now enforces its absence), and the www guestbook page was folded into the slimmer /demos page in the 2026-08-11 marketing v3 IA. The behavioral fixes survive in the wallet tool description (@browserid-ng/wallet 0.4.7, published) and the test-pinned bsky guide. (Closed by audit 2026-08-27.)
