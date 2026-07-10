---
# browserid-ng-n4cx
title: Sign-in / account entry point on browserid.me itself
status: completed
type: task
priority: normal
created_at: 2026-07-10T17:04:47Z
updated_at: 2026-07-10T17:39:44Z
---

browserid.me has no sign-in button — today you can only establish a broker session via an RP's login dialog (observed while trying to test agent flows: /agents and /consent both need a session). Add a first-party sign-in entry (e.g. on the landing page nav or /account) that drives the same dialog flow with the broker as its own RP. Relates to w7xu (landing repositioning).

## Summary of Changes

/account rebuilt as the first-party entry point (2026-07-10): signed-out → sign-in form (password, or emailed-code path for password-less primary-created accounts via stage_reset/complete_reset); signed-in → identity list (agent badges via derived parents, key-not-in-this-browser hint), agents/consent links, warrant list, session/cache tools. Landing top nav gained a Sign in link. Warrant visibility: consent + manual signing surfaces now append to an origin-local warrant_log (browser-only — the broker still stores nothing, §6.4); /account lists them with Copy / Reissue (fresh 90-day signature, clipboard) / Forget, and explains that per-warrant remote revocation awaits the status list (egr7) — today the lever is revoking the agent key.
