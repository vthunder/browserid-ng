---
# browserid-ng-dgsg
title: Wallet per-login confirm should show identity + caller, not just the origin
status: completed
type: task
priority: normal
created_at: 2026-08-27T19:28:40Z
updated_at: 2026-08-27T19:34:13Z
---

The per-login native confirm ("Sign in to {origin}?") is the ONLY real backstop on the wallet's localhost bridge — every /login mint is gated on it. It currently shows the attacker-controllable origin string and nothing else. It should give the human more to judge:

- WHICH identity is about to be used (e.g. danmills@sandmill.org) — the wallet may hold others later.
- WHETHER the request came from the paired extension vs. a bare HTTP caller (once callers are distinguishable, see the pairing/CORS beans).

## Context
wallet/src/server.js /login -> wallet/src/login.js login() approveLogin dialog (main.js approveLogin). Flagged during gxi9 wallet review 2026-08-27. This is the last line of defense behind pairing, so its legibility matters. Related: b8q0, the pairing-identification bean.

## Summary of Changes

The per-login native confirm (wallet/src/main.js approveLogin) now shows,
besides the RP origin: `Identity: <email>` (which identity is about to be
used) and `Requested via: <caller>` — the paired extension's
chrome-extension:// origin, or "a local process on this machine (no browser
origin)" for bare HTTP callers. The caller line derives from the Origin
header on the /login request (server.js describeCaller), which the browser
attaches itself and a page cannot forge; the RP origin from the body remains
caller-claimed and is now noted as such in the handler.
