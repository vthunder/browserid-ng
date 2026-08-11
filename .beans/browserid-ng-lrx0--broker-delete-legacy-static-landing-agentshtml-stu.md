---
# browserid-ng-lrx0
title: 'Broker: delete legacy static landing + agents.html stub'
status: completed
type: task
priority: normal
created_at: 2026-08-11T20:44:21Z
updated_at: 2026-08-11T20:48:48Z
---

Follow-up to marketing v3 (browserid-ng-kc7g). Two dead static files on the broker:

- static/index.html: the pre-split marketing landing, served at / only when MARKETING_URL is unset (local dev); production 308s to www. Stale by two design generations.
- static/agents.html: redirect stub to /account with an inline script that costs an INLINE_SCRIPT_HASHES entry + guard-test row.

- [x] Delete static/index.html; dev-mode / redirects to /account instead
- [x] Delete static/agents.html; /agents becomes a Rust Redirect::permanent to /account
- [x] Remove agents.html CSP hash + guard-test entry
- [x] Broker tests pass (csp guard test); e2e marketing-split still green
- [x] Deploy broker + verify prod

## Summary of Changes

Deleted both dead static files and replaced them with redirects in Rust.

- static/index.html deleted. The / route no longer reads a file: with MARKETING_URL set it 308s to the marketing site (unchanged, production path); without it, dev now 307s to /account. The auth origin has no landing page of its own by design.
- static/agents.html deleted (it was a meta-refresh + inline-script stub to /account). /agents is now Redirect::permanent(/account) — no file, no inline script.
- Dropped the agents.html entry from INLINE_SCRIPT_HASHES and from the csp guard test file list; the guard asserts an exact count so both had to move together.

Verified: 60 broker lib tests pass incl. inline_script_hashes_match; dev-mode / → 307 /account and /agents → 308 /account against a live local broker; marketing-split e2e 6/6 green (covers the MARKETING_URL 308 path).
