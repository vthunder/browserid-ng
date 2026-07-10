---
# browserid-ng-0eud
title: Session cookie missing Secure/SameSite; sessions never expire
status: completed
type: bug
priority: normal
created_at: 2026-07-08T06:13:39Z
updated_at: 2026-07-10T23:50:47Z
parent: browserid-ng-8u60
---

session.rs:98-104 sets HttpOnly+Path but not Secure or SameSite. sessions table stores created_at but nothing checks age on lookup, so a leaked session id is valid forever.
- [ ] Add Secure + SameSite=Lax to the session cookie
- [ ] Add a session TTL and enforce it on lookup (sqlite + memory stores)

## Summary of Changes (2026-07-11)

Session cookie now carries HttpOnly + Secure (non-localhost deployments) + SameSite=Lax + Max-Age=30d; sessions also expire server-side 30 days after creation, enforced (with row deletion) in get_session_from_cookies, so a replayed cookie dies with the session row. clear_session_cookie matches attributes.

Caveat recorded: SameSite=Lax means the communication_iframe's third-party silent session check no longer receives cookies — that path was already dead in modern browsers (third-party cookie blocking); the dialog is a top-level popup and unaffected.
