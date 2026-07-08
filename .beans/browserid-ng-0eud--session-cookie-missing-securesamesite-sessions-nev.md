---
# browserid-ng-0eud
title: Session cookie missing Secure/SameSite; sessions never expire
status: todo
type: bug
priority: normal
created_at: 2026-07-08T06:13:39Z
updated_at: 2026-07-08T06:13:39Z
parent: browserid-ng-8u60
---

session.rs:98-104 sets HttpOnly+Path but not Secure or SameSite. sessions table stores created_at but nothing checks age on lookup, so a leaked session id is valid forever.
- [ ] Add Secure + SameSite=Lax to the session cookie
- [ ] Add a session TTL and enforce it on lookup (sqlite + memory stores)
