---
# browserid-ng-jaa1
title: 'Decide: revoke outstanding certs when a domain''s authority flips'
status: draft
type: task
created_at: 2026-07-30T20:35:08Z
updated_at: 2026-07-30T20:35:08Z
parent: browserid-ng-tsqk
---

Re-deriving the hierarchy does not invalidate already-issued certs, so after a flip the previous owner keeps a working cert until expiry (90d) while the new owner holds a fresh one. Flipping status bits on authority change closes the window and is cheap with existing machinery.

Sounds correct but possibly harsh — DECIDE BEFORE IMPLEMENTING. Treat as one instance of the larger deferred question: how should BrowserID handle identifiers changing hands in general?
