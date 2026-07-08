---
# browserid-ng-y2ho
title: CSRF token is generated but never enforced
status: todo
type: bug
priority: high
created_at: 2026-07-08T06:13:39Z
updated_at: 2026-07-08T06:13:39Z
parent: browserid-ng-8u60
---

session_context returns csrf_token but NO state-changing handler reads/compares it. Practical CSRF only incidentally blocked (application/json requirement + CORS Any without allow_credentials).
- [ ] Enforce csrf_token on all POST /wsapi mutations, OR remove it so it doesn't imply protection
- [ ] Tests
