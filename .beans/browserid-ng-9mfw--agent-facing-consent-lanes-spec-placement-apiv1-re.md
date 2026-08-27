---
# browserid-ng-9mfw
title: 'Agent-facing consent lanes: spec placement, /api/v1 reparenting, DPoP auth'
status: todo
type: task
created_at: 2026-08-27T14:14:54Z
updated_at: 2026-08-27T14:14:54Z
---

Raised by Dan reviewing the registry-api-v1 skeleton (2026-08-28). The requester-side lanes (/warrant/request, /warrant/poll, /warrant/record-request, /agent-provision/*) are today out of scope of registry-api-v1 (approver side). Decide:

(a) own spec doc in the same API family vs folding into registry-api-v1;
(b) either way, reparent the routes under /api/v1/* to match the family (legacy paths kept as aliases);
(c) whether their auth should adopt the DPoP-style proof model from registry-api-v1 §3 (today: device-cert-signed request bodies, code-as-credential polling).
