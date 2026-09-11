---
# browserid-ng-99ga
title: Restoring a detached identity leaves its derived agent identities suspended
status: todo
type: bug
created_at: 2026-09-11T22:16:57Z
updated_at: 2026-09-11T22:16:57Z
---

Observed in prod 2026-09-11: detaching dan@mingo.place from the account page suspended its derived agent dan+mingo@mingo.place (correct: agents go with their parent, registry-api-v1 §5.2.5); re-attaching the handle (restore) brought the handle back but the agent row stayed suspended (suspended_at 22:03:42 still set after the 22:04 restore). Restore should bring the parent's derived agents back with it (membership::identity_returns), or the spec should say they don't and mingo must re-provision.
