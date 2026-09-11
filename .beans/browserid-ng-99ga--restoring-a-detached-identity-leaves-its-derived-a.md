---
# browserid-ng-99ga
title: Restoring a detached identity leaves its derived agent identities suspended
status: todo
type: bug
priority: normal
created_at: 2026-09-11T22:16:57Z
updated_at: 2026-09-11T22:17:26Z
---

Observed in prod 2026-09-11: detaching dan@mingo.place from the account page suspended its derived agent dan+mingo@mingo.place (correct: agents go with their parent, registry-api-v1 §5.2.5); re-attaching the handle (restore) brought the handle back but the agent row stayed suspended (suspended_at 22:03:42 still set after the 22:04 restore). Restore should bring the parent's derived agents back with it (membership::identity_returns), or the spec should say they don't and mingo must re-provision.

Finding: membership::identity_returns DOES clear derived agents' suspension, so the 22:04 re-attach did not take the Restore path — the attach handler saw the handle as neither held nor suspended_on the account and ran Add (fresh row). So detach + re-attach loses the hold link (suspended_identities) or the account page's detach removes the row outright; either way the parent came back as a new identity and its agents stayed suspended. Check membership::detach vs identity_suspended_on.
