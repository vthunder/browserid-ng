---
# browserid-ng-rrve
title: Second-browser-cold browsers-prefix reconciliation
status: todo
type: task
priority: low
created_at: 2026-07-21T21:02:32Z
updated_at: 2026-07-21T21:02:32Z
parent: browserid-ng-oup3
---

A SECOND browser signing in cold (account exists, browsers namespace in use) gets an IdP-self-assigned holder whose prefix cannot be adopted (adopt_namespace_prefix refuses while in use) -> lands Uncategorized until re-issue. Design + build the reconciliation (e.g. warm re-key on next login). Documented edge in the deep-dive note.
