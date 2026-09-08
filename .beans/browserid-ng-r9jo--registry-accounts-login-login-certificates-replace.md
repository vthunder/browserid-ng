---
# browserid-ng-r9jo
title: Registry accounts + login + login certificates (replaces the guard)
status: draft
type: feature
priority: high
created_at: 2026-09-08T14:09:50Z
updated_at: 2026-09-08T14:09:50Z
---

Dan's redesign 2026-09-08 after the guard screen confused him on mingo sign-in: accounts are first-class (create explicitly, discover by identity proof); login on an account by a registry-offered method (password first, stored_key = registry-signed login cert, device/identity later) yields a session; every operation runs under a session; guard tokens and fields go. Review draft: docs/plans/2026-09-08-registry-login-draft.md. Blocks nothing until ruled; then: spec edit (§4.2, §4.5, §5.2, §5.1), broker + registrar changes, dialog + wallet, delete /guard + /wsapi/guard.
