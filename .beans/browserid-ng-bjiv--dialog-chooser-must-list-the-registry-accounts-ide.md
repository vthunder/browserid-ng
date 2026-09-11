---
# browserid-ng-bjiv
title: Dialog chooser must list the registry account's identities, never the broker cookie's list or a local cache
status: todo
type: bug
priority: high
created_at: 2026-09-11T20:40:29Z
updated_at: 2026-09-11T20:40:29Z
---

Today the chooser is populated from /wsapi/list_emails under the broker cookie session, and when that session is missing it falls back to a REMEMBERED chooser from localStorage (recallAccountEmails, v2nb). Both are wrong: the cookie must not be able to list the account's emails (registry-api-v1: identity certs never open a session; the registry session is the authority on membership), and a local cache can show identities that are not on the account (Dan hit this 2026-09-11: the chooser offered a handle that lived on a different registry account). Required: the dialog establishes its registry login (single wallet account) FIRST, lists identities from the registry account (GET the account's identities over the token lane), and only then shows the chooser; no cold/remembered chooser. Depends on the single-registry-login change in registry-session.js.
