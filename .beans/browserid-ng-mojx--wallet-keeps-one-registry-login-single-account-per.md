---
# browserid-ng-mojx
title: Wallet keeps one registry login (single account per wallet), never per identity
status: completed
type: bug
priority: high
created_at: 2026-09-11T20:40:29Z
updated_at: 2026-09-11T22:17:12Z
---

common/js/registry-session.js tracks the registry account PER IDENTITY (browserid:registry:account:<identity>) and, for an identity with no cached account whose lookup returns 404, CREATES a new registry account around it (ensure → createAccount). A freshly minted derived identity (mingo handle) therefore got its own account next to the user's real one (Dan, 2026-09-11). Fix: one wallet account + one login key per registry host; every sign-in logs into that account and ATTACHES the identity's certs (join / transfer with an explicit confirmation screen); createAccount only when the wallet has no account at all. Healing falls out: the next sign-in of the split identity transfers it into the wallet's account. Related: chooser-from-registry bean.

## Summary of Changes

registry-session.js keeps one wallet account + login key per registry host; ensure() logs into it and attaches each identity (join / restore / confirmed transfer via askTakeover); account creation only when the wallet has none. Dialog takeover screen. registry-api-v1 §4.5 states the rule. Verified in prod 2026-09-11: a brand-new handle (foo@mingo.place) joined the existing account (user 1) with its parent link; user count unchanged.
