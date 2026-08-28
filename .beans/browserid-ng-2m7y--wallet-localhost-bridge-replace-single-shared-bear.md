---
# browserid-ng-2m7y
title: 'Wallet localhost bridge: replace single shared bearer token with per-caller tokens + attestation'
status: todo
type: task
priority: low
created_at: 2026-08-27T19:28:40Z
updated_at: 2026-08-27T19:28:48Z
blocked_by:
    - browserid-ng-b8q0
    - browserid-ng-bd19
    - browserid-ng-dgsg
---

The wallet's localhost bridge authenticates callers with ONE shared 24-byte bearer token (wallet/src/store.js pairToken; wallet/src/server.js x-wallet-token). Whoever holds the string can mint; pairers overwrite each other's token; nothing binds the token to a specific caller. This is the deeper design fix behind the tactical hardening beans.

## Direction (bigger design question — not urgent)
- Per-caller tokens keyed by extension id / caller identity, so revoking or distinguishing one caller doesn't affect others and a stolen token is scoped.
- Some form of caller attestation (extension id binding at minimum; process attestation is a stretch on macOS).
- Revisit the whole bridge trust model: is a bearer token over loopback HTTP the right primitive, or should this be a native messaging host / unix socket with OS-level peer credentials?

## Context
Flagged during gxi9 wallet review 2026-08-27. The tactical fixes (b8q0 wildcard CORS, pairing-caller-identification, richer per-login confirm) reduce exposure without this; do this when the wallet moves past prototype-grade bridge security.
