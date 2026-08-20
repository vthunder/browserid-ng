---
# browserid-ng-y9vr
title: 'Client keystore health check: drop expired/revoked/stale-class certs proactively'
status: completed
type: feature
priority: normal
created_at: 2026-08-20T06:54:01Z
updated_at: 2026-08-20T07:11:51Z
---

Owner proposal (2026-08-20): an honest client should proactively check its local store instead of presenting credentials that are already dead. Agreed framing: hygiene, never enforcement — server gates stay load-bearing; dropping local state is always safe (worst case = one re-issue through the proper ceremony).

Design:
- Local pass, EVERY load (dialog + /account, no network): parse each saved device/config pair, drop expired (exp within 60s) and unparseable records.
- Remote pass, session-gated: GET /wsapi/device_certs and drop local pairs whose registry row is revoked or absent; also drop pairs whose cert prov claim mismatches the address's current proof class (list_emails proofs). /account: every load. Dialog: throttled to once/day (localStorage stamp) to keep sign-in latency flat.
- Depends on x5c3 for registry honesty (rows stamped on gate/class revocations) so the remote diff is trivial.

## Summary of Changes (2026-08-20)

- keystore.js: `healthLocal()` (no network — drops expired-within-60s and unparseable device records) and `healthRemote(registryCerts, proofs, brokerHost)` (drops pairs whose registry row is revoked (any issuer) or missing (broker-issued only — foreign issuers own their own lists), and pairs whose issued-under `prov` class mismatches the address's current proof class). Best-effort deletions, drop counts returned.
- Dialog: healthLocal at every boot before any flow consults the cache; healthRemote in the authenticated boot, throttled to once/24h (localStorage stamp).
- /account: both passes on every load inside reloadAccount, before refreshKeystore — registry + proofs already fetched there, zero extra requests. account.proofs retained.
- Framing: hygiene, never enforcement — server gates stay load-bearing; the client just never presents a credential it can already know is dead. CSP hash updated. e2e 105/105.
