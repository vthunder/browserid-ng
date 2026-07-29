---
# browserid-ng-c5n5
title: '[H1] Blind SSRF in foreign status-list fetch'
status: completed
type: bug
priority: high
created_at: 2026-07-28T23:53:20Z
updated_at: 2026-07-29T01:18:04Z
parent: browserid-ng-wre6
---

Full detail in docs/security-audit-2026-07-29.md (H1). check_foreign_status fires status_http().get(&r.uri) as the FIRST action after cache miss (broker/verifier.rs:196), before parse/uri_matches_issuer/token.verify (which gate only response interpretation). No redirect policy (reqwest follows up to 10), no scheme allowlist, no private-IP/loopback/link-local block. r.uri is attacker-authored; reachable unauthenticated via POST /verify-access (caller-controlled accepted_fallbacks) and /guestbook. Blind, but timing + distinct error strings form a host/port oracle and redirects reach 169.254.169.254 from an HTTPS origin.

- [ ] Require https scheme
- [ ] Resolve + reject private/loopback/link-local IPs; pin resolved IP for the connection (anti-rebinding)
- [ ] Disable redirects
- [ ] Cap response body (see M4)

## Summary of Changes
H1 fixed: validate_status_url (https-only, private/loopback/link-local/ULA rejected), redirects disabled, streaming body cap. allow_private_hosts flag relaxes for localhost/tests only.
