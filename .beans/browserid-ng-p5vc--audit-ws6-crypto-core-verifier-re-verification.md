---
# browserid-ng-p5vc
title: 'Audit WS6: crypto core + verifier re-verification'
status: todo
type: task
priority: normal
created_at: 2026-11-01T12:40:56Z
updated_at: 2026-11-01T15:43:06Z
parent: browserid-ng-ag1l
---

browserid-core (jws, keys, assertion, attestation, admission, device certs, status), browserid-verifier, browserid-dnssec. Re-verify July 'sound' verdict rather than assume it; new since July: device certs, admission, typed signing, attestation. Check verification ordering, time handling, key/sig length pins, DNSSEC fail-closed.

## From WS1 — candidates to confirm/refute
D1 subaddress widening at mint (core device.rs:96-111 + both mint routes); D7 /verify drops scope parameters; D14 DoT transport failure demotes primaries; D15 browserid-rp status path (no host==iss, redirects, no private-IP guard, ttl grace uncapped) and registrar validity bar; D16 iat unbounded. Agents found core verify_at/admission::validate conformant on the headline §6.1/§6.4 items; re-verify rather than assume. See docs/security-audit-2026-11-ws1-spec-review.md §1.
