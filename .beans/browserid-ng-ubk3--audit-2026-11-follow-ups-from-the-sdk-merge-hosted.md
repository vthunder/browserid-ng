---
# browserid-ng-ubk3
title: '[Audit 2026-11] Follow-ups from the SDK merge: hosted /verify returns expires_at; sdk/agent mirrors the D1 exact-identity rule'
status: todo
type: bug
priority: normal
created_at: 2026-11-03T08:48:28Z
updated_at: 2026-11-03T08:48:28Z
parent: browserid-ng-ag1l
---

Two small items left by the SDK remediation (merge f98cc05):

1. W4-13 (bean fqnh) caps Lane A bearers at the verifier's expires_at, but hosted /verify (browserid-verifier) does not return expires_at yet; only /validate-record does. Add expires_at (min of access cert, warrant and assertion exp) to the /verify response so the cap bites. Acceptance: fqnh's tests with a recorded /verify response carrying expires_at; the SDK fallback to the 1 h cap stays.

2. D1 client mirror: sdk/agent has a skipped test (AUDIT-2026-11 D1) for authorizesIdentity; mirror core's rule (auth certs exact; subaddressing only for config certs as grantor) and un-skip it.
