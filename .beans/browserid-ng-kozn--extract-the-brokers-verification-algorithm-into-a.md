---
# browserid-ng-kozn
title: Extract the broker's verification algorithm into a shared crate; browserid-rp consumes it
status: in-progress
type: task
priority: high
created_at: 2026-07-24T13:29:12Z
updated_at: 2026-08-25T20:32:27Z
---

Direction from Dan (2026-07-24): there must be ONE verification implementation. Today three exist at different fidelity: browserid-core AccessPresentation::verify (crypto join — shared, good), browserid-broker verifier.rs (DNSSEC discovery + primary/fallback conformance + fail-closed status, post-4lxl), and browserid-rp Verifier (pinned/well-known trust table + conformance added in xux4). Either an RP outsources to the hosted /verify-access, or it should run the SAME algorithm the broker runs.

Plan: extract verify_access_with_dns + the Discoverer/DNSSEC machinery (fallback_fetcher, dns_fetcher) from browserid-broker into a crate (e.g. browserid-verifier) consumed by both the broker and browserid-rp; the rp pinned-table mode remains only as an offline/test convenience. Related: audit B1 (broker/core cross-issuer contradiction — fix it in the extracted crate once, i9rr), xux4 (conformance patch this supersedes), 4lxl (fail-closed status lives in the same algorithm). First consumer: the bsky bridge (browserid-bsky), which outsources to hosted /verify-access until this lands.

## Decisions (2026-08-25)

- Crate: NEW workspace member `browserid-verifier` (not folded into browserid-dnssec — keeps the trust-root crate dep-light). Dockerfile workspace-member edit required.
- rp behavior: fail-closed status checks become the default when verify_dnssec is rebacked by the shared crate; `without_status_checks` survives as a documented non-conformant offline/test escape hatch.
- Note: drift is worse than described above — browserid-rp has since grown its own `verify_dnssec` (direct browserid-dnssec key resolution, no fallback-broker/host= logic, no foreign-status fail-closed machinery). Extraction unifies these.
