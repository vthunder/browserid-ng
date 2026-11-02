---
# browserid-ng-zsi1
title: '[Audit 2026-11] W2-6: DnsRecord::parse rejects a repeated field'
status: todo
type: bug
priority: normal
created_at: 2026-11-02T22:43:20Z
updated_at: 2026-11-02T22:43:20Z
parent: browserid-ng-ag1l
---

Findings: W2-6. Severity: Low (robustness; exploiting it needs zone write access, which already means owning the key; the hazard is a zone-editing mistake that leaves a stale key live and invisible). Decision: none needed (B5: an ambiguous root rejects).

Where: browserid-core/src/dns.rs:30-45: DnsRecord::parse loops over ;-separated fields and overwrites on repeats, so public-key=A; public-key=B yields B with no error; same for v, the algorithm and host. browserid-dnssec already rejects two records (test_multiple_browserid_records_signed_is_bogus); this is the within-record twin.

Change: reject a repeated field name in DnsRecord::parse. Update the dns_txt fuzz target's oracle ("key byte-equal to the last public-key= field") and the ws3 property dns_txt_parser_is_total_and_never_upgrades accordingly.

Acceptance: delete the W2-6 row (T-REJ-11) from EXPECTED_FAIL in browserid-core/tests/audit_2026_11_ws2_runner.rs.

Reports: ws2 §2. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.
