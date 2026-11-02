---
# browserid-ng-rq5b
title: '[Audit 2026-11] D14: DoT transport failure is a hard reject (retry once), never an insecure answer'
status: todo
type: bug
priority: high
created_at: 2026-11-02T22:43:19Z
updated_at: 2026-11-02T22:43:19Z
parent: browserid-ng-ag1l
---

Findings: D14 (WS1/WS6). Severity: Medium. Decision: Q2 settled 2026-11-02: (b) retry once with a short budget (reference 2 s), then hard reject. Spec §3 (amended) says transport failure is a hard reject, not "insecure".

Where: browserid-dnssec/src/dns.rs:139-184 (lookup: unparsable name, failed TLS connect, send error, empty response -> DnsLookupResult::insecure()), :545-548 (Refused and other rcodes -> insecure), :273-276 and lib.rs:268 (Insecure -> ResolveError::NotPrimary -> fallback path). The existing unit test test_refused_is_insecure_not_bogus pins the wrong answer.

What: with port 853 blocked (A7) a domain that runs a primary is treated as no-primary for the duration, so a fallback-issued cert for its identities passes step 2. Bounded (the fallback checks the same DNS and the attacker still needs its mailbox proof) but it is the B1 boundary the spec says holds unconditionally; fallback_to_broker already treats its own Insecure as a hard error, so the asymmetry is accidental.

Change: return a distinct transport-failure variant (or bogus()) from every non-answer path in lookup; map Refused and unexpected rcodes to it; retry the DoT connect once within a ~2 s budget before failing; have discover surface it as VerifierError::Discovery rather than falling back. Flip test_refused_is_insecure_not_bogus.

Acceptance (un-ignore) in browserid-dnssec/tests/audit_2026_11_ws6.rs: d14_transport_failure_is_not_an_insecure_answer, d14_resolve_idp_key_does_not_report_not_primary_on_transport_failure.

Reports: ws6 §1.4. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.
