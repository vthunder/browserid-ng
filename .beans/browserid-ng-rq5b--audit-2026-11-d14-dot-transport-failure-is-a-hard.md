---
# browserid-ng-rq5b
title: '[Audit 2026-11] D14: DoT transport failure is a hard reject (retry once), never an insecure answer'
status: completed
type: bug
priority: high
created_at: 2026-11-02T22:43:19Z
updated_at: 2026-11-03T08:25:05Z
parent: browserid-ng-ag1l
---

Findings: D14 (WS1/WS6). Severity: Medium. Decision: Q2 settled 2026-11-02: (b) retry once with a short budget (reference 2 s), then hard reject. Spec §3 (amended) says transport failure is a hard reject, not "insecure".

Where: browserid-dnssec/src/dns.rs:139-184 (lookup: unparsable name, failed TLS connect, send error, empty response -> DnsLookupResult::insecure()), :545-548 (Refused and other rcodes -> insecure), :273-276 and lib.rs:268 (Insecure -> ResolveError::NotPrimary -> fallback path). The existing unit test test_refused_is_insecure_not_bogus pins the wrong answer.

What: with port 853 blocked (A7) a domain that runs a primary is treated as no-primary for the duration, so a fallback-issued cert for its identities passes step 2. Bounded (the fallback checks the same DNS and the attacker still needs its mailbox proof) but it is the B1 boundary the spec says holds unconditionally; fallback_to_broker already treats its own Insecure as a hard error, so the asymmetry is accidental.

Change: return a distinct transport-failure variant (or bogus()) from every non-answer path in lookup; map Refused and unexpected rcodes to it; retry the DoT connect once within a ~2 s budget before failing; have discover surface it as VerifierError::Discovery rather than falling back. Flip test_refused_is_insecure_not_bogus.

Acceptance (un-ignore) in browserid-dnssec/tests/audit_2026_11_ws6.rs: d14_transport_failure_is_not_an_insecure_answer, d14_resolve_idp_key_does_not_report_not_primary_on_transport_failure.

Reports: ws6 §1.4. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.


## Summary of Changes

- browserid-dnssec/src/dns.rs: `lookup` is now one `exchange()` (connect + EDNS DO query + first response → `Result<Message, String>`) run in a retry loop: on transport failure it retries once if less than `TRANSPORT_RETRY_BUDGET` (2 s, pub const) has elapsed since the first attempt began, then returns `DnsLookupResult::bogus()`. Every non-answer path is now Bogus: unparsable name, connect/TLS failure, send error, timeout, empty response, and `classify_response`'s REFUSED/NOTIMP/FORMERR/other rcodes. No new `DnssecStatus` variant (core untouched): transport failure maps to Bogus, which every consumer already hard-rejects (`FallbackFetcher` → `VerifierError::DnssecValidationFailed`; `resolve_idp_key` → `ResolveError::Bogus`). Module doc and `ResolveError::Bogus` doc updated; `test_refused_is_insecure_not_bogus` flipped to `test_refused_is_bogus_not_insecure` (covers Refused/NotImp/FormErr).
- browserid-verifier/src/discovery.rs: `fallback_to_broker` short-circuits for a localhost dev broker (`dev_local_broker`) and reads the loopback broker's `.well-known` key without any DoT lookup — the pre-existing dev path, but it used to be reached only through an Insecure answer, which an offline dev box would now get as a hard reject. Real domains are unchanged.
- Acceptance: `d14_transport_failure_is_not_an_insecure_answer`, `d14_resolve_idp_key_does_not_report_not_primary_on_transport_failure` un-ignored (resolver = 127.0.0.1:1, connection refused, no network); new `d14_retry_once_within_budget_then_reject` bounds the lookup time. dnssec: 18 unit + 3 integration pass.
- Side effect to note: the hosted-IdP domain probe (browserid-broker/src/routes/hosted_idp.rs:979) now reports "bogus" instead of "insecure" when the DoT resolver is unreachable, which is the honest reading.
