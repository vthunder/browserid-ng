---
# browserid-ng-rn46
title: '[Audit 2026-11] W6-3/W5-8: status-list decoder inflates before the cap (zlib bomb via /status/proxy); bound the encoder too (W3-4)'
status: completed
type: bug
priority: high
created_at: 2026-11-02T22:43:19Z
updated_at: 2026-11-03T08:11:25Z
parent: browserid-ng-ag1l
---

Findings: W6-3 (= W5-8), plus W3-4 (encoder side, Low). Severity: High (DoS). Decision: none needed. WS8 PoC: a ~1 MB payload inflates to 768 MiB; RSS 9 MiB -> 845 MiB during one decode call.

Where: browserid-core/src/status.rs:96-108 (StatusList::decode: ZlibDecoder read_to_end, then the 4 MiB cap); status.rs:66-81 (from_revoked / set allocate on an unbounded index). Reachable unauthenticated via GET /status/proxy?uri= (browserid-broker/src/routes/status.rs:46) and every foreign status fetch; July M4's 4 MiB body cap applies to the compressed bytes only.

Change:
- decode: wrap the decoder in take(MAX + 1) before read_to_end and reject on > MAX, so the inflated allocation never exceeds the cap.
- from_revoked / set: bound capacity and idx (checked arithmetic, hard ceiling matching the 4 MiB list size) so a publisher-side bug cannot allocate gigabytes (W3-4).
- Remove the 32 MiB-inflating seed guard note in fuzz/fuzz_targets/status_list.rs if it exists; the status_list fuzz target should keep running.

Acceptance (un-ignore):
- browserid-core/tests/audit_2026_11_ws6_bomb.rs: w6_3_oversized_status_list_is_rejected_without_inflating_it
- browserid-core/tests/audit_2026_11_ws3_status_alloc.rs: decode_allocation_is_bounded_for_any_input
- browserid-core/tests/audit_2026_11_ws8_w6_3.rs (PoC; flips to asserting peak RSS stays near the cap)

The /status/proxy route hardening (rate limit, generic error, uri constraint) is the W6-5/W5-5 bean.

Reports: ws6 §2, ws5 §2 (W5-8), ws3 §3 (W3-4), ws8 §3. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.



## Summary of Changes

- browserid-core/src/status.rs: `StatusList::decode` pre-sizes the inflate buffer from the compressed length (capped) and reads through `Take(STATUS_LIST_MAX_BYTES + 1)`, so an over-cap list rejects without ever inflating past 4 MiB. `from_revoked` clamps capacity to `STATUS_LIST_MAX_INDEX` with checked arithmetic (sizing formula unchanged so golden vectors stay byte-identical); `set` ignores an index past the ceiling, new `try_set` reports it (W3-4).
- New public consts `STATUS_LIST_MAX_BYTES` (4 MiB) and `STATUS_LIST_MAX_INDEX`, re-exported from the crate root. No signature changes to existing API.
- Acceptance un-ignored: ws6_bomb `w6_3_oversized_status_list_is_rejected_without_inflating_it`, ws3_status_alloc `decode_allocation_is_bounded_for_any_input`; WS8 PoC flipped to assert RSS growth < 32 MiB on the 768 MiB bomb.
- fuzz: status_list target doc + README note updated (seed stays; it now exercises the bounded path).
