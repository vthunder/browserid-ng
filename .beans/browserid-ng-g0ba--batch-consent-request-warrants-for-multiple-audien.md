---
# browserid-ng-g0ba
title: 'Batch consent: request warrants for multiple audiences in one approval'
status: completed
type: feature
priority: normal
created_at: 2026-07-10T18:32:04Z
updated_at: 2026-07-10T18:57:17Z
---

Follow-on to pz0f (2026-07-10, vthunder): an agent often needs several audiences at once — e.g. `https://mingo.place` (web service) and `sbo://mingo.place` (ledger writes, sbo-8t4b) — and asking the principal to approve twice is needless friction.

## Design (keeps the warrant atom single-audience)

Warrants are unchanged: one `aud` each, N warrants come back. Only the request/consent layer batches:

- **Request (`R`, action=warrant)**: replace `warrant-aud`/`warrant-scopes` with `warrant-grants: [{aud, scopes?}, …]` (per-audience scopes — web and ledger vocabularies differ). Cap the batch (e.g. ≤8). Keep single-field form accepted for compat or bump the request typ.
- **Broker**: WarrantRequestRecord holds the grant list; consent page renders every requested grant (each with verified audience + its scopes); approval is all-or-nothing in v1 (one deliberate action covering the displayed set — per-item toggles later if wanted); the page signs N warrants; delete-on-delivery unchanged (until jipx lands).
- **Poll**: `{status: "approved", warrants: ["…", …]}` (array; keep `warrant` populated when N==1 for compat).
- **SDK**: `request_warrants(&[(aud, scopes)])` / `obtain_warrants(...)`; add_warrant each on pickup. agent_cli takes multiple audiences.
- **Spec**: §6.2/§6.4 update + a worked https+sbo example.

## Notes
- Privacy analysis unchanged: the batch exists only in the pending request (and each RP still sees only its own warrant).
- Consent-fatigue: the screen must render every audience with equal prominence — no folding N grants behind one summary line.

## Summary of Changes

Shipped 2026-07-10. Core: warrant-grants: [{aud, scopes?}] (1..=8, deduped) replaces warrant-aud/-scopes; ProvisioningRequest::warrant takes the grant list; WarrantGrant + MAX_WARRANT_GRANTS exported. Broker: request/record/poll/respond all batch-shaped (migration v7 drops+recreates the ephemeral table); poll returns warrants[] with warrant kept for N==1; respond validates one signed warrant per grant against its grant, all-or-nothing. Consent page renders every grant with equal prominence and signs one warrant per grant (each logged locally). SDK: request_warrants/obtain_warrants + single-audience wrappers; handle carries audiences[]. agent_cli grant <aud> [aud...]. Spec §4.1/§6.2/§6.3/§6.4 updated with an https+sbo worked example. New e2e: two-audience (https + sbo://) one-approval roundtrip incl. per-audience scope isolation and skip-already-held.
