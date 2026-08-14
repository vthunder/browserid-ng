---
# browserid-ng-qmvw
title: 'Broker: connection grant requests + audience proof + consent connection variant + authoring ceremony + /account rendering'
status: completed
type: task
priority: normal
created_at: 2026-08-14T16:48:45Z
updated_at: 2026-08-14T17:36:41Z
parent: browserid-ng-rjmm
---

Phase-1 item 2 (build order in rjmm handoff), per spec §7.5:

- [x] POST connection request endpoint (/warrant/record-request, both connection+authoring types) ({type: connection, audience, scopes, client, message?} → request_id/challenge/consent_uri/expires_in/interval)
- [x] Audience-proof fetch (BrokerProofFetcher w/ SSRF guard; gate+claim in list_requests): /.well-known/browserid-audience-proof/<request_id> at audience origin — TLS, no redirects, public-unicast-only resolution, short timeout, verbatim nonce compare (trailing-ASCII-whitespace strip), fail-closed; proof gates consent-page render
- [x] Consent card connection variant ('Connect <client_name> (<client_host>) to <audience>' — client_name marked as reported by the site; full audience incl. path; deliberate approval)
- [x] Approval mints binding.id (minted at request, pinned at respond), signs self-grant v2 connection record with approver config cert, stores registry row with id↔record pairing (§6.6 inv 5) + status index
- [x] Poll with {request_id} (serde alias on /warrant/poll): pending/approved/denied/expired/429; approved delivers warrant~config_cert
- [x] Grant-authoring ceremony ({type: authoring, grants:[{grantee, audience, scopes}]}, shared-origin rule, same proof, JIT consent rules + per-row grantee prominence, delivery of record+config-cert pairs)
- [x] Support advertisement (SupportDocument record-grants field) (discovery flag) so resources can capability-detect
- [x] /account renders connection records as host↔service connections (revocable)
- [x] Rate limit connection requests per audience origin (RecordRequestLimiter, 10/10min)
- [x] CSP inline-script hashes updated (account.html + consent.html)
- [x] Tests green (5 new integration tests in connection_record_test.rs; full workspace green; consent-touching e2e specs checked — 2 failures reproduce identically on the base commit, pre-existing), commit

## Summary of Changes

- **registrar**: models gain RequestKind (agent|connection|authoring) + RecordRequestMeta (challenge/proof_ok/client/binding_id) on WarrantRequestRecord, grantee on WarrantGrantItem, binding_id on WarrantRecord; new POST /warrant/record-request (both types: shape validation, audience-origin rule, per-origin RecordRequestLimiter 10/10min, binding.id minted with the request); /warrant/poll accepts request_id alias; list_requests surfaces record rows only via deep link AFTER the audience proof verifies (AudienceProofFetcher trait, trailing-whitespace-stripped byte compare) and claims them (binds account, allocates status idx — connection subject cn|user|binding_id, authoring per (grantee,audience,scopes)); respond_record validates the signed v2 records against the pending request (typ v2, grantor owned+covered, audience+scopes exact, status ref exact, connection: binding.id/client_host/client_name pinned; authoring: holder binding + grantee per row) and stores registry rows.
- **broker**: proof_fetch.rs BrokerProofFetcher (reuses the status-fetch SSRF guard: TLS, no redirects, public-unicast-only, 5s, 4KiB cap); sqlite migration v28 (kind + record_meta columns); upsert key folds binding_id so connections stay distinct rows; registry row map recovers binding_id from the stored JWS; WarrantInfo exposes binding_id/client_host/client_name; SupportDocument record-grants field advertised when consent surface on.
- **static**: consent.html — signWarrantV2 + connection card (client_name marked as-reported, full audience, deliberate approve) + authoring card (per-row grantee equal prominence) + signing-identity selector; account.html — connection rows render as host↔service connections (sentinel holder keeps them off device actors), revocable via existing controls. CSP hashes updated.

Deferred (follow-up): per-mint status-snapshot retention for audit (§6.4 SHOULD) — needs /validate-record to return the signed status-list tokens.
