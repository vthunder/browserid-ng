---
# browserid-ng-1g9j
title: 'Verifier v2 support: core parsing, operation P updates, operation A record validation, broker validate-record endpoint'
status: completed
type: task
priority: normal
created_at: 2026-08-14T15:55:33Z
updated_at: 2026-08-14T16:42:34Z
parent: browserid-ng-rjmm
---

Phase-1 item 1 of warrant v2 (bean rjmm). Implement browserid-warrant-v2 in the verifier per committed spec: §5 (binding slot, fail-closed kinds/protocols, grantee matchers, identity comparison, status REQUIRED, v1 compat), §6.1 steps 1+6 (operation P), §6.4 steps 1a-1e (operation A record validation, full §4.7 constraints, live expiry split), plus the NEW hosted two-object record-validation endpoint (warrant~config_cert, no caller auth). /verify-access behavior unchanged for v1.

- [x] Core: §5 identity comparison (domain lowercase+A-label, local byte-exact; grantee matchers * and *@domain, subdomains excluded, subaddresses covered) — new identity.rs
- [x] Core: Binding enum (holder|connection, fail-closed unknown kind/protocol), dual-version WarrantClaims + parse validation matrix, Warrant::create_v2 (v1 wire frozen: holder Option + skipped binding field)
- [x] Core: operation P updates (reject connection-bound + matcher-grantee in bundles; §5 comparison in step-6 join; binding-aware holder matcher)
- [x] Core: operation A RecordBundle (warrant~config_cert) validate steps 1a-1d + live-expiry recheck + holder-path subject matching — new admission.rs
- [x] Broker: validate_record_with_dns (resolution + fail-closed status 1e) + POST /validate-record route (device.rs handler mirrors /verify-access)
- [x] Tests green (ssh localtest), workspace builds — full workspace suite, 53 suites ok
- [x] Commit + update rjmm

## Summary of Changes

- **browserid-core/src/identity.rs** (new): §5 identity comparison — `identity_eq`/`domain_eq` (domain lowercased + A-label via idna, local byte-exact), `is_grantee_matcher`, `grantee_covers` (`*` = any authenticated email; `*@domain` covers subaddresses, not subdomains).
- **browserid-core/src/device.rs**: `TYP_WARRANT_V2`; `Binding` enum (`holder`/`connection`, serde-tagged so unknown kind/protocol fail deserialization → fail-closed) + `ConnectionProtocol::Oauth`; `WarrantClaims` now dual-version (`holder: Option<HolderMatcher>` v1, `binding: Option<Binding>` v2 — v1 wire byte-frozen, golden vectors unchanged) with `binding()`/`holder_matcher()` normalized accessors; `Warrant::parse` enforces the per-version shape matrix (v2 requires binding+status, no hybrid records, connection ⇒ self-grant + nonempty id/client_host, grantor never a matcher); `Warrant::create_v2` (status non-optional, refuses malformed per invariants 3/4). Operation P: §6.1 step 1 explicit rejects (connection-bound, matcher-grantee) before crypto; step 6 join uses §5 identity comparison + binding-aware matcher.
- **browserid-core/src/admission.rs** (new): operation A — `RecordBundle` (`warrant~config_cert`, strict 2-object parse), `validate()` = §6.4 steps 1b–1d (config-cert verify/purpose/identities-cover-grantor, warrant under config key, audience exact, full §4.7 constraints), `recheck_live()` (per-use validity-window re-check), `ValidatedRecord` with `status_refs()` (caller step 1e) and `matches_login()` (§6.4 step 3 holder path, fail-closed for connection bindings and non-* matcher vs holder-less login).
- **browserid-broker/src/verifier.rs**: `validate_record_with_dns` + `RecordValidationResult` — resolves config-cert issuer via `resolve_conformant_key` (authoritative for grantor domain), core validate, fail-closed status on both refs; returns grantor/grantee/binding/scopes/status_refs/expires_at.
- **browserid-broker/src/routes/device.rs + mod.rs**: `POST /validate-record` (no caller auth), mirrors the /verify-access handler shape. /verify-access itself unchanged.
- **browserid-agent**: `add_grant` uses `holder_matcher()`, rejects admission-only records (agents present). **browserid-registrar/consent.rs**: consent flow requires holder-bound warrants; registry record maps holder via accessor.
- Tests: identity unit tests; v2 parse matrix incl. raw-JWS unknown kind/protocol; P rejects + §5-comparison join; binding wire shape pinned to spec example; admission suite (happy path, wrong audience/signer/purpose/grantor, constraints in full, live expiry, v1-as-holder-binding, matches_login matrix); broker validate_record conformance (okay/audience/nonauthoritative-issuer/fail-closed status/v1/garbage shapes). Full workspace green.

Not in scope here (phase 1 items 2–3, phase 2–3): broker consent-card connection variant, binding.id mint + registry pairing, request endpoint + audience-proof fetch, /account rendering, mcp-auth credential-less lane.
