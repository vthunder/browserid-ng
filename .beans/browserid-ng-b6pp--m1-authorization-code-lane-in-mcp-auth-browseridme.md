---
# browserid-ng-b6pp
title: 'M1: authorization-code lane in mcp-auth + browserid.me approval-return endpoint'
status: in-progress
type: feature
priority: high
created_at: 2026-08-12T12:21:46Z
updated_at: 2026-08-12T14:30:17Z
parent: browserid-ng-81s6
---

THE critical path. mcp-auth today advertises only grant_types_supported:[jwt-bearer], no authorization_endpoint, no DCR — a generic host (claude.ai) can't do the paste-URL-approve-done flow. Add: discovery fields (authorization_endpoint, authorization_code grant, S256 PKCE); Dynamic Client Registration (RFC 7591, POST /register); GET /authorize (PKCE, redirects browser to a browserid.me warrant-approval page carrying audience=resource + scopes + return_url); POST /token authorization_code grant (verify PKCE, redeem code for the approved warrant, mint the same fail-closed bearer as Lane A). On browserid.me: a browser warrant-approval-with-return_url endpoint reusing the existing consent UI + keystore signing. Grantee model: start (A) gateway-as-agent (gateway provisions one identity; warrants name it grantee, connecting human grantor), design toward (C) warrant-to-holder-key. Prove headless via curl: discover→register→authorize→code→token→gated tools/call. Parent epic browserid-ng-81s6.

DECISION 2026-08-12: grantee model is A now, B eventually, SKIP C. C lets the connecting human self-revoke their own sub-agents but leaves the OWNER blind (opaque holders); B gives owner-meaningful named sub-identities (friend+claude@…) reusing the managed-agent path hardened today. Keep the warrant status ref per-warrant (per grantor) so A→B is additive.

## M1 mechanism (verified 2026-08-12 against consent.rs)
Lane B = wrap the EXISTING §6.6 external warrant-request + RFC-8628 poll in an OAuth shell. The gateway authenticates to POST /warrant/request with its own agent device cert, gets /consent/<code>, human approves in-browser (picks which identity delegates), gateway picks up warrant~config_cert via POST /warrant/poll. The ONE new broker piece: an origin-validated optional return_url on /consent so the browser redirects back to the gateway after approval (bridges OAuth-redirect ↔ browserid device-flow; the gateway still polls for the warrant as source of truth). /authorize orchestration + the gateway's DeviceAgent identity live in mcp-auth's new auth-code lane (mcp-auth gains an optional warrant-requesting client role; today it only verifies).

Build spec written: docs/plans/2026-08-12-M1-authcode-build-spec.md (module design: mcp-auth optional auth-code lane embedding a DeviceAgent; discovery/DCR/authorize/return/token signatures; broker return_url with origin validation; test plan; exit criteria).


## Build log (2026-08-12, worktree agent-a6f8fca1477878723)

Started M1 build. Plan: (1) broker/registrar return_url (request-body transport, server-side origin validation, echoed on respond, consent.html redirect) — note: spec step 4's `?return_url=` query-param transport is NOT used; the return_url travels in the POST /warrant/request body and is validated server-side against the requester's identity domain / grant audience origins, so consent.html only ever redirects to a server-validated URL (no client-side open-redirect surface). (2) mcp-auth auth-code lane: createAuthCodeLane({mcpAuth, credential, broker, fetch}) with lazy @browserid-ng/agent import, in-memory DCR/pending/code stores, shared bearer-minting helper factored out of handleToken (redeemPresentation). Multi-user hazard found in spec: DeviceAgent holds ONE grant per audience, so concurrent Lane-B users' warrants would clobber each other at the shared resource audience — fix: store the warrant~config_cert on the OAuth code record and re-addGrant under a serialization mutex right before assertionFor at token time.


## Summary of Changes (M1 build, 2026-08-12)

Built the full authorization-code lane (Lane B), both halves, all tests green.

### Broker/registrar — origin-validated return_url on the consent flow
- `browserid-registrar/src/consent.rs`: `POST /warrant/request` accepts optional `return_url`, validated UP FRONT by `validate_return_url()` — plain http(s) only (https except localhost), no userinfo/backslash/control chars, and the origin must provably belong to the requester: URL host == the agent identity's domain, OR full origin (scheme+host+port) == a requested grant audience's origin. Foreign origin ⇒ the whole request is refused (open-redirect guard). Persisted on `WarrantRequestRecord.return_url`; echoed in `RespondResponse.return_url` on approve AND deny (deny = manual-link only, page never auto-navigates on deny).
- Broker store: `warrant_requests.return_url` column, migration v27 (SCHEMA_VERSION 27); sqlite insert/select/row-map; registrar_glue maps both ways. NOTE: mingo-idp (separate repo) implements RegistrarStore directly and will need the new struct field when it updates the registrar dep.
- `browserid-broker/static/consent.html`: `resolve()` captures the respond JSON; if a (server-validated) return_url is present, the "Return to the app" button targets it and approval auto-navigates there after the announced 1.8s delay (replacing history.back() in that case). INLINE_SCRIPT_HASHES updated (consent.html hash → sha256-Dnwq3LA8...).
- Tests: `browserid-broker/tests/warrant_return_url_test.rs` (5 tests: persisted+echoed on approval, absent when not sent, foreign/spoof/scheme-downgrade/js: refused, identity-domain accepted, denial echoes) + `return_url_origin_validation` unit table in consent.rs.

### mcp-auth — the auth-code lane (Lane A untouched)
- `sdk/mcp-auth/index.mjs`: factored the Lane-A bearer mint out of `handleToken` into `redeemPresentation(presentation, scope)` (exposed on the McpAuth object) — BOTH grants terminate in it, so lane-B bearers ride the identical /verify-access (audience=resource) + store + per-call fail-closed status re-check.
- `createAuthCodeLane({ mcpAuth, credential, broker?, fetch?, label?, codeTtlS?=60, pendingTtlS?=900, returnPollTries?, returnPollDelayMs? })` returns `{ authorizationServerMetadata, handleRegister, handleAuthorize, handleAuthorizeReturn, handleToken }`. `@browserid-ng/agent` lazily imported (Lane-A-only users never load it); DeviceAgent built from the credential on first use.
- Flow: /authorize validates client_id + EXACT-match redirect_uri (throws, never redirects, on those two) → PKCE S256 REQUIRED (plain/missing ⇒ error redirect to the validated redirect_uri) → requestWarrants(audience=resource, grantor "*", returnUrl `${resource}/authorize/return?st=<32B-random>`) → 302 to consent. /authorize/return consumes the pending record (single-use), bounded-polls /warrant/poll, addGrant()s the warrant (early grantee/holder validation), mints single-use 60s code bound to client_id+redirect_uri+challenge AND carrying the warrant. /token deletes code on read, checks TTL/client/redirect/PKCE(timingSafeEqual), re-addGrant()s THIS code's warrant under a serialization mutex (fixes the multi-user shared-audience clobber the spec shape had), assertionFor(resource) → redeemPresentation.
- `sdk/agent`: `requestWarrants` gains optional `returnUrl` → `return_url` body field; version bumped 0.4.0 → 0.4.1. PUBLISH ORDER: agent 0.4.1 must go to npm before/with mcp-auth (mcp-auth deps "@browserid-ng/agent": "^0.4.1"; local tests use a node_modules symlink, gitignored).
- index.d.ts: DeviceCredential, AuthCodeLaneOptions, AuthCodeLane, Redirect, verifyPkceS256, redeemPresentation, AUTH_CODE_GRANT.
- Tests: sdk/mcp-auth 16 → 34 (16 lane unit tests: PKCE good/bad/short/charset, DCR validation incl fragment/plain-http/js:, authorize guards, denied/pending return, code single-use/TTL/bindings incl burned-on-tamper, jwt-bearer passthrough, discovery; 2 HTTP mock-broker integration tests driving discover→register→authorize→browser-302-bounce→return→token→requireWarrant with attribution + revoke-fails-closed on a Lane-B bearer, per the github-mcp mocking idiom). sdk/agent 20/20 still green.

### Test totals
- Rust: cargo test -p browserid-broker -p browserid-registrar → 39 suites, 284 passed, 0 failed (baseline 278; +5 broker integration, +1 registrar unit).
- JS: mcp-auth 34/34 (was 16), agent 20/20.

### Spec deviations (deliberate)
1. return_url transport: spec step 4 shows `?return_url=` as a query param on the consent URL; implemented via the POST /warrant/request body per the spec's own broker section — server-side validated+persisted, so consent.html never honors a client-supplied redirect (query-param transport would itself be an open redirect).
2. Denials also echo return_url (manual link only) so a denied OAuth flow can complete as error=access_denied instead of stranding the host tab.
3. Code record stores the actual warrant (spec sketch had `grantHeld:true`) — required for correctness with >1 concurrent user on the one shared resource audience.

### Curl walkthrough
Documented in sdk/mcp-auth/README.md ("curl walkthrough (local broker)"): wallet-provision the gateway identity → discovery → POST /register → openssl PKCE pair → /authorize 302 → approve in browser (browser auto-returns via the validated return_url) → POST /token within 60s → gated call; revoke at /account fails the next call closed. Real-browser localhost run left for the human (per the milestone exit criteria).

## Reviewed + merged 2026-08-12
Reviewed the security-critical parts directly: cross-user mutex (withAgent holds the lock across the async assertionFor — no interleaving; per-code warrant re-hold is correct and better than the spec sketch), validate_return_url (rejects non-http(s), origin ∈ identity-domain ∨ audience-origin — gateway rides the audience rule), verifyPkceS256 (RFC 7636 + timingSafeEqual). All sound. Merged to main (ff). Rust 284 pass, mcp-auth 34 pass. Broker return_url deploying. SDK publish (agent 0.4.1 + mcp-auth) deferred until M2 needs npx.
