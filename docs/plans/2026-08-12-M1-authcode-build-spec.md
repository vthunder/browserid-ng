# M1 build spec — the authorization-code lane (Lane B)

**Date:** 2026-08-12
**Parent:** epic `browserid-ng-81s6`, milestone `browserid-ng-b6pp`.
**Design:** `2026-08-12-mcp-gateway-hobbyist-to-saas.md`. Read it first.

**Goal:** a generic OAuth host (claude.ai) can `discover → register →
authorize (approve in browser) → code → token → gated tools/call` against a
BrowserID-gated MCP server, with no wallet. Exit criteria: the whole thing
proven headless with curl against a mock broker in tests, and against the
real broker on localhost.

## Architectural key: mcp-auth gains a warrant-requesting client role

Today `@browserid-ng/mcp-auth` only *verifies* a presented assertion (Lane A).
Lane B needs the AS to itself *obtain* a warrant on the user's behalf and then
*mint a presentation* to turn it into a bearer. That is exactly a
`DeviceAgent` (`@browserid-ng/agent`). So:

- Keep Lane A pure-verifier, zero new deps, unchanged.
- Add an **optional** auth-code lane, enabled only when the caller passes a
  **gateway agent credential** (the `~/.browserid` credential shape the wallet
  uses). When enabled, mcp-auth constructs a `DeviceAgent` from it and pulls
  in `@browserid-ng/agent`. Lane-A-only users never load it.

Package it as a second factory in the same module:
`createAuthCodeLane({ mcpAuth, credential, broker, fetch })` → returns the
new endpoint handlers. The gate CLI wires both; `createMcpAuth` is untouched
except for the discovery additions below.

## mcp-auth changes

### 1. Discovery (in `authorizationServerMetadata`, only when the lane is on)
Add: `authorization_endpoint: ${resource}/authorize`;
`grant_types_supported` gains `authorization_code`;
`response_types_supported: ["code"]`;
`code_challenge_methods_supported: ["S256"]`;
`registration_endpoint: ${resource}/register`;
`token_endpoint_auth_methods_supported` keep `["none"]` (public clients).
(Lane-A-only metadata stays exactly as today.)

### 2. Dynamic Client Registration (RFC 7591) — `POST /register`
In-memory client store. Accept `{redirect_uris, client_name?, ...}`, mint a
`client_id` (no secret — public PKCE clients), echo back the registration.
Validate `redirect_uris` are absolute https (or http://localhost for dev).
Store `{client_id → redirect_uris}` for the /authorize redirect_uri check.

### 3. `GET /authorize` — PKCE-guarded, bridges to the browser approval
Params: `response_type=code`, `client_id`, `redirect_uri` (must match the
registered set), `code_challenge`, `code_challenge_method=S256` (REQUIRE
S256; reject plain), `scope`, `state`.
Steps:
1. Validate client_id + redirect_uri + PKCE params. On bad redirect_uri,
   do NOT redirect (render an error) — open-redirect guard.
2. Server-side, raise a warrant request as the gateway agent:
   `requestWarrants(broker, { deviceCert, identity, grants:[{audience:
   resource, scopes: parseScope(scope)}], label, grantor: "*" })`
   (grantor `*` = the approver picks which identity delegates). Get back the
   `verification_uri_complete` (= `${broker}/consent/<wcode>`).
3. Store a pending-authorize record keyed by a fresh internal `auth_state`:
   `{ client_id, redirect_uri, host_state: state, code_challenge, wcode,
   scopesRequested, createdAt }`.
4. Redirect the browser (302) to
   `${broker}/consent/<wcode>?return_url=${resource}/authorize/return?st=<auth_state>`
   (return_url is the new broker feature, below).

### 4. `GET /authorize/return?st=<auth_state>` — the post-approval leg
1. Load the pending-authorize record; if missing/expired → error page.
2. Poll `warrant_poll(broker, wcode)` ONCE (approval already happened; retry a
   few times with short backoff to cover propagation). If denied/expired →
   redirect to the host `redirect_uri?error=access_denied&state=<host_state>`.
2. On success, `agent.addGrant(warrant~config_cert)` for the resource
   audience.
3. Mint a single-use OAuth `code`, store `{ code → { auth_state, grantHeld:true,
   code_challenge, redirect_uri, client_id } }`, short TTL (~60s).
4. Redirect the browser to `redirect_uri?code=<code>&state=<host_state>`.

### 5. `POST /token` — add the `authorization_code` branch
(Keep the existing `jwt-bearer` branch verbatim.)
For `grant_type=authorization_code`:
1. Look up the stored code; single-use (delete on read); check TTL,
   client_id, redirect_uri match.
2. Verify PKCE: `base64url(sha256(code_verifier)) === code_challenge`.
3. `presentation = await agent.assertionFor(resource)` (the DeviceAgent mints
   the access cert + assertion + attaches the warrant+config cert).
4. Feed `presentation` through the SAME verify path `handleToken` uses
   (`POST /verify-access`, audience=resource, accepted_fallbacks) → on
   `status:"okay"`, mint + store the bearer exactly like Lane A. Reuse the
   Lane-A bearer-minting code (factor it into a shared helper).
Result: an identical bearer to Lane A, fail-closed per call downstream.

### Security checklist (must all hold)
- PKCE S256 REQUIRED; reject `plain` and missing challenge.
- `code` single-use, short TTL, bound to client_id + redirect_uri + PKCE.
- `redirect_uri` exact-match against the registered set; never redirect to an
  unvalidated URI (open-redirect).
- The warrant audience the gateway requests == `resource`; verify-access binds
  it, same as Lane A.
- `auth_state` and the broker `wcode` are unguessable; pending records expire.

## Broker change — origin-validated `return_url` on the consent flow

`browserid-registrar/src/consent.rs` + `browserid-broker/static/consent.html`.

- `warrant_request` accepts an optional `return_url`; persist it on the
  pending request (store + migration if the pending-request table needs a
  column).
- On approval (`respond`), return the `return_url` to the consent page.
- **Validate the return_url origin** belongs to the requesting service: its
  origin host must equal the requester's identity domain (the gateway's
  `resource` host, derivable from the requesting agent's identity/audience).
  Reject a mismatch (open-redirect guard) — the whole point is the browser
  only ever bounces back to the service that raised the request.
- `consent.html`: after a successful approval, if a (validated) `return_url`
  is present, `window.location.assign(return_url)` instead of showing the
  static "approved" state. (Remember the CSP inline-script-hash rule if this
  touches an inline script — prefer common/js.)

## Tests
- **mcp-auth unit:** PKCE verify (good/bad/missing/plain-rejected); DCR
  (register, redirect_uri validation); code store (single-use, TTL,
  client/redirect binding).
- **mcp-auth integration (mock broker):** stand up mock `/consent` (auto-
  approve returning a canned `warrant~config_cert`), `/warrant/request`,
  `/warrant/poll`, `/verify-access`; drive discover→register→authorize→return
  →token→`authenticate()` and assert a working bearer + attribution.
- **broker:** `return_url` persisted, echoed on approval, origin-validated
  (accept same-origin-as-requester, reject foreign). Follow
  `hosted_primary`/`merged_provision` test idioms; run via `ssh localtest`.
- Full `cargo test -p browserid-broker -p browserid-registrar` green;
  `npm test` in sdk/mcp-auth green.

## Exit criteria
A documented curl walkthrough (discover → register → authorize [approve in a
real browser on localhost] → code → token → `tools/call`) works against a
broker running locally, AND the mock-broker integration test proves it in CI.
Then M2 (the `gate` CLI) can wrap the filesystem server on top.

## Out of scope for M1
The `gate` CLI (M2), the demo/tunnel (M3), refresh tokens, grantee model B,
per-friend scope caps (owner policy, lives in the gate proxy / management UI).
