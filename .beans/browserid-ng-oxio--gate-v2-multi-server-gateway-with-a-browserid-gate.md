---
# browserid-ng-oxio
title: 'gate v2: multi-server gateway with a BrowserID-gated admin console'
status: completed
type: feature
priority: high
created_at: 2026-08-12T16:11:26Z
updated_at: 2026-08-12T17:23:24Z
parent: browserid-ng-81s6
---

npx @browserid-ng/gate --admin <email> → auto-port + auto-funnel(443) + gateway identity, prints 'configure at https://host/'. Admin signs in with BrowserID (gated to --admin) to a console that adds MCP servers (name, mount path, command, allowlist), each published warrant-gated at https://host/<mount>/mcp. One process, one funnel, N servers. Subsumes dwqa (multi-mount) + k2rz (mgmt UI). Design/spec: docs/plans/2026-08-12-gate-v2-admin-console.md. SECURITY-CRITICAL: public console + arbitrary-command spawn, gated ONLY by the BrowserID admin login — that login (verify presentation, audience==console origin, email==admin exact, signed session, CSRF) must be rock-solid.

---

## Build complete (2026-08-12) — bumped gate 0.2.1 → 0.3.0

Built in worktree agent-aa1253a92380e8fa5 on top of the real v1 (main 0f70fad),
reusing gate.mjs/tunnel.mjs/credential.mjs. Left status in-progress pending human review.

**Architecture.** Extracted a reusable `mount` (src/mount.mjs): one stdio child
(spawned via argv, never a shell) + mcp-auth + auth-code lane + allowlist +
tool→scope map, with `resource = <origin>/<slug>`. Because mcp-auth builds every
URL as `${resource}/…`, path-prefixing is automatic. src/gate.mjs
(createGateService, unchanged surface) is now a single root-mounted instance;
src/gateway.mjs (createGateway) routes `/<slug>/*` to the matching mount and
`/` + `/admin/*` to the console. One shared gateway DeviceCredential backs every
mount's Lane B; audiences (hence warrants + revocation) stay per-mount.

**STAGED config (per coordinator design change).** The console only WRITES
config.json — it never spawns/kills. The running set is fixed at startup (each
command printed to the terminal = the review checkpoint) and changes only on
restart. listMounts() surfaces running-vs-saved with a pending diff +
needsRestart. Emergency stop = Ctrl-C. No live process management from HTTP.

**Security (all satisfied, tested).** Login: verifyPresentation(p, consoleOrigin)
with audience pinned server-side (funnel origin in public mode; loopback Host in
--console-local) + email===adminEmail exact lowercased match. Session
(src/session.mjs): stateless HMAC cookie `v1.<emailB64>.<exp>.<nonce>.<hmac>`,
secret persisted 0600 at ~/.browserid-gate/session-secret (survives restart),
httpOnly+Secure(dropped for http loopback)+SameSite=Lax+TTL; forged/expired/
tampered rejected. CSRF: synchronizer token = HMAC(secret,"csrf."+nonce),
required (x-csrf-token) on every write. Spawn: StdioClientTransport argv, no
sh -c. Fail closed: no session 401 / wrong id 403 / bad verify reject.

**UI.** Static console in public/ (external app.js — no inline scripts), signed-
out "Sign in with BrowserID" → signed-in mount list (copyable /<mount>/mcp URL,
running/pending badges, enable/disable/remove staged, in-content remove confirm,
"Add an MCP" dialog).

**Tests: 37 pass (was 9).** Kept the 9 v1 gate tests + tunnel tests green; added
multimount.test.mjs (5), admin.test.mjs (12), lifecycle.test.mjs (4) — all
hermetic (mock broker + mock verifier, real-fs stdio child fixture).

**Not built (out of scope v1 per spec):** per-friend scope caps (k2rz fast
follow), multi-admin, non-tailscale auto-tunnel, config change-diff summary.

**Reconciliation note:** this worktree branched from 6682319 (pre-v1); rebuilt
against main 0f70fad. supersedes m2-gate's stale 30f2bab.

## Reviewed + merged 2026-08-12
Verified the security-critical + staged-config items directly in code (not just the report): login audience is server-pinned (publicOrigin in public mode, NOT client Host header; gateway.mjs:209), email exact lowercased match (gateway.mjs:242), verifyPresentation fail-closed→403, CSRF on writes (gateway.mjs:301), argv-not-shell spawn (mount.mjs:56-60 StdioClientTransport), HMAC session (session.mjs, per-install secret 0600, timingSafeEqual). STAGED CONFIG confirmed: config write handlers only push/splice+persistConfig; spawnMount is startup-only — no live spawn from HTTP (the mid-build design change stuck). v1 fixes preserved (rebased on 0f70fad; CORS via applyCors in mount.mjs, tunnel.mjs, distinct-agent, request-log). 37 tests pass. Merged to main. Version 0.3.0. Publish (agent 0.4.1 already up, mcp-auth 0.2.0 up, gate 0.3.0) needs user OTP.

## 0.3.3: multi-mount OAuth discovery — serve path-INSERTED well-known (RFC 8414/9728)
Live claude.ai failure (from the gate request log): claude fetched /.well-known/oauth-authorization-server/notes (path-inserted per RFC 8414, since the mount issuer is <origin>/notes) → 404, because mcp-auth only serves the path-SUFFIXED /notes/.well-known/oauth-authorization-server. For a root single-server the two coincide (why 0.2.x worked); for a mount they differ and clients use the inserted form. The hermetic tests fetched the suffixed URL, missing it. Fix: gateway routes /.well-known/{oauth-authorization-server,oauth-protected-resource}/<mount> to the mount by rewriting to the suffixed subpath it already serves. Regression test now fetches the path-inserted URL.

## 0.3.4: friendly page for the benign authorize/return double-submit
Live UX bug: the broker consent page auto-redirects to /authorize/return AND shows a manual 'return to the app' link. The auto-nav consumes the single-use auth record (success → code issued); the manual click hits /authorize/return again → raw JSON error 'unknown or expired authorization'. First hit already succeeded, so the gate now renders a friendly 'You're all set, close this window' HTML page for that invalid_request case instead of the error. ROOT cause (deeper follow-up): the consent page shouldn't both auto-nav and offer a re-triggering manual link — broker-side fix for all return_url flows.
