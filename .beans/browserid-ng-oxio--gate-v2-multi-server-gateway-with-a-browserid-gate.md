---
# browserid-ng-oxio
title: 'gate v2: multi-server gateway with a BrowserID-gated admin console'
status: in-progress
type: feature
priority: high
created_at: 2026-08-12T16:11:26Z
updated_at: 2026-08-12T16:11:26Z
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
