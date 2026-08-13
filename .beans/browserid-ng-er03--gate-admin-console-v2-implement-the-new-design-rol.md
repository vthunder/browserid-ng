---
# browserid-ng-er03
title: 'gate admin console v2: implement the new design (roles/people/servers UI + RBAC backend)'
status: completed
type: feature
priority: normal
created_at: 2026-08-13T08:01:15Z
updated_at: 2026-08-13T08:18:41Z
---

Implement the reviewed design handoff (~/Gate admin UI design.zip → docs/plans/2026-08-12-gate-admin-ui-design-brief.md + handoff README) for sdk/gate's admin console.

Scope: the design makes **roles** (per-server, per-tool grants) the single source of truth for access, adds a **People** address book and a **Roles** tab, and a richer staged-changes pill/popover. This replaces the per-mount email allowlist model, so it's a backend + frontend change.

## Todo

- [x] config.mjs: v2 schema {mounts, people, roles}; builtin Full-access role; legacy per-mount `allow` migration (role per mount, grants on:['*'])
- [x] mount.mjs: `access` resolver option (email → 'all' | Set(tools) | null); per-tool enforcement + filtered tools/list
- [x] gateway.mjs: startup role snapshot; tool-list caching into config + '*' grant expansion; access wiring; /admin/state; people/roles CRUD; mount restore (undo remove); mount path editing; login 403 carries `attempted` email; server-computed staged diff entries
- [x] public/: full rewrite of index.html/style.css/app.js per the high-fidelity prototype (tabs, staged pill+popover w/ auto-open-once, sign-in card, server rows+dialog, people chips, roles cards w/ checkbox grants, dark/light theme)
- [x] index.d.ts: new config/gateway types
- [x] tests: update lifecycle to the roles world; new roles.test.mjs (per-tool enforcement, role API, staging diffs, migration)
- [x] README + package.json 0.4.0
- [x] run full test suite (52/52 pass)

## Summary of Changes

**Backend** — roles are now the single source of truth for access:
- config.mjs: v2 schema {mounts, people, roles}; built-in Full access role always ensured; v1 per-mount allow lists auto-migrate (one role per allowlisted mount, members = old allowlist, grants on:["*"] = every tool); normalizePersonDef/normalizeGrants validators; mounts carry a tools discovery cache.
- mount.mjs: new `access` resolver option (email -> 'all' | Set(tools) | null) supersedes allow; per-tool enforcement returns ACCESS_DENIED before the child runs, and tools/list is filtered to the granted set. One-shot mode (allow) unchanged.
- gateway.mjs: enforcement pinned to the STARTUP snapshot of roles (staged model); tool lists cached into config at startup + '*' grants expanded once known; new API: GET /admin/state (whole console model + csrf), people/roles CRUD, POST /admin/mounts/:id/restore (undo remove), mount-path editing; wrong-identity login 403 now carries `attempted` (the caller's own email); server-computed staged diff entries (mounts + roles) drive the pill/popover.

**Frontend** — full rewrite of public/ (index.html/style.css/app.js) to the high-fidelity handoff: three tabs, staged pill + popover (auto-opens once on 0->1), sign-in card with wrong-identity error, server rows (accordion, URL well, command, tool pills, access grid, inline remove confirm, undo remove), add/edit dialog with live path preview/validation, People (avatar rows, role toggle chips, admin badge, add/remove person), Roles (cards, checkbox grant grids, built-in gold treatment, create/delete), light/dark themes (localStorage gate-admin-theme), all copy verbatim from the handoff.

**Tests**: 52/52 pass. New test/roles.test.mjs (per-tool enforcement, filtered tools/list, built-in protections, staged-vs-live role edits, people cascade, undo-remove, migration); lifecycle updated to the roles world. Screenshots verified against the prototype (light+dark, all screens).

Version: gate 0.4.0. Not committed/published — awaiting review.
