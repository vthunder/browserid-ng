// The multi-server gateway — the `--admin` console appliance. One Node HTTP
// server (auto-port, one 443 funnel) hosts N warrant-gated MCP endpoints plus a
// BrowserID-gated admin console that EDITS which servers run.
//
// Routing (src/gateway.mjs is the router; per-mount work lives in src/mount.mjs):
//   /  and /admin/*   → the admin console (login + config UI + config API)
//   /<slug>/*         → that mount's gated MCP endpoint (its own mcp-auth+lane)
//
// Each mount's `resource` = `<publicOrigin>/<slug>`, so mcp-auth path-prefixes
// every advertised OAuth URL for free. One shared gateway agent identity backs
// every mount's Lane B; audiences (and thus warrants + revocation) stay per
// mount.
//
// SECURITY — STAGED config (defense in depth). The console can only WRITE
// config.json; it NEVER spawns or kills a child. The running set of commands is
// fixed at STARTUP (and each command is printed to the terminal — that print IS
// the review checkpoint) and only changes on a restart (Ctrl-C + rerun). So
// even a login bypass is not immediate RCE: an attacker can edit config data,
// but the command they inject does not execute until the operator restarts at a
// terminal — a human-gated review the web attacker cannot trigger. The console
// surfaces "pending changes — restart to apply" so the admin knows a restart is
// needed. The login itself is the primary gate (exact audience + exact admin
// email, HMAC session cookie, CSRF on writes) — see src/session.mjs.
//
// Design: docs/plans/2026-08-12-gate-v2-admin-console.md (bean oxio).

import { createServer } from "node:http";
import { randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { verifyPresentation } from "@browserid-ng/verify";
import { createMount, json, applyCors, readBody } from "./mount.mjs";
import { createSessionManager, parseCookies } from "./session.mjs";
import { createFilePolicyStore } from "./policystore.mjs";
import { createConnectAuth } from "./connectauth.mjs";
import { sharedPage } from "./sharedpage.mjs";
import { gateHome } from "./credential.mjs";
import { identityEq, granteeCovers } from "@browserid-ng/mcp-auth";
import { loadConfig, saveConfig, normalizeConfig, normalizeMountDef, normalizePersonDef, normalizeGrants } from "./config.mjs";
import { ensureFunnel } from "./tunnel.mjs";

const PUBLIC_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "public");

/**
 * @param {object} opts  see index.d.ts (GatewayOptions).
 */
export function createGateway(opts) {
  const adminEmail = String(reqOpt(opts, "adminEmail")).trim().toLowerCase();
  // Optional since 0.6: with a broker that supports connection grants the
  // mounts run credential-less (spec §7.5); the credential is only the
  // agent-mode fallback for brokers without support.
  const credential = opts.credential || null;
  const broker = (opts.broker || "https://browserid.me").replace(/\/+$/, "");
  const doFetch = opts.fetch || globalThis.fetch;
  const log = opts.log || ((l) => console.log(l));
  const statusCacheS = opts.statusCacheS ?? 5;
  const consoleLocal = !!opts.consoleLocal;
  const persist = opts.persist ?? !opts.config;
  // Enforcement source (Dan's call, 2026-08-15): LOCAL roles by default
  // (self-hosted: operator == owner, unsigned rows enforce directly, the
  // pre-0.7 staged model). SIGNED records opt-in (--signed-grants): the
  // §6.5 path — required when the operator isn't the policy owner (managed
  // gateways), and what lets verification later travel down the stack.
  // Sticky: persisted in config so a forgotten flag never silently
  // downgrades enforcement; resolved after config load below.
  const funnelFn = opts.ensureFunnel || ensureFunnel;

  const mounts = new Map(); // slug -> live mount (spawned at startup, fixed)
  const byId = new Map(); // id -> live mount
  let startupDefs = []; // snapshot of config.mounts at startup (for the pending diff)
  let startupRoles = []; // snapshot of config.roles at startup — the ENFORCED set
  let config = opts.config ? normalizeConfig(opts.config) : loadConfig();
  const signedGrants = opts.signedGrants ?? config.signedGrants ?? false;
  if (typeof opts.signedGrants === "boolean" && config.signedGrants !== opts.signedGrants) {
    config.signedGrants = opts.signedGrants;
    if (opts.persist ?? !opts.config) saveConfig(config);
  }

  let publicOrigin = opts.origin ? String(opts.origin).replace(/\/+$/, "") : null;
  let port = null;
  let publicServer = null;
  let localServer = null;

  const adminSecure = () => (consoleLocal ? false : String(publicOrigin || "").startsWith("https"));
  let sessions = createSessionManager({ secret: opts.sessionSecret, ttlS: opts.sessionTtlS, secure: adminSecure() });

  // --- §6.5 policy layer: signed records are the enforcement source ---------
  // The roles/people UI is the EDITOR; "Sign grants" compiles it into flat
  // per-(email, mount) records the admin signs at the broker's authoring
  // card. Shared across mounts (one origin, one ceremony) and persisted —
  // records survive restarts.
  const policyStore = opts.policyStore
    || createFilePolicyStore(join(gateHome(), "policy.json"));
  // Member sessions for the identity-first connect flow (origin-wide, so a
  // second mount connects without another login).
  let userSessions = createSessionManager({
    secret: opts.sessionSecret, ttlS: opts.sessionTtlS, secure: adminSecure(), cookieName: "gate_user",
  });
  let connectAuth = createConnectAuth({
    broker, origin: () => publicOrigin || "", sessions: userSessions, fetch: doFetch,
  });

  /** Mode-unified entitlement: what `email` may use at `mount` ("all", a
   *  scope list, or null). Signed mode reads live records; local mode reads
   *  the startup roles snapshot (the staged model). Shared by admission,
   *  the identity-first authorize, and the /shared landing page. */
  async function entitlementForEmail(mount, email) {
    if (signedGrants) return entitlementAt(mount, email);
    if (identityEq(email, adminEmail) || email === adminEmail) return "all";
    const acc = accessFor(email, mount.id);
    if (acc === "all") return "all";
    if (!acc) return null;
    return [...acc].map((t) => `tool:${t}`);
  }

  /** What the signed records entitle `email` to at `mount` ("all" for the
   *  admin, a scope list, or null = no access). */
  async function entitlementAt(mount, email) {
    if (identityEq(email, adminEmail) || email === adminEmail) return "all";
    const rows = (await policyStore.list(mount.resource)).filter((r) => granteeCovers(r.grantee, email));
    // Liveness (cached ≤60s): a broker-revoked grant must stop admitting
    // here too — connection bearers revalidate at every mint, but the
    // jwt-bearer lane's entitlement read would otherwise trust a dead row.
    const live = [];
    for (const r of rows) if (await isRowLive(r)) live.push(r);
    if (!live.length) return null;
    return [...new Set(live.flatMap((r) => r.scopes || []))];
  }

  // --- access resolution (roles are the single source of truth) -------------
  // Enforcement uses the STARTUP snapshot of roles, matching the staged model:
  // role edits saved in the console take effect on the next restart. The admin
  // identity is implicit and always has full access. A grant entry of "*"
  // means every tool on that mount (legacy-allowlist migration).

  function accessFor(email, mountId) {
    const e = String(email || "").toLowerCase();
    if (e === adminEmail) return "all";
    let all = false;
    const set = new Set();
    for (const role of startupRoles) {
      if (!role.members.includes(e)) continue;
      if (role.builtin) return "all";
      for (const g of role.grants) {
        if (g.mountId !== mountId) continue;
        for (const t of g.on) {
          if (t === "*") all = true;
          else set.add(t);
        }
      }
    }
    if (all) return "all";
    return set.size ? set : null;
  }

  // --- grants: roles compiled to flat signed records (spec §6.5) ------------

  /** Compile the CURRENT config (people × roles) into the flat
   *  per-(email, mount audience) grants the admin signs. */
  function compileGrants() {
    const per = new Map(); // email -> Map(mountId -> "all" | Set(tool))
    for (const role of config.roles) {
      for (const member of role.members) {
        const acc = per.get(member) || new Map();
        per.set(member, acc);
        if (role.builtin) {
          for (const def of config.mounts) acc.set(def.id, "all");
          continue;
        }
        for (const g of role.grants) {
          const cur = acc.get(g.mountId);
          if (cur === "all") continue;
          if (g.on.includes("*")) acc.set(g.mountId, "all");
          else {
            const set = cur instanceof Set ? cur : new Set();
            for (const t of g.on) set.add(t);
            acc.set(g.mountId, set);
          }
        }
      }
    }
    const rows = [];
    for (const [email, perMount] of per) {
      for (const [mountId, toolset] of perMount) {
        const mount = byId.get(mountId);
        if (!mount) continue; // not running (staged) — sign after restart
        const names = toolset === "all"
          ? mount.toolNames
          : [...toolset].filter((t) => mount.toolNames.includes(t));
        if (!names.length) continue;
        rows.push({
          grantee: email,
          audience: mount.resource,
          scopes: names.map((t) => `tool:${t}`).sort(),
        });
      }
    }
    return rows.sort((a, b) => (a.grantee + a.audience).localeCompare(b.grantee + b.audience));
  }

  // A stored row only counts as SIGNED while its record is still alive —
  // revocation at the broker (or expiry) must resurface it as pending, or
  // the console reads "in sync" over a dead grant (Dan's repro,
  // 2026-08-15). Enforcement is already fail-closed per mint; this is the
  // DIFF's view: definitive invalidity (revoked/expired) drops the row so
  // it needs a fresh signature; an unreachable validator keeps last-known
  // rather than churning the console.
  const recordLiveness = new Map(); // record -> { at, ok }
  const LIVENESS_TTL_MS = (opts.grantsLivenessS ?? 60) * 1000;
  async function isRowLive(row) {
    if (row.exp != null && row.exp <= Math.floor(Date.now() / 1000)) return false;
    const cached = recordLiveness.get(row.record);
    if (cached && Date.now() - cached.at < LIVENESS_TTL_MS) return cached.ok;
    const anyMount = mounts.values().next().value;
    if (!anyMount) return true; // nothing to validate with; leave the row be
    let ok = true;
    try {
      await anyMount.mcpAuth.validateRecord(row.record, row.audience);
    } catch (e) {
      if (e?.httpStatus === 503) return cached?.ok ?? true; // unreachable
      ok = false; // revoked / expired / invalid — definitive
    }
    recordLiveness.set(row.record, { at: Date.now(), ok });
    return ok;
  }

  /** desired vs signed (admin-signed rows only): what needs a signature, and
   *  which signed rows are stale (no longer desired → custodial delete). */
  async function grantsDiff() {
    const desired = compileGrants();
    let signed = (await policyStore.list()).filter((r) => r.grantor === adminEmail);
    const dead = [];
    for (const r of signed) {
      if (!(await isRowLive(r))) dead.push(r);
    }
    for (const r of dead) {
      await policyStore.del(r.grantor, r.grantee, r.audience);
    }
    if (dead.length) signed = signed.filter((r) => !dead.includes(r));
    const skey = (r) => `${r.grantee}|${r.audience}`;
    const sameScopes = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
    const signedBy = new Map(signed.map((r) => [skey(r), r]));
    const pending = desired.filter((d) => {
      const have = signedBy.get(skey(d));
      return !have || !sameScopes([...(have.scopes || [])].sort(), d.scopes);
    });
    const desiredKeys = new Set(desired.map(skey));
    const stale = signed.filter((r) => !desiredKeys.has(skey(r)));
    return { desired, signed, pending, stale };
  }

  // One signing ceremony at a time; the console polls its status.
  let signState = null; // { requestId, consentUri, status: "pending"|"done"|"error", error?, signedCount? }

  async function startGrantSigning() {
    const { pending, stale } = await grantsDiff();
    // Custodial removals need no ceremony: deleting the held row ends access
    // at this resource (the admin can additionally revoke at the broker).
    for (const r of stale) await policyStore.del(r.grantor, r.grantee, r.audience);
    if (!pending.length) {
      signState = { status: "done", signedCount: 0, removed: stale.length };
      return signState;
    }
    const anyMount = mounts.values().next().value;
    if (!anyMount) throw badRequest("no running mounts to sign for");
    // The broker caps an authoring ceremony at 32 rows: sign in chunks — the
    // console shows the remainder and offers another signing pass.
    const batch = pending.slice(0, 32);
    const ceremony = await anyMount.lane.requestAuthoring({
      grants: batch,
      grantor: adminEmail,
      // After signing, land back in the console (origin-validated: the
      // console shares the mounts' origin).
      returnUrl: publicOrigin ? `${publicOrigin}/admin/` : undefined,
    });
    signState = {
      status: "pending",
      requestId: ceremony.requestId,
      consentUri: ceremony.consentUri,
      removed: stale.length,
    };
    ceremony.wait().then(
      (rows) => {
        for (const r of rows) recordLiveness.delete(r.record);
        signState = { ...signState, status: "done", signedCount: rows.length, remaining: pending.length - batch.length };
      },
      (e) => { signState = { ...signState, status: "error", error: String(e.message || e) }; }
    );
    return signState;
  }

  // --- startup spawning (the ONLY place a child is ever spawned) ------------

  async function spawnMount(def) {
    const resource = `${publicOrigin}/${def.mount}`;
    log(`[gate] starting mount /${def.mount} → ${def.command.join(" ")}`);
    const mount = await createMount({
      resource,
      ...(credential ? { credential } : {}),
      owners: [adminEmail],
      signedGrants,
      policyStore,
      userFor: (rq) => connectAuth.userFor(rq),
      entitlementFor: async (email) => entitlementForEmail(mount, email),
      name: def.name,
      child: { command: def.command[0], args: def.command.slice(1) },
      broker,
      statusCacheS,
      fetch: doFetch,
      log,
      meta: { id: def.id, slug: def.mount },
    });
    mounts.set(def.mount, mount);
    byId.set(def.id, mount);
    log(`[gate] mounted /${def.mount} → ${resource}/mcp (${mount.toolNames.length} tools)`);
    return mount;
  }

  // --- config editing (STAGED — persist only, never touches live children) --

  function persistConfig() { if (persist) saveConfig(config); }

  function addMount(rawDef) {
    const def = normalizeMountDef(rawDef);
    if (config.mounts.some((m) => m.mount === def.mount)) {
      throw badRequest(`mount path '${def.mount}' is already in use`);
    }
    config.mounts.push(def);
    persistConfig();
    return statusRow(def);
  }

  function updateMount(id, patch) {
    const def = config.mounts.find((m) => m.id === id);
    if (!def) throw notFound("no such mount");
    if (patch.name != null) def.name = String(patch.name).trim() || def.name;
    if (patch.mount != null) {
      const mount = normalizeMountDef({ ...def, mount: patch.mount }).mount;
      if (config.mounts.some((m) => m.mount === mount && m.id !== id)) {
        throw badRequest(`mount path '${mount}' is already in use`);
      }
      def.mount = mount;
    }
    if (Array.isArray(patch.command) || typeof patch.command === "string") {
      // Re-validate via normalize (also tokenizes a string form to argv).
      def.command = normalizeMountDef({ ...def, command: patch.command }).command;
    }
    if (patch.enabled != null) def.enabled = !!patch.enabled;
    persistConfig();
    return statusRow(def);
  }

  function removeMount(id) {
    const idx = config.mounts.findIndex((m) => m.id === id);
    if (idx < 0) throw notFound("no such mount");
    config.mounts.splice(idx, 1);
    persistConfig();
    return true;
  }

  /** Undo a staged removal: copy the startup def back into the saved config. */
  function restoreMount(id) {
    if (config.mounts.some((m) => m.id === id)) throw badRequest("mount is not removed");
    const startDef = startupDefs.find((m) => m.id === id);
    if (!startDef) throw notFound("no such mount");
    if (config.mounts.some((m) => m.mount === startDef.mount)) {
      throw badRequest(`mount path '${startDef.mount}' is already in use`);
    }
    const def = { ...startDef, command: [...startDef.command], tools: startDef.tools ? [...startDef.tools] : null };
    config.mounts.push(def);
    persistConfig();
    return statusRow(def);
  }

  // --- people (address book — grants nothing by itself) ---------------------

  function addPerson(rawDef) {
    const person = normalizePersonDef(rawDef);
    if (person.email === adminEmail) throw badRequest("the admin identity is implicit — it can't be added");
    if (config.people.some((p) => p.email === person.email)) throw badRequest("that person is already in the address book");
    config.people.push(person);
    persistConfig();
    return person;
  }

  /** Remove a person everywhere: the address book AND every role's members. */
  function removePerson(email) {
    const e = String(email || "").trim().toLowerCase();
    const idx = config.people.findIndex((p) => p.email === e);
    if (idx < 0) throw notFound("no such person");
    config.people.splice(idx, 1);
    for (const role of config.roles) role.members = role.members.filter((m) => m !== e);
    persistConfig();
    return true;
  }

  // --- roles (the single source of truth for access) ------------------------

  function addRole(rawDef) {
    const name = String(rawDef?.name || "").trim();
    if (!name) throw badRequest("role name is required");
    if (name.length > 80) throw badRequest("role name too long");
    const role = { id: `r_${randomId()}`, name, builtin: false, members: [], grants: [] };
    config.roles.push(role);
    persistConfig();
    return role;
  }

  function updateRole(id, patch) {
    const role = config.roles.find((r) => r.id === id);
    if (!role) throw notFound("no such role");
    if (Array.isArray(patch?.members)) {
      const members = [...new Set(patch.members.map((e) => String(e).trim().toLowerCase()).filter((e) => e && e.includes("@")))];
      if (members.includes(adminEmail)) throw badRequest("the admin identity is implicit — it can't join a role");
      // Address-book safety net: membership implies presence in people.
      for (const email of members) {
        if (!config.people.some((p) => p.email === email)) config.people.push({ email, name: email.split("@")[0] });
      }
      role.members = members;
    }
    if (patch?.grants != null) {
      if (role.builtin) throw badRequest("the built-in role's grants are not editable");
      role.grants = normalizeGrants(patch.grants, config.mounts);
    }
    persistConfig();
    return role;
  }

  function removeRole(id) {
    const role = config.roles.find((r) => r.id === id);
    if (!role) throw notFound("no such role");
    if (role.builtin) throw badRequest("the built-in role can't be deleted");
    config.roles = config.roles.filter((r) => r.id !== id);
    persistConfig();
    return true;
  }

  // --- status: running (startup) vs saved (config), with the pending diff ---

  // tools is a runtime-discovered cache, not an edit — excluded on purpose.
  const sig = (d) => JSON.stringify({ name: d.name, mount: d.mount, command: d.command, enabled: d.enabled !== false });

  /** One row per mount id present in either the saved config or the running
   *  set, tagged with its pending state relative to startup. `tools` is the
   *  live list when running, else the last-discovered cache, else null
   *  (= unknown until a restart has started this server). */
  function statusRow(savedDef) {
    const id = savedDef.id;
    const startDef = startupDefs.find((m) => m.id === id) || null;
    const live = byId.get(id) || null;
    let pending = null; // null | "new" | "changed" | "removed"
    if (!startDef) pending = "new";
    else if (sig(savedDef) !== sig(startDef)) pending = "changed";
    const tools = live ? live.toolNames : savedDef.tools || null;
    return {
      id,
      name: savedDef.name,
      mount: savedDef.mount,
      url: `${publicOrigin}/${savedDef.mount}/mcp`,
      command: savedDef.command,
      enabled: savedDef.enabled !== false,
      running: !!live,
      tools,
      toolCount: tools ? tools.length : 0,
      pending, // "new"/"changed" — needs a restart to take effect
    };
  }

  function listMounts() {
    const rows = config.mounts.map(statusRow);
    // Startup mounts that are no longer in the saved config = pending removals;
    // they keep running until restart, so surface them too.
    for (const s of startupDefs) {
      if (!config.mounts.some((m) => m.id === s.id)) {
        const live = byId.get(s.id);
        const tools = live ? live.toolNames : s.tools || null;
        rows.push({
          id: s.id, name: s.name, mount: s.mount, url: `${publicOrigin}/${s.mount}/mcp`,
          command: s.command, enabled: false, running: !!live,
          tools, toolCount: tools ? tools.length : 0, pending: "removed",
        });
      }
    }
    const pendingCount = rows.filter((r) => r.pending).length;
    return { mounts: rows, pending: pendingCount, needsRestart: pendingCount > 0 };
  }

  /** Staged role edits relative to startup, as popover diff entries. */
  function diffRoles() {
    const out = [];
    const label = (r) => `role ${r.name.toLowerCase()}`;
    const membersSig = (r) => JSON.stringify([...r.members].sort());
    const grantsSig = (r) =>
      JSON.stringify(r.grants.map((g) => ({ m: g.mountId, on: [...g.on].sort() })).sort((a, b) => (a.m < b.m ? -1 : 1)));
    for (const role of config.roles) {
      const start = startupRoles.find((r) => r.id === role.id);
      if (!start) { out.push({ sign: "+", label: label(role), desc: "new role" }); continue; }
      if (membersSig(role) !== membersSig(start)) out.push({ sign: "~", label: label(role), desc: "members edited" });
      if (grantsSig(role) !== grantsSig(start)) out.push({ sign: "~", label: label(role), desc: "tool scopes edited" });
    }
    for (const start of startupRoles) {
      if (!config.roles.some((r) => r.id === start.id)) out.push({ sign: "−", label: label(start), desc: "will be removed" });
    }
    return out;
  }

  /** The whole console state in one read: what the UI renders. `pending` is
   *  the staged-changes diff (mount rows carry their own pending tag too). */
  function listState() {
    const { mounts: rows } = listMounts();
    const pending = [
      ...rows
        .filter((r) => r.pending)
        .map((r) => ({
          sign: r.pending === "new" ? "+" : r.pending === "removed" ? "−" : "~",
          label: `/${r.mount}`,
          desc:
            r.pending === "new" ? `${r.name} — new server`
            : r.pending === "removed" ? `${r.name} — will be removed`
            : `${r.name} — edited`,
        })),
      ...diffRoles(),
    ];
    return {
      admin: adminEmail,
      origin: publicOrigin,
      broker,
      mounts: rows,
      people: [
        { email: adminEmail, name: adminEmail.split("@")[0], admin: true },
        ...config.people.map((p) => ({ ...p, admin: false })),
      ],
      roles: config.roles.map((r) => ({ ...r, members: [...r.members], grants: r.grants.map((g) => ({ mountId: g.mountId, on: [...g.on] })) })),
      pending,
      needsRestart: pending.length > 0,
    };
  }

  // --- HTTP router ----------------------------------------------------------

  async function route(rq, res, { adminAllowed }) {
    const url = new URL(rq.url, publicOrigin || `http://${rq.headers.host}`);
    const path = url.pathname;
    res.on("finish", () => log(`[gate] ${rq.method} ${path} → ${res.statusCode}`));
    if (applyCors(rq, res)) return;

    try {
      if (rq.method === "GET" && path === "/healthz") return json(res, 200, { ok: true, mounts: mounts.size });

      if (path === "/" || path === "/admin" || path.startsWith("/admin/")) {
        // The root is the ONE entry point (Dan, 2026-08-16): admins land in
        // the console, everyone else on their /shared page. A member session
        // (that isn't the admin) routes straight there; console-local public
        // listeners route members there too instead of a bare 404.
        if (path === "/") {
          const adminSession = sessions.verify(parseCookies(rq.headers.cookie));
          const isAdmin = !!adminSession && adminSession.email.toLowerCase() === adminEmail;
          const member = connectAuth.userFor(rq);
          if (!isAdmin && member && member !== adminEmail) {
            res.writeHead(302, { location: "/shared" });
            return res.end();
          }
          if (!adminAllowed) {
            res.writeHead(302, { location: "/shared" });
            return res.end();
          }
        }
        if (!adminAllowed) return json(res, 404, { error: "not_found" });
        return admin(rq, res, { url, path, adminOrigin: adminOriginFor(rq) });
      }

      // RFC 8414 / RFC 9728 PATH-INSERTED discovery: a mount's OAuth issuer is
      // `<origin>/<mount>`, so a spec client (claude.ai) fetches the metadata at
      // `/.well-known/<doc>/<mount>` (inserted), NOT `/<mount>/.well-known/<doc>`
      // (suffixed — what mcp-auth's URLs use). For a root single-server the two
      // coincide; for a mount they differ. Serve the inserted form by rewriting
      // to the suffixed subpath the mount already handles.
      // Identity-first connect: the member login (origin-wide session).
      if (path === "/connect/login" || path === "/connect/logout") {
        if (await connectAuth.handle(rq, res, { path, url })) return;
      }

      // The member landing: everything shared with the signed-in identity,
      // with per-agent connect instructions. The admin shares ONE url.
      if (rq.method === "GET" && path === "/shared") {
        if (!connectAuth.userFor(rq)) {
          res.writeHead(302, { location: "/connect/login?next=%2Fshared" });
          return res.end();
        }
        res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
        return res.end(sharedPage());
      }
      if (rq.method === "GET" && path === "/shared/servers") {
        const email = connectAuth.userFor(rq);
        if (!email) return json(res, 401, { error: "not_signed_in" });
        const servers = [];
        for (const m of mounts.values()) {
          const ent = await entitlementForEmail(m, email);
          if (ent == null) continue;
          const toolNames = ent === "all" ? m.toolNames : m.toolNames.filter((t) => ent.includes(`tool:${t}`));
          if (!toolNames.length) continue;
          servers.push({ slug: m.slug, name: m.name, url: `${m.resource}/mcp`, tools: toolNames });
        }
        return json(res, 200, { email, servers });
      }

      // Connection mode (spec §7.5): the audience proof is ORIGIN-scoped —
      // the broker fetches it at the host root, not under a mount path — so
      // fan out across mounts to whichever lane has the pending request.
      const ap = /^\/\.well-known\/browserid-audience-proof\/([^/]+)$/.exec(path);
      if (rq.method === "GET" && ap) {
        for (const m of mounts.values()) {
          const body = m.lane.handleAudienceProof(ap[1]);
          if (body != null) {
            res.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
            return res.end(body);
          }
        }
        res.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
        return res.end("no such pending request");
      }

      const wk = /^\/\.well-known\/(oauth-authorization-server|oauth-protected-resource)\/([^/]+)$/.exec(path);
      if (rq.method === "GET" && wk) {
        const m = mounts.get(wk[2]);
        if (m) {
          const handled = await m.handle(rq, res, { subpath: `/.well-known/${wk[1]}`, url });
          if (!handled) json(res, 404, { error: "not_found" });
          return;
        }
        return json(res, 404, { error: "not_found" });
      }

      const seg = path.slice(1).split("/")[0];
      const mount = mounts.get(seg);
      if (mount) {
        const subpath = path.slice(seg.length + 1) || "/";
        const handled = await mount.handle(rq, res, { subpath, url });
        if (!handled) json(res, 404, { error: "not_found" });
        return;
      }
      json(res, 404, { error: "not_found" });
    } catch (e) {
      console.error(`[gate] ${rq.method} ${path}:`, e);
      if (!res.headersSent) json(res, 500, { error: "server_error" });
    }
  }

  // Login audience = the origin the admin's browser actually used. Public
  // listener → the pinned funnel origin (never the client Host header, to avoid
  // audience confusion). Local listener → the loopback Host (already trusted).
  function adminOriginFor(rq) {
    return consoleLocal ? `http://${rq.headers.host}` : publicOrigin;
  }

  // --- admin console --------------------------------------------------------

  async function admin(rq, res, { path, adminOrigin }) {
    if (rq.method === "GET" && (path === "/" || path === "/admin" || path === "/admin/")) {
      return serveStatic(res, "index.html", "text/html; charset=utf-8");
    }
    if (rq.method === "GET" && path === "/admin/app.js") return serveStatic(res, "app.js", "text/javascript; charset=utf-8");
    if (rq.method === "GET" && path === "/admin/style.css") return serveStatic(res, "style.css", "text/css; charset=utf-8");
    if (rq.method === "GET" && path === "/admin/gallery") return serveStatic(res, "gallery.json", "application/json");

    if (rq.method === "GET" && path === "/admin/bootstrap") {
      const s = sessions.verify(parseCookies(rq.headers.cookie));
      const signedIn = !!s && s.email.toLowerCase() === adminEmail;
      return json(res, 200, { broker, origin: adminOrigin, signedIn, admin: signedIn ? s.email : null });
    }

    // Login — the security gate.
    if (rq.method === "POST" && path === "/admin/login") {
      const body = await readJson(rq);
      const presentation = body?.presentation;
      if (!presentation || typeof presentation !== "string") {
        return json(res, 400, { error: "invalid_request", error_description: "missing presentation" });
      }
      const result = await verifyPresentation(presentation, adminOrigin, {
        verifierUrl: `${broker}/verify-access`,
        fetch: doFetch,
      });
      if (!result.ok) {
        return json(res, 403, { error: "access_denied", error_description: `verification failed: ${result.reason}` });
      }
      if (String(result.email).toLowerCase() !== adminEmail) {
        log(`[gate] admin login DENIED for ${result.email} (not ${adminEmail})`);
        // `attempted` is the caller's OWN verified email (never the admin's) —
        // the UI echoes it back in the wrong-identity error.
        return json(res, 403, { error: "access_denied", error_description: "not the admin identity", attempted: result.email });
      }
      const { csrf, setCookies } = sessions.issue(result.email);
      res.setHeader("Set-Cookie", setCookies);
      log(`[gate] admin login OK for ${result.email}`);
      return json(res, 200, { ok: true, admin: result.email, csrf });
    }

    // Below: valid admin session required (fail closed).
    const session = requireSession(rq, res);
    if (!session) return;

    if (rq.method === "GET" && path === "/admin/whoami") {
      return json(res, 200, { admin: session.email, host: publicOrigin, csrf: sessions.csrfForNonce(session.nonce) });
    }
    // Grants (spec §6.5): the compiled desired set vs the signed records, and
    // the signing ceremony (the admin signs at the broker's authoring card).
    if (rq.method === "GET" && path === "/admin/grants") {
      if (!signedGrants) return json(res, 200, { disabled: true, desired: [], signed: [], pending: [], stale: [], signState: null });
      const diff = await grantsDiff();
      return json(res, 200, { ...diff, signState });
    }
    if (rq.method === "POST" && path === "/admin/grants/sign") {
      if (!requireCsrf(rq, res, session)) return;
      if (!signedGrants) return json(res, 400, { error: "invalid_request", error_description: "signed grants are not enabled (--signed-grants)" });
      if (signState?.status === "pending") {
        return json(res, 409, { error: "conflict", error_description: "a signing ceremony is already pending", signState });
      }
      try {
        return json(res, 200, await startGrantSigning());
      } catch (e) {
        return json(res, e.status || 500, { error: "sign_failed", error_description: String(e.message || e) });
      }
    }
    if (rq.method === "GET" && path === "/admin/grants/status") {
      return json(res, 200, { signState });
    }
    if (rq.method === "POST" && path === "/admin/logout") {
      if (!requireCsrf(rq, res, session)) return;
      res.setHeader("Set-Cookie", sessions.clearCookies());
      return json(res, 200, { ok: true });
    }

    // A mutating handler: CSRF-gated, 400s with the thrown message.
    const write = async (fn) => {
      if (!requireCsrf(rq, res, session)) return;
      try { return await fn(); }
      catch (e) { return json(res, e.status || 400, { error: "invalid_request", error_description: e.message }); }
    };

    if (rq.method === "GET" && path === "/admin/state") {
      return json(res, 200, { ...listState(), csrf: sessions.csrfForNonce(session.nonce) });
    }

    if (path === "/admin/mounts") {
      if (rq.method === "GET") return json(res, 200, listMounts());
      if (rq.method === "POST") return write(async () => json(res, 201, { ...addMount(await readJson(rq)), needsRestart: true }));
    }
    const m = /^\/admin\/mounts\/([^/]+)(\/restore)?$/.exec(path);
    if (m) {
      const id = decodeURIComponent(m[1]);
      if (rq.method === "POST" && m[2]) return write(() => json(res, 200, restoreMount(id)));
      if (rq.method === "PATCH" && !m[2]) return write(async () => json(res, 200, { ...updateMount(id, await readJson(rq)), needsRestart: true }));
      if (rq.method === "DELETE" && !m[2]) return write(() => { removeMount(id); return json(res, 200, { ok: true, needsRestart: true }); });
    }

    if (path === "/admin/people" && rq.method === "POST") {
      return write(async () => json(res, 201, addPerson(await readJson(rq))));
    }
    const p = /^\/admin\/people\/([^/]+)$/.exec(path);
    if (p && rq.method === "DELETE") {
      return write(() => { removePerson(decodeURIComponent(p[1])); return json(res, 200, { ok: true }); });
    }

    if (path === "/admin/roles" && rq.method === "POST") {
      return write(async () => json(res, 201, addRole(await readJson(rq))));
    }
    const r = /^\/admin\/roles\/([^/]+)$/.exec(path);
    if (r) {
      const id = decodeURIComponent(r[1]);
      if (rq.method === "PATCH") return write(async () => json(res, 200, updateRole(id, await readJson(rq))));
      if (rq.method === "DELETE") return write(() => { removeRole(id); return json(res, 200, { ok: true }); });
    }
    json(res, 404, { error: "not_found" });
  }

  function requireSession(rq, res) {
    const session = sessions.verify(parseCookies(rq.headers.cookie));
    if (!session || session.email.toLowerCase() !== adminEmail) {
      json(res, 401, { error: "unauthorized", error_description: "admin session required" });
      return null;
    }
    return session;
  }
  function requireCsrf(rq, res, session) {
    const token = rq.headers["x-csrf-token"];
    if (!sessions.checkCsrf(session, Array.isArray(token) ? token[0] : token)) {
      json(res, 403, { error: "forbidden", error_description: "missing or invalid CSRF token" });
      return false;
    }
    return true;
  }
  async function serveStatic(res, file, type) {
    try {
      const buf = await readFile(join(PUBLIC_DIR, file));
      res.writeHead(200, { "content-type": type, "cache-control": "no-cache" });
      res.end(buf);
    } catch { json(res, 404, { error: "not_found" }); }
  }
  async function readJson(rq) { try { return JSON.parse(await readBody(rq)); } catch { return {}; } }

  // --- start / stop ---------------------------------------------------------

  async function start(startOpts = {}) {
    const wantPort = startOpts.port ?? 0;
    publicServer = createServer((rq, res) => route(rq, res, { adminAllowed: !consoleLocal }));
    await listen(publicServer, wantPort, consoleLocal ? "0.0.0.0" : undefined);
    port = publicServer.address().port;

    if (consoleLocal) {
      localServer = createServer((rq, res) => route(rq, res, { adminAllowed: true }));
      await listen(localServer, 0, "127.0.0.1");
    }

    // Resolve the public origin: --resource wins; else claim a tailscale
    // funnel; else FALL BACK to localhost so the console always comes up —
    // the caller surfaces "tunnel this to share it" guidance (funnelError).
    // A funnel can also succeed DEGRADED (443 was busy → a non-standard port):
    // that comes back as funnelWarning, for the caller to surface loudly.
    let funnelError = null;
    let funnelWarning = null;
    if (!publicOrigin) {
      try {
        const res = await funnelFn(port);
        const url = typeof res === "string" ? res : res.url;
        funnelWarning = typeof res === "string" ? null : res.warning || null;
        publicOrigin = url.replace(/\/+$/, "");
        if (funnelWarning) log(`[gate] ⚠ ${funnelWarning}`);
      } catch (e) {
        funnelError = e?.message || String(e);
        publicOrigin = `http://127.0.0.1:${port}`;
        log(`[gate] no public tunnel (${funnelError}) — serving on ${publicOrigin} (local only)`);
      }
    }
    sessions = createSessionManager({ secret: opts.sessionSecret, ttlS: opts.sessionTtlS, secure: adminSecure() });

    // Snapshot the config as the immutable "running set", then spawn enabled
    // entries. Nothing spawned after this until a restart.
    startupDefs = config.mounts.map((m) => ({ ...m, command: [...m.command], tools: m.tools ? [...m.tools] : null }));
    for (const def of startupDefs) {
      if (def.enabled === false) { log(`[gate] mount /${def.mount} is disabled — not started`); continue; }
      try { await spawnMount(def); }
      catch (e) { log(`[gate] FAILED to start mount /${def.mount}: ${e.message}`); }
    }

    // Tool discovery (MCP tools/list) just happened for every spawned child —
    // cache the lists in config so the console can grant per-tool even while a
    // server is disabled, and expand any "*" grants (legacy migration) into the
    // now-known concrete tool lists. This is startup housekeeping, not a staged
    // edit: it happens at the human-gated restart and is excluded from sig().
    for (const def of [...startupDefs, ...config.mounts]) {
      const live = byId.get(def.id);
      if (live) def.tools = [...live.toolNames];
    }
    for (const role of config.roles) {
      for (const g of role.grants) {
        const def = config.mounts.find((m) => m.id === g.mountId);
        if (def?.tools && g.on.includes("*")) g.on = [...def.tools];
      }
    }
    // The ENFORCED role set for this run — snapshotted AFTER expansion so a
    // clean startup reports "in sync".
    startupRoles = config.roles.map((r) => ({
      ...r,
      members: [...r.members],
      grants: r.grants.map((g) => ({ mountId: g.mountId, on: [...g.on] })),
    }));
    persistConfig();

    const consoleUrl = consoleLocal ? `http://127.0.0.1:${localServer.address().port}/` : `${publicOrigin}/`;
    return {
      origin: publicOrigin, port, consoleUrl,
      localPort: localServer?.address().port || null,
      public: publicOrigin.startsWith("https"),
      funnelError,
      funnelWarning,
    };
  }

  async function close() {
    for (const id of [...byId.keys()]) {
      const mount = byId.get(id);
      byId.delete(id);
      mounts.delete(mount.slug);
      try { await mount.close(); } catch { /* best effort */ }
    }
    for (const s of [publicServer, localServer]) {
      if (!s) continue;
      try { s.closeAllConnections?.(); } catch { /* best effort */ }
      await new Promise((r) => s.close(r));
    }
    publicServer = localServer = null;
  }

  return {
    start, close, addMount, updateMount, removeMount, restoreMount, listMounts,
    addPerson, removePerson, addRole, updateRole, removeRole, listState,
    get origin() { return publicOrigin; },
    get port() { return port; },
    get publicServer() { return publicServer; },
    get localServer() { return localServer; },
    get sessions() { return sessions; },
    get mounts() { return mounts; },
    adminEmail, broker, signedGrants,
  };
}

// --- helpers ----------------------------------------------------------------

function reqOpt(o, k) {
  if (!o || o[k] == null || o[k] === "") throw new Error(`gate/gateway: '${k}' is required`);
  return o[k];
}
function listen(server, port, host) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => { server.off("error", reject); resolve(); });
  });
}
function badRequest(msg) { const e = new Error(msg); e.status = 400; return e; }
function randomId() { return randomBytes(6).toString("hex"); }
function notFound(msg) { const e = new Error(msg); e.status = 404; return e; }
