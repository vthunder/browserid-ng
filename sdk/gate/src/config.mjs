// The gateway config store — the durable state the console manages.
// ~/.browserid-gate/config.json (0600), shape:
//   { mounts: [ { id, name, mount, command:[…], enabled, tools:[…]|null } ],
//     people: [ { email, name } ],
//     roles:  [ { id, name, builtin, members:[email…],
//                 grants:[ { mountId, on:[toolName…] } ] } ] }
// GATE_HOME overrides the directory (tests, alternate installs).
//
// ACCESS MODEL (design: docs/plans/2026-08-12-gate-admin-ui-design-brief.md +
// the reviewed handoff): roles are the single source of truth. A role = members
// (emails) + per-mount, per-tool grants. The built-in "Full access" role grants
// every tool on every mount (including future ones) and cannot be deleted. The
// people list is just an address book — being in it grants nothing. The admin
// identity (set at launch) is implicit and never appears in a role.
//
// A grant tool entry of "*" means "every tool on that mount" — used by the
// legacy-allowlist migration below (tool lists aren't known until the mount has
// started); the gateway expands it to the concrete tool list at startup.

import { readFileSync, writeFileSync, mkdirSync, chmodSync, existsSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { join } from "node:path";
import { gateHome } from "./credential.mjs";

export function configPath() {
  return join(gateHome(), "config.json");
}

/** Load the config (defaults to an empty store). Always normalized. */
export function loadConfig() {
  const path = configPath();
  if (!existsSync(path)) return normalizeConfig(null);
  let doc;
  try { doc = JSON.parse(readFileSync(path, "utf8")); } catch { doc = null; }
  return normalizeConfig(doc);
}

/** Persist the config (0600 in a 0700 dir). */
export function saveConfig(config) {
  const home = gateHome();
  mkdirSync(home, { recursive: true, mode: 0o700 });
  try { chmodSync(home, 0o700); } catch { /* best effort */ }
  const path = configPath();
  const doc = { mounts: config.mounts || [], people: config.people || [], roles: config.roles || [] };
  writeFileSync(path, JSON.stringify(doc, null, 2), { mode: 0o600 });
  try { chmodSync(path, 0o600); } catch { /* best effort */ }
  return path;
}

/**
 * Normalize a raw config document into the v2 shape. Migrates the v1 per-mount
 * `allow` email lists (when the doc predates roles): each allowlisted mount
 * becomes a role of the same name whose members are the old allowlist, granted
 * every tool on that mount ("*", expanded at startup). Ensures the built-in
 * "Full access" role exists.
 */
export function normalizeConfig(doc) {
  const cfg = { mounts: [], people: [], roles: [], signedGrants: doc?.signedGrants === true };
  const legacy = []; // [{id, name, allow}] from pre-roles configs

  for (const m of Array.isArray(doc?.mounts) ? doc.mounts : []) {
    if (!m || typeof m !== "object") continue;
    const clean = {
      id: typeof m.id === "string" && m.id ? m.id : `m_${randomBytes(6).toString("hex")}`,
      name: String(m.name || m.mount || ""),
      mount: String(m.mount || ""),
      command: Array.isArray(m.command) ? m.command.map(String) : [],
      enabled: m.enabled !== false,
      tools: Array.isArray(m.tools) ? m.tools.map(String) : null,
    };
    cfg.mounts.push(clean);
    if (Array.isArray(m.allow) && m.allow.length) legacy.push({ id: clean.id, name: clean.name, allow: m.allow.map(normEmail).filter(Boolean) });
  }

  for (const p of Array.isArray(doc?.people) ? doc.people : []) {
    const email = normEmail(p?.email);
    if (!email || cfg.people.some((x) => x.email === email)) continue;
    cfg.people.push({ email, name: String(p?.name || "").trim() || email.split("@")[0] });
  }

  for (const r of Array.isArray(doc?.roles) ? doc.roles : []) {
    if (!r || typeof r !== "object" || !r.name) continue;
    cfg.roles.push({
      id: typeof r.id === "string" && r.id ? r.id : `r_${randomBytes(6).toString("hex")}`,
      name: String(r.name),
      builtin: !!r.builtin,
      members: [...new Set((Array.isArray(r.members) ? r.members : []).map(normEmail).filter(Boolean))],
      grants: (Array.isArray(r.grants) ? r.grants : [])
        .filter((g) => g && typeof g.mountId === "string")
        .map((g) => ({ mountId: g.mountId, on: [...new Set((Array.isArray(g.on) ? g.on : []).map(String).filter(Boolean))] })),
    });
  }

  // v1 → v2 migration: only when the doc has no roles array at all.
  if (!Array.isArray(doc?.roles)) {
    for (const l of legacy) {
      for (const email of l.allow) {
        if (!cfg.people.some((p) => p.email === email)) cfg.people.push({ email, name: email.split("@")[0] });
      }
      cfg.roles.push({ id: `r_${l.id}`, name: l.name, builtin: false, members: l.allow, grants: [{ mountId: l.id, on: ["*"] }] });
    }
  }

  if (!cfg.roles.some((r) => r.builtin)) {
    cfg.roles.unshift({ id: "full", name: "Full access", builtin: true, members: [], grants: [] });
  }
  return cfg;
}

const normEmail = (e) => String(e || "").trim().toLowerCase();

const SLUG_RE = /^[a-z0-9][a-z0-9._-]*$/i;
// Reserved top-level path segments the router owns — a mount can't shadow them.
export const RESERVED_SLUGS = new Set(["admin", "healthz", "assets", "well-known", "connect", "shared"]);

/**
 * Validate + normalize a mount definition from the admin UI. Throws Error with
 * a human-readable message on any problem (the caller surfaces it as 400).
 * Access is NOT part of a mount (roles own it) — any `allow` input is ignored.
 */
export function normalizeMountDef(def) {
  const name = String(def?.name || "").trim();
  const mount = String(def?.mount || "").trim().toLowerCase();
  if (!name) throw new Error("name is required");
  if (name.length > 120) throw new Error("name too long");
  if (!SLUG_RE.test(mount)) throw new Error("mount slug must match [a-z0-9._-] and start alphanumeric");
  if (mount.length > 64) throw new Error("mount slug too long");
  if (RESERVED_SLUGS.has(mount)) throw new Error(`'${mount}' is a reserved path`);

  // command: an argv array, or a convenience string tokenized HERE into literal
  // argv (never handed to a shell — no globbing/substitution/operators).
  let command = def?.command;
  if (typeof command === "string") command = tokenizeArgv(command);
  if (!Array.isArray(command) || command.length === 0 || !command.every((s) => typeof s === "string" && s.length)) {
    throw new Error("command must be a non-empty argv array (or a whitespace-separated string)");
  }

  return {
    id: typeof def?.id === "string" && def.id ? def.id : `m_${randomBytes(6).toString("hex")}`,
    name,
    mount,
    command: command.slice(),
    enabled: def?.enabled !== false,
    tools: Array.isArray(def?.tools) ? def.tools.map(String) : null,
  };
}

/** Validate + normalize a person from the admin UI. */
export function normalizePersonDef(def) {
  const email = normEmail(def?.email);
  if (!email || !email.includes("@")) throw new Error("a valid email is required");
  if (email.length > 254) throw new Error("email too long");
  const name = String(def?.name || "").trim().slice(0, 120) || email.split("@")[0];
  return { email, name };
}

/** Validate + normalize a role's grants list from the admin UI. */
export function normalizeGrants(grants, mounts) {
  if (!Array.isArray(grants)) throw new Error("grants must be an array");
  const out = [];
  for (const g of grants) {
    if (!g || typeof g.mountId !== "string") throw new Error("each grant needs a mountId");
    if (!mounts.some((m) => m.id === g.mountId)) throw new Error(`unknown mount '${g.mountId}'`);
    const on = [...new Set((Array.isArray(g.on) ? g.on : []).map(String).filter(Boolean))];
    if (on.some((t) => t.length > 200)) throw new Error("tool name too long");
    if (on.length) out.push({ mountId: g.mountId, on });
  }
  return out;
}

/** Simple, quote-aware argv tokenizer (NO shell semantics). */
export function tokenizeArgv(s) {
  const out = [];
  const re = /"([^"]*)"|'([^']*)'|(\S+)/g;
  let m;
  while ((m = re.exec(s))) out.push(m[1] ?? m[2] ?? m[3]);
  return out;
}
