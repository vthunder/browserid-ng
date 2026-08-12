// The gateway config store — the durable list of MCP servers the console
// manages. ~/.browserid-gate/config.json (0600), shape:
//   { mounts: [ { id, name, mount, command:[…], allow:[…], enabled } ] }
// GATE_HOME overrides the directory (tests, alternate installs).

import { readFileSync, writeFileSync, mkdirSync, chmodSync, existsSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { join } from "node:path";
import { gateHome } from "./credential.mjs";

export function configPath() {
  return join(gateHome(), "config.json");
}

/** Load the config (defaults to an empty mount list). */
export function loadConfig() {
  const path = configPath();
  if (!existsSync(path)) return { mounts: [] };
  let doc;
  try { doc = JSON.parse(readFileSync(path, "utf8")); } catch { return { mounts: [] }; }
  if (!doc || !Array.isArray(doc.mounts)) return { mounts: [] };
  return doc;
}

/** Persist the config (0600 in a 0700 dir). */
export function saveConfig(config) {
  const home = gateHome();
  mkdirSync(home, { recursive: true, mode: 0o700 });
  try { chmodSync(home, 0o700); } catch { /* best effort */ }
  const path = configPath();
  writeFileSync(path, JSON.stringify({ mounts: config.mounts || [] }, null, 2), { mode: 0o600 });
  try { chmodSync(path, 0o600); } catch { /* best effort */ }
  return path;
}

const SLUG_RE = /^[a-z0-9][a-z0-9._-]*$/i;
// Reserved top-level path segments the router owns — a mount can't shadow them.
export const RESERVED_SLUGS = new Set(["admin", "healthz", "assets", "well-known"]);

/**
 * Validate + normalize a mount definition from the admin UI. Throws Error with
 * a human-readable message on any problem (the caller surfaces it as 400).
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

  const allow = Array.isArray(def?.allow)
    ? [...new Set(def.allow.map((e) => String(e).trim().toLowerCase()).filter(Boolean))]
    : [];

  return {
    id: typeof def?.id === "string" && def.id ? def.id : `m_${randomBytes(6).toString("hex")}`,
    name,
    mount,
    command: command.slice(),
    allow,
    enabled: def?.enabled !== false,
  };
}

/** Simple, quote-aware argv tokenizer (NO shell semantics). */
export function tokenizeArgv(s) {
  const out = [];
  const re = /"([^"]*)"|'([^']*)'|(\S+)/g;
  let m;
  while ((m = re.exec(s))) out.push(m[1] ?? m[2] ?? m[3]);
  return out;
}
