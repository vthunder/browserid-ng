// @browserid-ng/gate — wrap a stdio MCP server as a BrowserID-gated HTTP endpoint.

import type { Server as HttpServer } from "node:http";

export interface GateChildSpec {
  command: string;
  args?: string[];
  env?: Record<string, string>;
  cwd?: string;
}

export interface GateOptions {
  /** Allowlisted grantor emails (whose humans may connect). */
  allow: string[];
  /** Display label (consent card + landing). */
  name?: string;
  /** The wrapped stdio server to spawn + proxy. Omit if `client` is supplied. */
  child?: GateChildSpec;
  /** A pre-connected MCP Client (tests) — used instead of spawning a child. */
  client?: unknown;
  /** The gateway's device credential (Lane B). */
  credential: {
    device_key: string;
    agent_device_cert: string;
    idp: string;
    identity?: string;
  };
  /** Canonical public URL of THIS gate (OAuth resource + audience). */
  resource: string;
  /** Broker origin (default https://browserid.me). */
  broker?: string;
  /** Per-grant status cache seconds (default 5). */
  statusCacheS?: number;
  /** Attribution/log sink (default console.log). */
  log?: (line: string) => void;
}

export interface GateService {
  server: HttpServer;
  mcpAuth: unknown;
  lane: unknown;
  tools: Array<{ name: string; [k: string]: unknown }>;
  scopesForTool: Record<string, string[]>;
  allow: Set<string>;
  resource: string;
  broker: string;
  close(): Promise<void>;
}

/** Build (and connect) a gate service around a stdio MCP child. */
export function createGateService(opts: GateOptions): Promise<GateService>;

/** A short, side-effect-free digest of a tool's arguments for the audit line. */
export function argsDigest(args: unknown, max?: number): string;

// --- credential.mjs ---

export function gateHome(): string;
export function credentialPath(): string;
export function loadCredential(): GateOptions["credential"] | null;
export function saveCredential(cred: GateOptions["credential"]): string;
export function ensureCredential(opts: {
  broker: string;
  label?: string;
  handle?: string;
  onApproveUrl?: (url: string, info: { verificationUri?: string; userCode?: string; fingerprint?: string }) => void;
  http?: typeof fetch;
}): Promise<GateOptions["credential"]>;

// --- gateway.mjs (the multi-server admin console) ---

export interface MountDef {
  id?: string;
  name: string;
  /** URL path slug ([a-z0-9._-]); the endpoint is <origin>/<mount>/mcp. */
  mount: string;
  /** argv — spawned literally, never via a shell. A string is tokenized to argv. */
  command: string[] | string;
  enabled?: boolean;
  /** Last-discovered tool names (cached at startup); null until first started. */
  tools?: string[] | null;
}

export interface PersonDef {
  email: string;
  name: string;
}

/** One per-mount grant inside a role. `on: ["*"]` = every tool (migration). */
export interface RoleGrant {
  mountId: string;
  on: string[];
}

/** Roles are the single source of truth for access. The built-in "Full access"
 *  role grants everything (incl. future mounts) and cannot be deleted. */
export interface RoleDef {
  id: string;
  name: string;
  builtin: boolean;
  members: string[];
  grants: RoleGrant[];
}

export interface GatewayConfig {
  mounts: MountDef[];
  people?: PersonDef[];
  roles?: RoleDef[];
}

export interface MountStatus {
  id: string;
  name: string;
  mount: string;
  url: string;
  command: string[];
  enabled: boolean;
  /** Whether a child is live for this mount (spawned at startup). */
  running: boolean;
  /** Live tool names when running, else the last-discovered cache, else null
   *  (= unknown until a restart has started this server). */
  tools: string[] | null;
  toolCount: number;
  /** null | "new" | "changed" | "removed" — a config edit awaiting a restart. */
  pending: null | "new" | "changed" | "removed";
}

/** One staged-diff entry (the console's "N staged" popover). */
export interface PendingChange {
  sign: "+" | "~" | "−";
  label: string;
  desc: string;
}

export interface GatewayState {
  admin: string;
  origin: string | null;
  broker: string;
  mounts: MountStatus[];
  people: Array<PersonDef & { admin: boolean }>;
  roles: RoleDef[];
  pending: PendingChange[];
  needsRestart: boolean;
}

export interface GatewayOptions {
  /** Shared gateway DeviceCredential (Lane B). */
  credential: GateOptions["credential"];
  /** The ONE identity allowed into the console (exact match). */
  adminEmail: string;
  broker?: string;
  /** Public origin (skips the funnel; e.g. tests / cloudflared). */
  origin?: string;
  /** Bind the console to 127.0.0.1 only; still funnel /<mount>/*. */
  consoleLocal?: boolean;
  statusCacheS?: number;
  /** In-memory config INSTEAD of the on-disk store (tests). */
  config?: GatewayConfig;
  /** Persist config edits to disk (default true unless `config` is given). */
  persist?: boolean;
  /** Session HMAC key (default: persisted install secret). */
  sessionSecret?: Buffer;
  sessionTtlS?: number;
  fetch?: typeof fetch;
  log?: (line: string) => void;
  /** Override the tunnel (tests). */
  ensureFunnel?: (port: number) => Promise<string>;
}

export interface Gateway {
  /** Bind (auto-port), funnel unless `origin` was given, then spawn enabled
   *  config mounts. The running set is fixed until the next start(). */
  start(opts?: { port?: number }): Promise<{ origin: string; port: number; consoleUrl: string; localPort: number | null }>;
  close(): Promise<void>;
  /** STAGED config edits — persist only; nothing spawns/kills until restart. */
  addMount(def: MountDef): MountStatus;
  updateMount(id: string, patch: Partial<MountDef>): MountStatus;
  removeMount(id: string): boolean;
  /** Undo a staged removal (copies the startup def back into the config). */
  restoreMount(id: string): MountStatus;
  listMounts(): { mounts: MountStatus[]; pending: number; needsRestart: boolean };
  addPerson(def: { email: string; name?: string }): PersonDef;
  removePerson(email: string): boolean;
  addRole(def: { name: string }): RoleDef;
  updateRole(id: string, patch: { members?: string[]; grants?: RoleGrant[] }): RoleDef;
  removeRole(id: string): boolean;
  listState(): GatewayState;
  readonly origin: string | null;
  readonly port: number | null;
  readonly adminEmail: string;
  readonly broker: string;
}

export function createGateway(opts: GatewayOptions): Gateway;

// --- config.mjs / session.mjs (advanced) ---

export function configPath(): string;
export function loadConfig(): Required<GatewayConfig>;
export function saveConfig(config: GatewayConfig): string;
/** Normalize a raw config doc; migrates v1 per-mount `allow` lists to roles. */
export function normalizeConfig(doc: unknown): Required<GatewayConfig>;
export function normalizeMountDef(def: MountDef): Required<MountDef>;
export function normalizePersonDef(def: { email: string; name?: string }): PersonDef;
export function normalizeGrants(grants: RoleGrant[], mounts: MountDef[]): RoleGrant[];
export function tokenizeArgv(s: string): string[];
