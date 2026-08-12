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
