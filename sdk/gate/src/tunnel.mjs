// Tailscale funnel integration (browserid-ng-7uzd).
//
// We do NOT build a tunnel — we DETECT the one the operator already has (or,
// with --tunnel tailscale, ask tailscale to create one) and derive the gate's
// public `--resource` from it. That closes the two sharp edges from the first
// M3 run: forgetting that `--resource` must equal the public funnel URL (else
// the OAuth audience is localhost and no host can reach it), and the funnel
// port-conflict dance (443/8443/10000, pick a free one).
//
// Source of truth: `tailscale serve status --json` →
//   { Web: { "<host>:<port>": { Handlers: { "/": { Proxy: "http://127.0.0.1:<localPort>" }}}},
//     AllowFunnel: { "<host>:<port>": true } }
// A public funnel is a Web entry whose proxy targets our local port AND is
// present in AllowFunnel.

import { execFile } from "node:child_process";
import { promisify } from "node:util";

const pexec = promisify(execFile);

/** Public https URL from a "host:port" serve key (443 → no port suffix). */
function publicUrl(key) {
  const i = key.lastIndexOf(":");
  const host = key.slice(0, i);
  const port = key.slice(i + 1);
  return port === "443" ? `https://${host}` : `https://${host}:${port}`;
}

/** The localhost port a "http://127.0.0.1:8787" / "http://localhost:8787" proxy targets. */
function proxyLocalPort(proxy) {
  const m = /^https?:\/\/(?:127\.0\.0\.1|localhost)(?::(\d+))?/.exec(String(proxy || ""));
  if (!m) return null;
  return Number(m[1] || (String(proxy).startsWith("https:") ? 443 : 80));
}

/** Funnel ports tailscale permits, in preference order. */
export const FUNNEL_PORTS = [443, 8443, 10000];

/** Default runner: `tailscale <args...>` → { stdout }. Returns null on any
 *  failure (not installed, not up, old CLI) so callers degrade gracefully. */
async function defaultRun(args) {
  return pexec("tailscale", args, { encoding: "utf8", timeout: 10000 });
}

async function serveStatus(run) {
  try {
    const { stdout } = await run(["serve", "status", "--json"]);
    const parsed = JSON.parse(stdout);
    return parsed && typeof parsed === "object" ? parsed : null;
  } catch {
    return null;
  }
}

/**
 * The public funnel URL already mapping to `localPort`, or null.
 * @param {number} localPort
 * @param {{run?: (args:string[])=>Promise<{stdout:string}>}} [opts]
 */
export async function detectFunnel(localPort, { run = defaultRun } = {}) {
  const st = await serveStatus(run);
  if (!st || !st.Web) return null;
  const funnel = st.AllowFunnel || {};
  for (const [key, cfg] of Object.entries(st.Web)) {
    const proxy = cfg?.Handlers?.["/"]?.Proxy;
    if (proxyLocalPort(proxy) === Number(localPort) && funnel[key]) {
      return publicUrl(key);
    }
  }
  return null;
}

/**
 * Ensure a public funnel maps to `localPort`, creating one on the first free
 * funnel port if none exists. Returns the public https URL.
 * Throws with an actionable message if tailscale can't do it.
 * @param {number} localPort
 * @param {{run?: (args:string[])=>Promise<{stdout:string}>}} [opts]
 */
export async function ensureFunnel(localPort, { run = defaultRun } = {}) {
  const existing = await detectFunnel(localPort, { run });
  if (existing) return existing;

  const st = await serveStatus(run);
  if (st === null) {
    throw new Error(
      "tailscale not available (is it installed and running?). " +
        "Set --resource to your public URL manually, or use cloudflared."
    );
  }
  const taken = new Set(
    Object.keys(st.Web || {}).map((k) => Number(k.slice(k.lastIndexOf(":") + 1)))
  );
  const port = FUNNEL_PORTS.find((p) => !taken.has(p));
  if (!port) {
    throw new Error(
      "all tailscale funnel ports (443/8443/10000) are already in use; " +
        "free one (`tailscale funnel --https=<port> off`) or pass --resource."
    );
  }
  try {
    await run(["funnel", "--bg", `--https=${port}`, String(localPort)]);
  } catch (e) {
    throw new Error(
      `could not start tailscale funnel on :${port} (${e?.message || e}). ` +
        "Funnel must be enabled for your tailnet; see https://tailscale.com/kb/1223/funnel."
    );
  }
  const url = await detectFunnel(localPort, { run });
  if (!url) {
    throw new Error(
      `funnel started on :${port} but its URL could not be read back from ` +
        "`tailscale serve status`."
    );
  }
  return url;
}

/**
 * CLAIM a specific public funnel port (default 443) for `localPort`, re-pointing
 * a stale mapping if one exists. This is what an appliance-style gateway wants:
 * it OWNS the standard port, and its local port changes each run (auto-port), so
 * "pick a free port" would keep dodging 443 and land on 8443/10000 — which
 * managed hosts (claude.ai) reject. Idempotent: if the port already maps here,
 * no-op. Returns the public https URL (no port suffix for 443).
 * @param {number} localPort
 * @param {{run?: (args:string[])=>Promise<{stdout:string}>, publicPort?: number}} [opts]
 */
export async function claimFunnel(localPort, { run = defaultRun, publicPort = 443 } = {}) {
  // Already publicly mapped to this exact local port? Keep it.
  const existing = await detectFunnel(localPort, { run });
  if (existing) return existing;
  const st = await serveStatus(run);
  if (st === null) {
    throw new Error(
      "tailscale not available (is it installed and running?). " +
        "Use --resource to set the public URL manually, or --console-local, or cloudflared."
    );
  }
  // Claim (or re-point) the standard port at our local port.
  try {
    await run(["funnel", "--bg", `--https=${publicPort}`, String(localPort)]);
  } catch (e) {
    throw new Error(
      `could not claim tailscale funnel :${publicPort} → :${localPort} (${e?.message || e}). ` +
        "Funnel must be enabled for your tailnet; see https://tailscale.com/kb/1223/funnel."
    );
  }
  const url = await detectFunnel(localPort, { run });
  if (!url) {
    throw new Error(
      `claimed funnel :${publicPort} → :${localPort} but its URL could not be read back ` +
        "from `tailscale serve status`."
    );
  }
  return url;
}

/** The teardown hint for a funnel URL (its port), for printing on exit. */
export function funnelOffHint(resourceUrl) {
  try {
    const u = new URL(resourceUrl);
    const port = u.port || "443";
    return `tailscale funnel --https=${port} off`;
  } catch {
    return "tailscale funnel --https=<port> off";
  }
}
