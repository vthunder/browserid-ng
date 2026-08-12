// The gateway's OWN BrowserID identity (design decision #A: "gateway-as-agent").
//
// Lane B needs an agent credential the lane can raise warrant requests as and
// mint presentations with. We provision ONE, once, at first run — exactly the
// wallet's path (`requestProvision` → human approves a link → device
// credential) — and store it in the wallet's `{ credential }` shape so the
// DeviceAgent can be reconstructed on every subsequent boot with no human in
// the loop.
//
// Store: a gate-specific dir (default ~/.browserid-gate, override GATE_HOME),
// kept owner-only (700/600) because it holds a private device key.

import { readFileSync, writeFileSync, mkdirSync, chmodSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { requestProvision } from "@browserid-ng/agent";

export function gateHome() {
  return process.env.GATE_HOME || join(homedir(), ".browserid-gate");
}

export function credentialPath() {
  return join(gateHome(), "credential.json");
}

/** Load a stored gateway credential ({ device_key, agent_device_cert, idp,
 *  identity }), or null if none / unusable. */
export function loadCredential() {
  let stored;
  try {
    stored = JSON.parse(readFileSync(credentialPath(), "utf8"));
  } catch {
    return null;
  }
  const cred = stored.credential ?? stored;
  if (!cred || typeof cred !== "object" || !cred.device_key || !cred.agent_device_cert) {
    return null;
  }
  return cred;
}

/** Persist a gateway credential (0600 in a 0700 dir). */
export function saveCredential(cred) {
  const home = gateHome();
  mkdirSync(home, { recursive: true, mode: 0o700 });
  try { chmodSync(home, 0o700); } catch {}
  const path = credentialPath();
  writeFileSync(path, JSON.stringify({ credential: cred }, null, 2), { mode: 0o600 });
  try { chmodSync(path, 0o600); } catch {}
  return path;
}

/**
 * Ensure a gateway credential exists, provisioning one if not. On first run
 * this raises a provisioning request and calls `onApproveUrl(url)` with the
 * approval link — the CLI prints it as its LAST line so the operator approves
 * once — then BLOCKS until the human approves (operator-driven, unlike the
 * wallet's non-blocking agent tools). Returns the credential.
 *
 * @param {object} opts
 * @param {string} opts.broker
 * @param {string} [opts.label]   display name on the approval card
 * @param {string} [opts.handle]  suggested identity handle
 * @param {(url:string, info:object)=>void} [opts.onApproveUrl]
 * @param {typeof fetch} [opts.http]
 */
export async function ensureCredential({ broker, label, handle, onApproveUrl, http = fetch } = {}) {
  const existing = loadCredential();
  if (existing) return existing;

  const pending = await requestProvision(broker, { handle, label: label || "mcp gateway", http });
  if (onApproveUrl) {
    onApproveUrl(pending.verificationUriComplete, {
      verificationUri: pending.verificationUri,
      userCode: pending.userCode,
      fingerprint: pending.fingerprint,
    });
  }
  const { credential } = await pending.wait();
  saveCredential(credential);
  return credential;
}
