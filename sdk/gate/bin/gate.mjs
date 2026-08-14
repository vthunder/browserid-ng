#!/usr/bin/env node
// gate — publish stdio MCP servers as remote, BrowserID-gated HTTP endpoints.
//
// ONE mode: the console.
//
//   npx @browserid-ng/gate --admin you@example.com
//
// Auto-picks a free local port, claims a tailscale funnel on 443 (if tailscale
// is available — otherwise it runs on localhost and tells you how to tunnel),
// provisions the gateway's own identity once, and prints a console URL. Sign in
// there (only --admin gets in) and add MCP servers by name + mount + command;
// each is published at https://<host>/<mount>/mcp. Access is granted via roles
// (People + Roles tabs: per-server, per-tool grants). Add --console-local to
// keep the console on 127.0.0.1 (only the mounts funnel).
//
// (One-shot mode — wrapping a single server from flags — was removed in v0.5;
// `createGateService` remains as the library API for embedding a single gate.)
//
// First run provisions the GATEWAY's own BrowserID identity (Lane B needs one):
// it prints an approval link as the LAST line and blocks until you approve. The
// credential lives in ~/.browserid-gate (override GATE_HOME) and is reused.

import { createGateway } from "../src/gateway.mjs";
import { ensureCredential } from "../src/credential.mjs";
import { claimFunnel, funnelOffHint } from "../src/tunnel.mjs";

const REMOVED = ["--allow", "--name", "--tunnel", "--"];

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (REMOVED.includes(a) || REMOVED.some((r) => r !== "--" && a.startsWith(r + "="))) {
      console.error(
        "gate: one-shot mode was removed — gate now always runs the console.\n" +
          "Start it and add your server in the web UI instead:\n\n" +
          "  npx @browserid-ng/gate --admin you@example.com\n"
      );
      process.exit(1);
    } else if (a === "--admin") out.admin = argv[++i];
    else if (a.startsWith("--admin=")) out.admin = a.slice(8);
    else if (a === "--console-local") out.consoleLocal = true;
    else if (a === "--handle") out.handle = argv[++i];
    else if (a.startsWith("--handle=")) out.handle = a.slice(9);
    else if (a === "--port") out.port = Number(argv[++i]);
    else if (a.startsWith("--port=")) out.port = Number(a.slice(7));
    else if (a === "--resource") out.resource = argv[++i];
    else if (a.startsWith("--resource=")) out.resource = a.slice(11);
    else if (a === "--broker") out.broker = argv[++i];
    else if (a.startsWith("--broker=")) out.broker = a.slice(9);
    else if (a === "-h" || a === "--help") out.help = true;
    else { console.error(`gate: unexpected argument '${a}'\n\n${HELP}`); process.exit(1); }
  }
  return out;
}

function slugifyHandle(name) {
  const s = String(name || "")
    .toLowerCase()
    .replace(/['’]/g, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 40)
    .replace(/-+$/g, "");
  return s || "mcp-gateway";
}

const HELP = `gate — publish stdio MCP servers as BrowserID-gated HTTP endpoints

  npx @browserid-ng/gate --admin you@example.com

Runs the gateway + web console. Sign in (only --admin gets in), add MCP
servers by name + mount path + command, and grant access with roles —
per person, per server, per tool. Changes are staged; restart to apply.

  --admin <email>    REQUIRED: the one identity allowed into the console
  --console-local    bind the console to 127.0.0.1 (still funnel /<mount>/*)
  --handle <slug>    the gateway agent's identity handle (default: mcp-gateway)
  --port <n>         local listen port (default: auto-pick)
  --resource <url>   public URL = the OAuth audience (default: tailscale funnel
                     on 443; without tailscale, falls back to localhost)
  --broker <url>     BrowserID broker (default $BROWSERID_BROKER or https://browserid.me)

Reachability: with tailscale installed (and Funnel enabled) the gateway claims
https://<your-machine>.ts.net automatically. Without it, gate still runs on
localhost — put any tunnel in front (tailscale recommended; cloudflared works)
and pass its URL as --resource to share publicly.

First run provisions the gateway identity: approve the printed link once.`;

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) { console.log(HELP); return; }
  if (!args.admin) {
    console.error("gate: --admin <email> is required.\n\n" + HELP);
    process.exit(1);
  }
  const broker = (args.broker || process.env.BROWSERID_BROKER || "https://browserid.me").replace(/\/+$/, "");

  // Credential-less by default (spec §7.5): when the broker supports
  // connection grants, the gateway needs NO identity of its own — mounts
  // raise connection requests as the audience and hold the records. The
  // provisioned gateway identity is only the fallback for brokers without
  // support.
  let credential = null;
  let recordGrants = false;
  try {
    const res = await fetch(`${broker}/.well-known/browserid`, { headers: { accept: "application/json" } });
    const doc = await res.json().catch(() => ({}));
    recordGrants = res.ok && typeof doc["record-grants"] === "string" && !!doc["record-grants"];
  } catch { /* unreachable broker: fall through to the credential path */ }
  if (!recordGrants) {
    const handle = slugifyHandle(args.handle || "mcp-gateway");
    credential = await ensureCredential({
      broker,
      handle,
      label: "MCP gateway console",
      onApproveUrl: (url, info) => {
        console.error("");
        console.error("This gateway needs its OWN BrowserID identity (approve once). Open this link and approve:");
        if (info?.userCode) console.error(`  (or open ${info.verificationUri} and enter code ${info.userCode})`);
        if (info?.fingerprint) console.error(`  key fingerprint: ${info.fingerprint}`);
        console.error("Waiting for approval…");
        console.log(url); // LAST LINE
      },
    });
  }

  const gateway = createGateway({
    credential,
    adminEmail: args.admin,
    broker,
    consoleLocal: args.consoleLocal,
    // If --resource is given, skip the funnel and use it as the public origin.
    origin: args.resource,
    // The console is an appliance: it CLAIMS 443 (re-pointing across restarts,
    // since the local port is auto-picked) so hosts like claude.ai — which
    // reject non-standard ports — can reach it.
    ensureFunnel: (port) => claimFunnel(port),
  });

  const shutdown = async () => { await gateway.close(); process.exit(0); };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);

  const { origin, consoleUrl, port, public: isPublic, funnelError, funnelWarning } = await gateway.start({ port: args.port ?? 0 });
  const bar = "─".repeat(64);
  console.error(bar);
  console.error(`  MCP Gateway is live (admin: ${args.admin}).`);
  console.error(`  local port:  ${port}`);
  console.error(`  public host: ${origin}`);
  if (args.consoleLocal) {
    console.error("");
    console.error(`  Console (LOCAL ONLY): ${consoleUrl}`);
    console.error("  Mounts are still funneled publicly at " + origin + "/<mount>/mcp");
  } else {
    console.error("");
    console.error(`  Configure at: ${consoleUrl}`);
  }
  if (funnelError) {
    console.error("");
    console.error("  ⚠ LOCAL ONLY — no public tunnel, so this URL is reachable just from");
    console.error("    this machine. To share it publicly, tunnel it:");
    console.error("    • recommended: install tailscale (with Funnel enabled) and rerun —");
    console.error("      gate will claim https://<your-machine>.ts.net automatically;");
    console.error("    • or run any tunnel (e.g. cloudflared) and pass --resource <its-url>.");
    console.error(`    (tunnel detection said: ${funnelError})`);
  } else if (funnelWarning) {
    console.error("");
    console.error(`  ⚠ ${funnelWarning}`);
  } else if (!isPublic && !args.resource) {
    console.error("");
    console.error("  ⚠ non-https origin — hosts like claude.ai need a public https URL.");
  }
  if (origin.includes(".ts.net")) console.error(`  (teardown: ${funnelOffHint(origin)})`);
  console.error(bar);
}

main().catch((e) => {
  console.error("gate: fatal —", e?.message || e);
  process.exit(1);
});
