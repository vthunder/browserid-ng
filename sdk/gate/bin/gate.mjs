#!/usr/bin/env node
// gate — publish stdio MCP servers as remote, BrowserID-gated HTTP endpoints.
//
// TWO modes:
//
//   Console (v0.3, the headline):
//     npx @browserid-ng/gate --admin you@example.com
//   Auto-picks a free local port, sets up a tailscale funnel on 443, provisions
//   the gateway's own identity once, and prints a console URL. Sign in there
//   (only --admin gets in) and add MCP servers by name + mount + command +
//   allowlist; each is published at https://<host>/<mount>/mcp. Add
//   --console-local to keep the console on 127.0.0.1 (only the mounts funnel).
//
//   One-shot (library/compat): wrap a single server directly:
//     npx @browserid-ng/gate --allow you@example.com --name "Notes" -- \
//       npx -y @modelcontextprotocol/server-filesystem ~/notes
//
// First run provisions the GATEWAY's own BrowserID identity (Lane B needs one):
// it prints an approval link as the LAST line and blocks until you approve. The
// credential lives in ~/.browserid-gate (override GATE_HOME) and is reused.

import { createGateService } from "../src/gate.mjs";
import { createGateway } from "../src/gateway.mjs";
import { ensureCredential } from "../src/credential.mjs";
import { detectFunnel, ensureFunnel, claimFunnel, funnelOffHint } from "../src/tunnel.mjs";

function parseArgs(argv) {
  const out = { allow: [], child: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--") { out.child = argv.slice(i + 1); break; }
    else if (a === "--admin") out.admin = argv[++i];
    else if (a.startsWith("--admin=")) out.admin = a.slice(8);
    else if (a === "--console-local") out.consoleLocal = true;
    else if (a === "--allow") out.allow.push(...splitList(argv[++i]));
    else if (a.startsWith("--allow=")) out.allow.push(...splitList(a.slice(8)));
    else if (a === "--name") out.name = argv[++i];
    else if (a.startsWith("--name=")) out.name = a.slice(7);
    else if (a === "--handle") out.handle = argv[++i];
    else if (a.startsWith("--handle=")) out.handle = a.slice(9);
    else if (a === "--tunnel") out.tunnel = argv[++i];
    else if (a.startsWith("--tunnel=")) out.tunnel = a.slice(9);
    else if (a === "--port") out.port = Number(argv[++i]);
    else if (a.startsWith("--port=")) out.port = Number(a.slice(7));
    else if (a === "--resource") out.resource = argv[++i];
    else if (a.startsWith("--resource=")) out.resource = a.slice(11);
    else if (a === "--broker") out.broker = argv[++i];
    else if (a.startsWith("--broker=")) out.broker = a.slice(9);
    else if (a === "-h" || a === "--help") out.help = true;
    else { console.error(`gate: unexpected argument '${a}' (did you forget '--' before the server command?)`); process.exit(1); }
  }
  return out;
}
const splitList = (s) => String(s || "").split(/[\s,]+/).filter(Boolean);

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

Console mode (multi-server + admin console):
  npx @browserid-ng/gate --admin you@example.com [--console-local]

One-shot mode (wrap a single server):
  npx @browserid-ng/gate --allow you@example.com --name "Dan's Notes" -- \\
    npx -y @modelcontextprotocol/server-filesystem ~/notes

  --admin <email>    run the console; only this identity may sign in
  --console-local    bind the console to 127.0.0.1 (still funnel /<mount>/*)
  --allow <emails>   one-shot: grantor allowlist (whose humans may connect)
  --name <label>     one-shot: display name (consent cards + landing)
  --handle <slug>    the gateway agent's identity handle (default: slug of --name/host)
  --port <n>         one-shot listen port (default 8787 / $PORT); console auto-picks
  --resource <url>   one-shot public URL = the OAuth audience (default: funnel/localhost)
  --tunnel tailscale one-shot: create a tailscale funnel automatically
  --broker <url>     BrowserID broker (default $BROWSERID_BROKER or https://browserid.me)
  --                 one-shot: the wrapped server command follows

First run provisions the gateway identity: approve the printed link once.`;

async function runConsole(args, broker) {
  const handle = slugifyHandle(args.handle || "mcp-gateway");
  const credential = await ensureCredential({
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

  const { origin, consoleUrl, port } = await gateway.start({ port: args.port ?? 0 });
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
  if (origin.includes(".ts.net")) console.error(`  (teardown: ${funnelOffHint(origin)})`);
  console.error(bar);
}

async function runOneShot(args, broker) {
  const port = args.port || Number(process.env.PORT) || 8787;
  const name = args.name || "mcp gateway";

  let resource = (args.resource || process.env.MCP_RESOURCE || "").replace(/\/+$/, "");
  let derivedFromTunnel = false;
  if (!resource) {
    try {
      if (args.tunnel === "tailscale") {
        resource = await ensureFunnel(port);
        derivedFromTunnel = true;
        console.error(`[gate] tailscale funnel → ${resource}  (teardown: ${funnelOffHint(resource)})`);
      } else {
        const detected = await detectFunnel(port);
        if (detected) { resource = detected; derivedFromTunnel = true; console.error(`[gate] detected tailscale funnel → ${resource}`); }
      }
    } catch (e) {
      console.error(`[gate] tunnel setup failed: ${e.message}`);
    }
    if (!resource) resource = `http://localhost:${port}`;
  }

  const handle = slugifyHandle(args.handle || name);
  const credential = await ensureCredential({
    broker, handle, label: name,
    onApproveUrl: (url, info) => {
      console.error("");
      console.error("This gateway needs its OWN BrowserID identity (approve once). Open this link and approve:");
      if (info?.userCode) console.error(`  (or open ${info.verificationUri} and enter code ${info.userCode})`);
      if (info?.fingerprint) console.error(`  key fingerprint: ${info.fingerprint}`);
      console.error("Waiting for approval…");
      console.log(url); // LAST LINE
    },
  });

  const [command, ...childArgs] = args.child;
  const svc = await createGateService({ allow: args.allow, name, child: { command, args: childArgs }, credential, resource, broker });
  const shutdown = async () => { await svc.close(); process.exit(0); };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);

  svc.server.listen(port, () => {
    const mcpUrl = `${resource}/mcp`;
    const isPublic = resource.startsWith("https://");
    console.error(`[gate] "${name}" listening on :${port}  resource ${resource}`);
    const bar = "─".repeat(64);
    console.error(bar);
    console.error(`  ${name} is live and BrowserID-gated.`);
    console.error(`  Add to Claude:  ${mcpUrl}`);
    if (!isPublic) {
      console.error("");
      console.error("  ⚠ LOCALHOST url — not reachable by Claude/a friend. Put a tunnel in front");
      console.error("    (tailscale funnel / cloudflared) and pass its URL as --resource, or --tunnel tailscale.");
    } else if (derivedFromTunnel) {
      console.error(`  (public URL from your tailscale funnel — teardown: ${funnelOffHint(resource)})`);
    }
    console.error(bar);
  });
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) { console.log(HELP); return; }
  const broker = (args.broker || process.env.BROWSERID_BROKER || "https://browserid.me").replace(/\/+$/, "");

  if (args.admin) return runConsole(args, broker);

  // One-shot mode.
  if (!args.child || args.child.length === 0) {
    console.error("gate: nothing to do. Use --admin <email> for the console, or --allow … -- <cmd> for one-shot.\n\n" + HELP);
    process.exit(1);
  }
  if (args.allow.length === 0) {
    console.error("gate: --allow is required in one-shot mode (at least one grantor email).\n\n" + HELP);
    process.exit(1);
  }
  return runOneShot(args, broker);
}

main().catch((e) => {
  console.error("gate: fatal —", e?.message || e);
  process.exit(1);
});
