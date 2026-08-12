#!/usr/bin/env node
// gate — the CLI. Wrap a stdio MCP server as a BrowserID-gated HTTP endpoint.
//
//   npx @browserid-ng/gate --allow you@example.com,friend@gmail.com --name "Dan's Notes" -- \
//     npx -y @modelcontextprotocol/server-filesystem ~/notes
//
// On first run it provisions the GATEWAY's own BrowserID identity (Lane B needs
// one): it prints an approval link as the LAST line and waits for you to
// approve it once. The credential is stored in ~/.browserid-gate (override
// GATE_HOME) and reused on every subsequent boot — no human in the loop again.
//
// Flags:
//   --allow <emails>   comma/space-separated grantor allowlist (required)
//   --name <label>     display name on consent cards + the landing page
//   --port <n>         listen port (default 8787, or $PORT)
//   --resource <url>   public URL of this gate (default http://localhost:<port>;
//                      set this to your tunnel URL — the OAuth audience)
//   --broker <url>     BrowserID broker (default https://browserid.me / $BROWSERID_BROKER)
//   --                 everything after this is the wrapped server command + args
//
// Reachability is NOT ours: put a tunnel in front (see README — `tailscale
// funnel` / `cloudflared`) and pass its public URL as --resource.

import { createGateService } from "../src/gate.mjs";
import { ensureCredential } from "../src/credential.mjs";

function parseArgs(argv) {
  const out = { allow: [], child: null };
  let i = 0;
  for (; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--") { out.child = argv.slice(i + 1); break; }
    else if (a === "--allow") out.allow.push(...splitList(argv[++i]));
    else if (a.startsWith("--allow=")) out.allow.push(...splitList(a.slice(8)));
    else if (a === "--name") out.name = argv[++i];
    else if (a.startsWith("--name=")) out.name = a.slice(7);
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

const HELP = `gate — wrap a stdio MCP server as a BrowserID-gated HTTP endpoint

  npx @browserid-ng/gate --allow you@example.com,friend@gmail.com --name "Dan's Notes" -- \\
    npx -y @modelcontextprotocol/server-filesystem ~/notes

  --allow <emails>   grantor allowlist — whose humans may connect (required)
  --name <label>     display name (consent cards + landing)
  --port <n>         listen port (default 8787 / $PORT)
  --resource <url>   public URL of this gate = the OAuth audience (default http://localhost:<port>)
  --broker <url>     BrowserID broker (default $BROWSERID_BROKER or https://browserid.me)
  --                 the wrapped server command follows

First run provisions the gateway identity: approve the printed link once.
Put a tunnel (tailscale funnel / cloudflared) in front and pass its URL as --resource.`;

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) { console.log(HELP); return; }
  if (!args.child || args.child.length === 0) {
    console.error("gate: no wrapped server command — put it after '--'.\n\n" + HELP);
    process.exit(1);
  }
  if (args.allow.length === 0) {
    console.error("gate: --allow is required (at least one grantor email whose agents may connect).\n\n" + HELP);
    process.exit(1);
  }

  const broker = (args.broker || process.env.BROWSERID_BROKER || "https://browserid.me").replace(/\/+$/, "");
  const port = args.port || Number(process.env.PORT) || 8787;
  const resource = (args.resource || process.env.MCP_RESOURCE || `http://localhost:${port}`).replace(/\/+$/, "");
  const name = args.name || "mcp gateway";

  // 1. The gateway's own identity (Lane B). Provision once, then reuse.
  //    The approval link must be the LAST line, so print status to stderr and
  //    the link to stdout as the final thing before we block on approval.
  const credential = await ensureCredential({
    broker,
    label: name,
    onApproveUrl: (url, info) => {
      console.error("");
      console.error("This gateway needs its OWN BrowserID identity (approve once). Open this link and approve:");
      if (info?.userCode) console.error(`  (or open ${info.verificationUri} and enter code ${info.userCode})`);
      if (info?.fingerprint) console.error(`  key fingerprint: ${info.fingerprint}`);
      console.error("Waiting for approval…");
      console.log(url); // LAST LINE
    },
  });

  // 2. Spawn + proxy the wrapped child, gate it, listen.
  const [command, ...childArgs] = args.child;
  const svc = await createGateService({
    allow: args.allow,
    name,
    child: { command, args: childArgs },
    credential,
    resource,
    broker,
  });

  const shutdown = async () => { await svc.close(); process.exit(0); };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);

  svc.server.listen(port, () => {
    console.error(`[gate] "${name}" listening on :${port}`);
    console.error(`[gate]   resource (audience): ${resource}`);
    console.error(`[gate]   broker:              ${broker}`);
    console.error(`[gate]   allowed grantors:    ${args.allow.join(", ")}`);
    console.error(`[gate]   wrapped tools:       ${svc.tools.map((t) => t.name).join(", ") || "(none)"}`);
    console.error(`[gate]   add to a host as:    ${resource}/mcp`);
  });
}

main().catch((e) => {
  console.error("gate: fatal —", e?.message || e);
  process.exit(1);
});
