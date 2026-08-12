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
import { detectFunnel, ensureFunnel, funnelOffHint } from "../src/tunnel.mjs";

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

// A BrowserID identity handle for the gateway agent: lowercased, non-alnum →
// hyphens, trimmed, bounded. "Dan's Notes" → "dans-notes". Never empty (an
// empty handle would request the base identity — the "become you" trap).
function slugifyHandle(name) {
  const s = String(name || "")
    .toLowerCase()
    .replace(/['’]/g, "") // drop apostrophes: "Dan's" → "dans", not "dan-s"
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 40)
    .replace(/-+$/g, "");
  return s || "mcp-gateway";
}

const HELP = `gate — wrap a stdio MCP server as a BrowserID-gated HTTP endpoint

  npx @browserid-ng/gate --allow you@example.com,friend@gmail.com --name "Dan's Notes" -- \\
    npx -y @modelcontextprotocol/server-filesystem ~/notes

  --allow <emails>   grantor allowlist — whose humans may connect (required)
  --name <label>     display name (consent cards + landing)
  --handle <slug>    the gateway agent's identity handle (default: slug of --name)
  --port <n>         listen port (default 8787 / $PORT)
  --resource <url>   public URL of this gate = the OAuth audience (default: auto-detected
                     from a tailscale funnel to --port, else http://localhost:<port>)
  --tunnel tailscale set up a tailscale funnel to --port automatically (picks a free
                     funnel port) and use its URL as --resource
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
  const name = args.name || "mcp gateway";

  // Resolve the public resource (OAuth audience). Precedence: explicit
  // --resource / $MCP_RESOURCE win; otherwise detect an existing tailscale
  // funnel to our port (or, with --tunnel tailscale, create one), and fall
  // back to localhost only if there's no tunnel. The audience MUST be the URL
  // hosts actually reach — deriving it removes the #1 M3 footgun.
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
        if (detected) {
          resource = detected;
          derivedFromTunnel = true;
          console.error(`[gate] detected tailscale funnel → ${resource}`);
        }
      }
    } catch (e) {
      console.error(`[gate] tunnel setup failed: ${e.message}`);
      // fall through to localhost; the operator can still pass --resource
    }
    if (!resource) resource = `http://localhost:${port}`;
  }

  // 1. The gateway's own identity (Lane B). Provision once, then reuse.
  //    It MUST be a distinct named agent, never the operator's base identity —
  //    requesting a `handle` is what makes it "an agent acting for you" rather
  //    than "you" (omitting it trips BrowserID's "it's asking to become you"
  //    refusal). Derive the handle from --name (or --handle), so "Dan's Notes"
  //    provisions e.g. `<you>+dans-notes@<domain>`.
  //    The approval link must be the LAST line, so print status to stderr and
  //    the link to stdout as the final thing before we block on approval.
  const handle = slugifyHandle(args.handle || name);
  const credential = await ensureCredential({
    broker,
    handle,
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
    const mcpUrl = `${resource}/mcp`;
    const isPublic = resource.startsWith("https://");
    console.error(`[gate] "${name}" listening on :${port}`);
    console.error(`[gate]   resource (audience): ${resource}`);
    console.error(`[gate]   broker:              ${broker}`);
    console.error(`[gate]   allowed grantors:    ${args.allow.join(", ")}`);
    console.error(`[gate]   wrapped tools:       ${svc.tools.map((t) => t.name).join(", ") || "(none)"}`);
    console.error("");
    const bar = "─".repeat(64);
    console.error(bar);
    console.error(`  ${name} is live and BrowserID-gated.`);
    console.error("");
    console.error("  Add to Claude (claude.ai → Settings → Connectors → Add):");
    console.error(`    ${mcpUrl}`);
    console.error("");
    console.error("  Share with a friend (they approve with their own identity):");
    console.error(`    ${mcpUrl}`);
    if (!isPublic) {
      console.error("");
      console.error("  ⚠ This is a LOCALHOST url — not reachable by Claude or a friend.");
      console.error("    Put a public tunnel in front and it'll be picked up automatically:");
      console.error(`      tailscale funnel --https=8443 ${port}      (then rerun, or pass --tunnel tailscale)`);
      console.error("    or cloudflared, passing its URL as --resource.");
    } else if (derivedFromTunnel) {
      console.error("");
      console.error(`  (public URL derived from your tailscale funnel — teardown: ${funnelOffHint(resource)})`);
    }
    console.error(bar);
  });
}

main().catch((e) => {
  console.error("gate: fatal —", e?.message || e);
  process.exit(1);
});
