// Agent-friendly, non-blocking front end to the browserid-agent CLI, so an LLM
// agent can obtain an assertion in two quick tool calls instead of running a
// command that blocks on human consent:
//
//   node mint-assertion.mjs consent <audience>
//       → prints  CONSENT_URL: <url>   (the human approves the warrant there)
//         or       READY               (a warrant already existed)
//       returns immediately; the CLI keeps running detached until approved.
//
//   node mint-assertion.mjs get <audience>
//       → prints  ASSERTION: <certificate~assertion~warrant>   once approved
//         or       PENDING              (approve the consent URL, then retry)
//
// It shells to the agent CLI. Point AGENT_CLI at the command prefix that already
// includes your credential, e.g.:
//   export AGENT_CLI="cargo run -q -p browserid-agent --example agent_cli -- ./agent-credential.json"
// (default assumes ./agent-credential.json in this directory).

import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, existsSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

// Everything resolves relative to THIS file, so it works from any cwd with no
// env vars: the credential sits next to it, and the agent CLI is run against the
// workspace two levels up.
const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, "..", "..");
const CREDENTIAL = process.env.AGENT_CREDENTIAL || join(HERE, "agent-credential.json");
const AGENT_CLI =
  process.env.AGENT_CLI ||
  `cargo run -q --manifest-path ${JSON.stringify(join(REPO, "Cargo.toml"))} ` +
    `-p browserid-agent --example agent_cli -- ${JSON.stringify(CREDENTIAL)}`;

const [, , cmd, audience] = process.argv;
if (!cmd || !audience || !["consent", "get"].includes(cmd)) {
  console.error("usage: node mint-assertion.mjs <consent|get> <audience>");
  process.exit(2);
}

// Preflight: without an agent identity there's nothing to mint. Tell the agent
// exactly what to ask the human for.
if (!existsSync(CREDENTIAL)) {
  console.log(
    "NEED_CREDENTIAL: no agent identity yet. Ask the human to create an agent key at " +
      "https://browserid.me/agents and save the downloaded file as:\n  " + CREDENTIAL
  );
  process.exit(4);
}

// Stable per-audience temp files so `consent` and a later `get` (separate
// processes) share state.
const tag = createHash("sha1").update(audience).digest("hex").slice(0, 12);
const dir = join(tmpdir(), "browserid-mint");
mkdirSync(dir, { recursive: true });
const outFile = join(dir, `${tag}.assertion`);
const errFile = join(dir, `${tag}.log`);

function readAssertion() {
  if (!existsSync(outFile)) return null;
  const s = readFileSync(outFile, "utf8").trim();
  // The CLI prints exactly the assertion on stdout; a valid one has two '~'.
  return s.includes("~") ? s.split("\n").pop().trim() : null;
}

if (cmd === "get") {
  const a = readAssertion();
  if (a) console.log("ASSERTION: " + a);
  else console.log("PENDING — approve the consent URL, then retry `get`.");
  process.exit(a ? 0 : 3);
}

// cmd === "consent": always mint fresh, so a stale/expired assertion from a
// previous run is never handed back. Clear prior state before spawning.
rmSync(outFile, { force: true });
rmSync(errFile, { force: true });

// Kick off `assert <audience>`, detached, redirecting its streams to files so it
// survives this process exiting. It prints the approve URL to stderr, blocks
// until the human approves, then writes the assertion to stdout (→ outFile).
const sh = `${AGENT_CLI} assert ${JSON.stringify(audience)} >${JSON.stringify(outFile)} 2>${JSON.stringify(errFile)}`;
const child = spawn("sh", ["-c", sh], { detached: true, stdio: "ignore" });
child.unref();

// Poll the log for the approve URL (or an early assertion if a warrant existed).
const deadline = Date.now() + 30000;
const timer = setInterval(() => {
  if (readAssertion()) {
    clearInterval(timer);
    console.log("READY — a warrant already existed; call `get` to read the assertion.");
    process.exit(0);
  }
  let log = "";
  try { log = readFileSync(errFile, "utf8"); } catch {}
  const m = log.match(/approve at:\s*(\S+)/i);
  if (m) {
    clearInterval(timer);
    console.log("CONSENT_URL: " + m[1]);
    console.log("(approve there, then call `get` for the assertion)");
    process.exit(0);
  }
  if (Date.now() > deadline) {
    clearInterval(timer);
    console.error("timed out waiting for the CLI to emit a consent URL. Log:\n" + log);
    process.exit(1);
  }
}, 400);
