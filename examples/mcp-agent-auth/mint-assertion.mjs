// Agent-friendly front end to the browserid-agent CLI, so an LLM agent can
// obtain a scoped, warrant-backed assertion in two quick tool calls:
//
//   node mint-assertion.mjs consent <audience> [scope...]   (default: post read)
//       → CONSENT_URL: <url>   the human approves the warrant there
//         or  READY            a warrant already covering these scopes exists
//         or  ERROR: <reason>  the CLI failed (surfaced, not buried)
//       returns immediately; the CLI keeps running detached until approved.
//
//   node mint-assertion.mjs get <audience>
//       → ASSERTION: <certificate~assertion~warrant>   (polls until approved)
//         or  PENDING          not approved yet — approve the link, then retry
//         or  ERROR: <reason>
//
// It requests SCOPES via the CLI's `grant`, then reads the assertion via
// `assert` — so the warrant the human approves actually carries those scopes.
//
// Zero config: the credential (agent-credential.json) and the agent CLI are
// found relative to this file. Override with AGENT_CREDENTIAL / AGENT_CLI, and
// set AGENT_NAME to provision a specific reserved name (multi-name credentials).

import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, existsSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, "..", "..");
const CREDENTIAL = process.env.AGENT_CREDENTIAL || join(HERE, "agent-credential.json");
const AGENT_CLI =
  process.env.AGENT_CLI ||
  `cargo run -q --manifest-path ${JSON.stringify(join(REPO, "Cargo.toml"))} ` +
    `-p browserid-agent --example agent_cli -- ${JSON.stringify(CREDENTIAL)}`;

const [, , cmd, audience, ...scopeArgs] = process.argv;
if (!cmd || !audience || !["consent", "get"].includes(cmd)) {
  console.error("usage: node mint-assertion.mjs <consent|get> <audience> [scope...]");
  process.exit(2);
}
const SCOPES = scopeArgs.length ? scopeArgs : ["post", "read"];

if (!existsSync(CREDENTIAL)) {
  console.log(
    "NEED_CREDENTIAL: no agent identity yet. Ask the human to create an agent key at " +
      "https://browserid.me/agents and save the downloaded file as:\n  " + CREDENTIAL
  );
  process.exit(4);
}

// Per-audience temp files shared between the `consent` and `get` processes.
const tag = createHash("sha1").update(audience).digest("hex").slice(0, 12);
const dir = join(tmpdir(), "browserid-mint");
mkdirSync(dir, { recursive: true });
const outFile = join(dir, `${tag}.assertion`);
const logFile = join(dir, `${tag}.log`);
const q = JSON.stringify;

const readAssertion = () => {
  if (!existsSync(outFile)) return null;
  const s = readFileSync(outFile, "utf8").trim();
  return s.includes("~") ? s.split("\n").pop().trim() : null; // a valid one has '~'
};
const readLog = () => { try { return readFileSync(logFile, "utf8"); } catch { return ""; } };
const failed = () => readLog().includes("MINT_FAILED");
// Surface the CLI's own error line, skipping cargo build chatter.
function reason() {
  const lines = readLog().split("\n").map((l) => l.trim()).filter(Boolean)
    .filter((l) => !/^(warning|compiling|finished|running|updating|\s*downloaded|\s*compiling)\b/i.test(l))
    .filter((l) => l !== "MINT_FAILED");
  const errLine = [...lines].reverse().find((l) => /^error[: ]/i.test(l));
  return errLine || lines[lines.length - 1] || "unknown error (see the CLI output)";
}

// ---- get: poll until the assertion appears (the human is approving) --------
if (cmd === "get") {
  const deadline = Date.now() + 150000;
  const tick = () => {
    const a = readAssertion();
    if (a) { console.log("ASSERTION: " + a); process.exit(0); }
    if (failed()) { console.log("ERROR: " + reason()); process.exit(1); }
    if (Date.now() > deadline) {
      console.log("PENDING — not approved yet. Approve the consent link, then run `get` again.");
      process.exit(3);
    }
    setTimeout(tick, 2000);
  };
  tick();
}

// ---- consent: request the scopes, return the approve URL -------------------
if (cmd === "consent") {
  rmSync(outFile, { force: true });
  rmSync(logFile, { force: true });

  // grant <aud> <scopes...> runs the consent flow (prints "approve at: <url>",
  // then holds a warrant WITH the scopes); assert <aud> then emits the
  // assertion. Detached + stream to files so this process can return the URL
  // immediately while the CLI blocks on the human. A failure writes MINT_FAILED.
  // If the human reserved a specific name (multi-name credential), provision it
  // first; otherwise the CLI auto-provisions (single reserved name or pattern).
  const provision = process.env.AGENT_NAME
    ? `${AGENT_CLI} provision ${q(process.env.AGENT_NAME)} && `
    : "";
  const grant = `${AGENT_CLI} grant ${q(audience)} ${SCOPES.map(q).join(" ")}`;
  const assert = `${AGENT_CLI} assert ${q(audience)} >${q(outFile)}`;
  const sh = `( ${provision}${grant} && ${assert} ) 2>>${q(logFile)} || echo MINT_FAILED >>${q(logFile)}`;
  spawn("sh", ["-c", sh], { detached: true, stdio: "ignore" }).unref();

  // Wait for one of: an approve URL, an early assertion (warrant already held),
  // or a failure. Generous deadline: the CLI may compile on first run.
  const deadline = Date.now() + 150000;
  const tick = () => {
    if (readAssertion()) {
      console.log("READY — a warrant covering these scopes already exists; call `get`.");
      process.exit(0);
    }
    const m = readLog().match(/approve at:\s*(\S+)/i);
    if (m) {
      console.log("CONSENT_URL: " + m[1]);
      console.log("(show this to the human; when they approve, call `get`)");
      process.exit(0);
    }
    if (failed()) { console.log("ERROR: " + reason()); process.exit(1); }
    if (Date.now() > deadline) {
      console.log("ERROR: timed out before the CLI produced a consent URL. Last output:\n" + reason());
      process.exit(1);
    }
    setTimeout(tick, 400);
  };
  tick();
}
