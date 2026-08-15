#!/usr/bin/env node
// E2E fixture: a credential-less gate (spec §6.5 × §7.5) wrapping the
// fs-child, plus a TEST-ONLY admin surface on PORT+1 that triggers the
// share (authoring) ceremony — the piece a product console would own.
//
//   node gate-server.mjs <port> <broker> <ownerEmail>
//
// Prints "READY" on stdout once both listeners are up.
import { createServer } from "node:http";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createGateService } from "../../sdk/gate/src/gate.mjs";

const PORT = Number(process.argv[2]);
const BROKER = process.argv[3];
const OWNER = process.argv[4];
const HERE = dirname(fileURLToPath(import.meta.url));

const dataDir = mkdtempSync(join(tmpdir(), "gate-e2e-"));
writeFileSync(join(dataDir, "hello.txt"), "shared notes from the vault\n");

const svc = await createGateService({
  owners: [OWNER],
  name: "Shared Notes (e2e)",
  child: {
    command: process.execPath,
    args: [join(HERE, "..", "..", "sdk", "gate", "test", "fixtures", "fs-child.mjs"), dataDir],
  },
  resource: `http://127.0.0.1:${PORT}`,
  broker: BROKER,
  statusCacheS: 2,
  log: (l) => console.error(l),
});

// Test-only share surface: POST /share {grantee, scopes} → {request_id,
// consent_uri}; GET /share/<id> → {status, rows?|error?}.
const shares = new Map();
const admin = createServer(async (rq, res) => {
  const reply = (code, obj) => {
    res.writeHead(code, { "content-type": "application/json" });
    res.end(JSON.stringify(obj));
  };
  try {
    if (rq.method === "POST" && rq.url === "/share") {
      let raw = "";
      for await (const c of rq) raw += c;
      const body = JSON.parse(raw);
      const ceremony = await svc.lane.requestAuthoring({
        grants: [{ grantee: body.grantee, scopes: body.scopes || [] }],
        grantor: OWNER,
        pollDelayMs: 500,
      });
      shares.set(ceremony.requestId, { status: "pending" });
      ceremony.wait().then(
        (rows) => shares.set(ceremony.requestId, { status: "done", rows }),
        (e) => shares.set(ceremony.requestId, { status: "error", error: String(e.message || e) })
      );
      return reply(200, { request_id: ceremony.requestId, consent_uri: ceremony.consentUri });
    }
    const m = /^\/share\/([^/]+)$/.exec(rq.url || "");
    if (rq.method === "GET" && m) {
      return reply(200, shares.get(m[1]) || { status: "unknown" });
    }
    reply(404, { error: "not_found" });
  } catch (e) {
    reply(500, { error: String(e.message || e) });
  }
});

await new Promise((r) => svc.server.listen(PORT, r));
await new Promise((r) => admin.listen(PORT + 1, r));
console.log("READY");
