// Security audit 2026-11, WS2 — conformance-vector runner for
// @browserid-ng/gate (the mount's jwt-bearer lane and grantor gate).
//
// A mount is created per vector around a FAKE wrapped MCP client (no child
// process) with the vector's audience as its resource and the expected
// grantor on its allowlist; the hosted /verify response the in-process
// verifier recorded for the vector (test-vectors/conformance-2026-11.hosted.json)
// is replayed through the injected fetch. The runner then drives the mount
// over real HTTP: POST /token (jwt-bearer, the vector's bundle) and POST /mcp
// tools/list with the minted bearer. accept = tools/list answers 200;
// reject = /token or the grantor gate refuses. A /verify request that does
// not carry the vector's audience and bundle verbatim is answered with a
// failure and reported as `request diverged`.
//
// For every accept vector a second mount is driven whose allowlist holds the
// grantor with its local part's case flipped (`<id>/case`): spec §5 makes the
// local part byte-exact, so that mount must refuse.
//
// Vectors the gate gets wrong today are listed in EXPECTED_FAIL with the
// audit id they pin (`AUDIT-2026-11 <id>`); any other disagreement fails,
// and so does a listed vector that starts agreeing. Op-A vectors are
// skipped: the gate holds records through mcp-auth, whose runner covers them.
//
// Report: docs/security-audit-2026-11-ws2-conformance.md.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { createMount } from "../src/mount.mjs";
import { createPolicyStore } from "@browserid-ng/mcp-auth";

const VECTORS = JSON.parse(readFileSync(new URL("../../../test-vectors/conformance-2026-11.json", import.meta.url), "utf8"));
const HOSTED = JSON.parse(readFileSync(new URL("../../../test-vectors/conformance-2026-11.hosted.json", import.meta.url), "utf8")).responses;

const EXPECTED_FAIL = {
  // AUDIT-2026-11 W2-1: createMount strips trailing slashes from `resource` (mount.mjs:55), so a
  // warrant audience ending in `/` is sent to the verifier altered. AUDIT-2026-11 D7 (inherited).
  "P-OK-07": "W2-1,D7",
  "P-OK-08": "D7",
  // AUDIT-2026-11 W6-1 (inherited from the hosted verifier).
  "P-OK-12": "W6-1",
  // AUDIT-2026-11 D16 (inherited): no lower bound on iat.
  "P-TIME-05": "D16",
  "P-TIME-06": "D16",
  "P-TIME-07": "D16",
  "P-TIME-08": "D16",
  "P-TIME-09": "D16",
  // AUDIT-2026-11 S3 (inherited).
  "P-TYP-01": "S3",
  "P-TYP-02": "S3",
  // AUDIT-2026-11 W6-4 (inherited).
  "P-STAT-06": "W6-4",
  // AUDIT-2026-11 S5 (inherited).
  "P-CONS-01": "S5",
  "P-CONS-06": "S5",
  // --- op A, policy mode (held record in the mount's policy store, subject = the bearer's grantor) ---
  // Decision Q15 (a) (audit 2026-11 D5): a held policy record admits only with the one binding
  // {holder, "*"}; narrowed holder matchers are refused rather than evaluated until a wallet
  // authors them (Q15 (b)). These two vectors expect the matcher to be evaluated.
  "A-OK-02": "Q15a",
  "A-OK-10": "Q15a",
  // Inherited from the hosted validator (the row is revalidated at admission since D5/D6):
  // AUDIT-2026-11 S3 (v1 records still validate) and D16 (no lower bound on iat).
  "A-REJ-13": "S3",
  "A-REJ-21": "D16",
};

const OWNER = "owner@example.com";

const BROKER = "https://broker.test";
const fakeClient = {
  listTools: async () => ({ tools: [{ name: "ping", description: "", inputSchema: { type: "object" } }] }),
  callTool: async () => ({ content: [] }),
  close: async () => {},
};

function fetchFor(v, diverged) {
  return async (url, init) => {
    if (url.endsWith("/status/check")) return { ok: true, status: 200, json: async () => ({ ok: true, revoked: false }) };
    const body = JSON.parse(init.body);
    if (body.presentation !== v.bundle || body.audience !== v.audience) {
      diverged.push(`audience sent ${JSON.stringify(body.audience)}, presentation ${body.presentation === v.bundle ? "intact" : "altered"}`);
      return { ok: true, status: 200, json: async () => ({ status: "failure", reason: "runner: request diverged from the vector" }) };
    }
    return { ok: true, status: 200, json: async () => HOSTED[v.id] };
  };
}

/** Flip the case of the first letter of the local part. */
function flipCase(email) {
  const i = [...email].findIndex((c) => /[a-z]/i.test(c));
  if (i < 0) return email;
  const c = email[i];
  return email.slice(0, i) + (c === c.toLowerCase() ? c.toUpperCase() : c.toLowerCase()) + email.slice(i + 1);
}

/** Drive one mount: returns { ok, email?, reason? }. */
async function drive(v, allow, diverged) {
  const mount = await createMount({ resource: v.audience, broker: BROKER, name: "vectors", allow, client: fakeClient, fetch: fetchFor(v, diverged) });
  const server = createServer(async (rq, res) => {
    const url = new URL(rq.url, "http://127.0.0.1");
    try {
      if (!(await mount.handle(rq, res, { subpath: url.pathname, url }))) { res.writeHead(404); res.end(); }
    } catch (e) {
      res.writeHead(500); res.end(String(e));
    }
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    const tok = await fetch(`${base}/token`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion: v.bundle }),
    });
    const tj = await tok.json();
    if (!tok.ok) return { ok: false, reason: `/token ${tok.status}: ${tj.error_description || tj.error}` };
    const rpc = await fetch(`${base}/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${tj.access_token}` },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    });
    const text = await rpc.text();
    if (!rpc.ok) return { ok: false, reason: `/mcp ${rpc.status}: ${text.slice(0, 120)}` };
    const email = HOSTED[v.id].email;
    return { ok: true, email, grantee: HOSTED[v.id].grantee, scopes: HOSTED[v.id].scopes };
  } finally {
    await new Promise((r) => server.close(r));
    await mount.close();
  }
}

/** Op A in policy mode: the vector's record is a held policy row; the subject
 *  arrives as a jwt-bearer whose /verify answer (synthetic, no crypto — the
 *  record is what is under test) names the subject as grantor. admitted =
 *  tools/list answers 200, refused = the grantor gate's 403. */
async function driveA(v) {
  const w = v.objects.warrant;
  const store = createPolicyStore();
  await store.put({ record: v.bundle, grantor: w.grantor, grantee: w.grantee, audience: w.audience, scopes: ["tool:ping"], exp: w.exp });
  const subject = v.subject;
  const fetchA = async (url, init) => {
    if (url.endsWith("/status/check")) return { ok: true, status: 200, json: async () => ({ ok: true, revoked: false }) };
    if (url.endsWith("/validate-record")) {
      // The held row is revalidated at admission (D6): answer with the recorded hosted verdict
      // for THIS record, or a failure when the request diverged from the vector.
      const body = JSON.parse(init.body);
      if (body.record !== v.bundle || body.audience !== v.audience) return { ok: true, status: 200, json: async () => ({ status: "failure", reason: "runner: request diverged from the vector" }) };
      return { ok: true, status: 200, json: async () => HOSTED[v.id] };
    }
    return { ok: true, status: 200, json: async () => ({ status: "okay", email: subject.identity, grantee: subject.identity, holder: subject.holder, issuer: "browserid.me", scopes: ["tool:ping"], status_refs: [] }) };
  };
  const mount = await createMount({ resource: v.audience, broker: BROKER, name: "vectors", owners: [OWNER], policyStore: store, client: fakeClient, fetch: fetchA });
  const server = createServer(async (rq, res) => {
    const url = new URL(rq.url, "http://127.0.0.1");
    try {
      if (!(await mount.handle(rq, res, { subpath: url.pathname, url }))) { res.writeHead(404); res.end(); }
    } catch (e) { res.writeHead(500); res.end(String(e)); }
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    const tok = await fetch(`${base}/token`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion: "a~b~c~d" }) });
    const tj = await tok.json();
    if (!tok.ok) return { ok: false, reason: `/token ${tok.status}: ${tj.error_description || tj.error}` };
    const rpc = await fetch(`${base}/mcp`, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${tj.access_token}` }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }) });
    const text = await rpc.text();
    if (!rpc.ok) return { ok: false, reason: `/mcp ${rpc.status}: ${text.slice(0, 100)}` };
    return { ok: true, email: w.grantor, grantee: w.grantee, scopes: ["tool:ping"] };
  } finally {
    await new Promise((r) => server.close(r));
    await mount.close();
  }
}

function mismatch(e, r) {
  const wantAccept = e.verdict === "accept";
  if (wantAccept && !r.ok) return `expected accept, got reject: ${r.reason}`;
  if (!wantAccept && r.ok) return `expected reject (${e.reason_class}), got accept as ${r.email}`;
  if (!wantAccept) return null;
  const d = [];
  if (r.email !== e.email) d.push(`email ${e.email} != ${r.email}`);
  try { assert.deepEqual(r.scopes, e.scopes); } catch { d.push(`scopes ${JSON.stringify(e.scopes)} != ${JSON.stringify(r.scopes)}`); }
  return d.length ? d.join("; ") : null;
}

test("gate conformance vectors", async () => {
  let pass = 0, xfail = 0, skipped = 0;
  const unexpected = [], fixed = [];
  const judge = (id, why, short) => {
    const fid = EXPECTED_FAIL[id];
    if (!why && !fid) { pass++; console.log(`ok    ${id.padEnd(14)} ${short}`); }
    else if (why && fid) { xfail++; console.log(`XFAIL ${id.padEnd(14)} [${fid}] ${why}`); }
    else if (why) { console.log(`FAIL  ${id.padEnd(14)} ${why}`); unexpected.push(`${id}: ${why}`); }
    else { console.log(`FIXED ${id.padEnd(14)} [${fid}] now agrees — remove it from EXPECTED_FAIL`); fixed.push(`${id} [${fid}]`); }
  };
  for (const v of VECTORS.vectors) {
    if (v.op === "A") {
      if (!v.subject) { skipped++; continue; } // connection records: no login subject to admit
      const r = await driveA(v);
      const e = v.expect;
      const why = e.verdict === "accept"
        ? (r.ok ? null : `expected admit, got refuse: ${r.reason}`)
        : (r.ok ? `expected refuse (${e.reason_class}), got admit` : null);
      judge(v.id, why, r.ok ? `admit ${v.subject.identity}` : `refuse: ${r.reason}`);
      continue;
    }
    if (v.op !== "P") { skipped++; continue; }
    // Allowlist the grantor the bundle itself names, so the grantor gate never
    // masks the verifier's verdict (a reject vector must reject at /token,
    // not because its grantor is absent from the allowlist).
    const allowed = v.objects?.warrant?.grantor || v.expect.email || "nobody@example.com";
    const diverged = [];
    const r = await drive(v, [allowed], diverged);
    let why = mismatch(v.expect, r);
    if (diverged.length) why = `request diverged: ${diverged.join("; ")}${why ? ` → ${why}` : ""}`;
    judge(v.id, why, r.ok ? `accept ${r.email}` : `reject: ${r.reason}`);
    if (v.expect.verdict === "accept" && r.ok) {
      const probe = await drive(v, [flipCase(allowed)], []);
      const pwhy = probe.ok ? `allowlist entry ${flipCase(allowed)} admitted grantor ${allowed} (local part must be byte-exact)` : null;
      judge(`${v.id}/case`, pwhy, probe.ok ? `accept ${probe.email}` : `reject: ${probe.reason}`);
    }
  }
  console.log(`\ngate: ${pass} pass, ${xfail} expected-fail, ${skipped} skipped (op A without subject, op T), ${unexpected.length} unexpected, ${fixed.length} fixed`);
  assert.deepEqual(unexpected, [], "vectors disagreeing with the gate");
  assert.deepEqual(fixed, [], "vectors now passing; drop them from EXPECTED_FAIL");
});
