// Security audit 2026-11, WS2 — conformance-vector runner for
// @browserid-ng/mcp-auth.
//
// The package delegates crypto to the hosted /verify and /validate-record;
// this runner replays the response the in-process hosted verifier recorded
// per vector (test-vectors/conformance-2026-11.hosted.json, written by
// browserid-verifier/tests/audit_2026_11_ws2_runner.rs) through the
// injected fetch. Under test is the package's own contribution:
//   op P — the request it builds (bundle + audience verbatim) and the bearer
//          it mints from the response;
//   op A — validateRecord's request and result, then the package's own
//          §6.4 step-3 subject match. The package matches a subject against a
//          held record with `granteeCovers(record.grantee, subject)` alone
//          (conjoinPolicy, index.mjs), so that is what the match stage runs.
// A request that does not carry the vector's audience and bundle verbatim
// is answered with a failure and reported as `request diverged`.
//
// Vectors the package gets wrong today are listed in EXPECTED_FAIL with the
// audit id they pin (`AUDIT-2026-11 <id>`); any other disagreement fails,
// and so does a listed vector that starts agreeing.
//
// Report: docs/security-audit-2026-11-ws2-conformance.md.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createMcpAuth, granteeCovers, assertPolicyBinding, JWT_BEARER_GRANT, McpAuthError } from "../index.mjs";

const VECTORS = JSON.parse(readFileSync(new URL("../../../test-vectors/conformance-2026-11.json", import.meta.url), "utf8"));
const HOSTED = JSON.parse(readFileSync(new URL("../../../test-vectors/conformance-2026-11.hosted.json", import.meta.url), "utf8")).responses;

const EXPECTED_FAIL = {
  // AUDIT-2026-11 D7: scope entries arrive flattened and the bearer carries strings only.
  "P-OK-07": "D7",
  "P-OK-08": "D7",
  "A-OK-08": "D7",
  // AUDIT-2026-11 W6-1 (inherited from the hosted verifier).
  "P-OK-12": "W6-1",
  // AUDIT-2026-11 D16 (inherited): no lower bound on iat.
  "P-TIME-05": "D16",
  "P-TIME-06": "D16",
  "P-TIME-07": "D16",
  "P-TIME-08": "D16",
  "P-TIME-09": "D16",
  "A-REJ-21": "D16",
  // AUDIT-2026-11 S3 (inherited): v1 records still verify/validate.
  "P-TYP-01": "S3",
  "P-TYP-02": "S3",
  "A-REJ-13": "S3",
  // AUDIT-2026-11 W6-4 (inherited).
  "P-STAT-06": "W6-4",
  // AUDIT-2026-11 S5 (inherited).
  "P-CONS-01": "S5",
  "P-CONS-06": "S5",
  // Decision Q15 (a) (audit 2026-11 D5): a held policy record admits only with the one binding
  // {holder, "*"}; narrowed holder matchers are refused rather than evaluated until a wallet
  // authors them (Q15 (b)). These two vectors expect the matcher to be evaluated.
  "A-OK-02": "Q15a",
  "A-OK-10": "Q15a",
};

const BROKER = "https://broker.test";

function fetchFor(v, diverged) {
  return async (url, init) => {
    const body = JSON.parse(init.body);
    const sent = v.op === "P" ? body.presentation : body.record;
    if (sent !== v.bundle || body.audience !== v.audience) {
      diverged.push(`audience sent ${JSON.stringify(body.audience)}, bundle ${sent === v.bundle ? "intact" : "altered"}`);
      return { ok: true, status: 200, json: async () => ({ status: "failure", reason: "runner: request diverged from the vector" }) };
    }
    if (url.endsWith("/status/check")) return { ok: true, status: 200, json: async () => ({ ok: true, revoked: false }) };
    return { ok: true, status: 200, json: async () => v.hostedOverride || HOSTED[v.id] };
  };
}

/** The hosted response a D7-fixed verifier would return: the vector's
 *  expected scope entries verbatim, objects included (W4-14 probe). */
function withEntries(v) {
  return { ...v, id: `${v.id}/entries`, hostedOverride: { ...HOSTED[v.id], scopes: v.expect.scopes } };
}

async function runP(v, diverged) {
  const auth = createMcpAuth({ resource: v.audience, broker: BROKER, fetch: fetchFor(v, diverged) });
  try {
    const out = await auth.handleToken({ grant_type: JWT_BEARER_GRANT, assertion: v.bundle });
    const ctx = await auth.authenticate(`Bearer ${out.access_token}`);
    return { ok: true, email: ctx.grantor, grantee: ctx.grantee, holder: ctx.holder, scopes: ctx.scopes };
  } catch (e) {
    if (!(e instanceof McpAuthError)) throw e;
    return { ok: false, reason: e.message };
  }
}

async function runA(v, diverged) {
  const auth = createMcpAuth({ resource: v.audience, broker: BROKER, fetch: fetchFor(v, diverged) });
  let r;
  try {
    r = await auth.validateRecord(v.bundle, v.audience);
  } catch (e) {
    if (!(e instanceof McpAuthError)) throw e;
    return { ok: false, reason: e.message };
  }
  if (v.subject && !granteeCovers(r.grantee, v.subject.identity)) {
    return { ok: false, reason: `subject ${v.subject.identity} not covered by grantee ${r.grantee}` };
  }
  if (v.subject) {
    // Admission of a login subject under a held policy record (§6.4 step 3, Q15 (a)).
    try { assertPolicyBinding(r.binding); } catch (e) { return { ok: false, reason: e.message }; }
  }
  return { ok: true, email: r.grantor, grantee: r.grantee, holder: v.subject?.holder ?? "", scopes: r.scopes };
}

function mismatch(v, r) {
  const e = v.expect;
  const wantAccept = e.verdict === "accept";
  if (wantAccept && !r.ok) return `expected accept, got reject: ${r.reason}`;
  if (!wantAccept && r.ok) return `expected reject (${e.reason_class}), got accept as ${r.email}`;
  if (!wantAccept) return null;
  const d = [];
  if (r.email !== e.email) d.push(`email ${e.email} != ${r.email}`);
  if (r.grantee !== e.grantee) d.push(`grantee ${e.grantee} != ${r.grantee}`);
  if (v.op === "P" && r.holder !== e.holder) d.push(`holder ${e.holder} != ${r.holder}`);
  try { assert.deepEqual(r.scopes, e.scopes); } catch { d.push(`scopes ${JSON.stringify(e.scopes)} != ${JSON.stringify(r.scopes)}`); }
  return d.length ? d.join("; ") : null;
}

test("mcp-auth conformance vectors", async () => {
  let pass = 0, xfail = 0, skipped = 0;
  const unexpected = [], fixed = [];
  const probes = VECTORS.vectors.filter((v) => v.id === "P-OK-08" || v.id === "A-OK-08").map(withEntries);
  for (const v of [...VECTORS.vectors, ...probes]) {
    if (v.op !== "P" && v.op !== "A") { skipped++; continue; }
    const diverged = [];
    const r = v.op === "P" ? await runP(v, diverged) : await runA(v, diverged);
    let why = mismatch(v, r);
    if (diverged.length) why = `request diverged: ${diverged.join("; ")}${why ? ` → ${why}` : ""}`;
    const fid = EXPECTED_FAIL[v.id];
    if (!why && !fid) { pass++; console.log(`ok    ${v.id.padEnd(10)} ${r.ok ? `accept ${r.email}` : `reject: ${r.reason}`}`); }
    else if (why && fid) { xfail++; console.log(`XFAIL ${v.id.padEnd(10)} [${fid}] ${why}`); }
    else if (why) { console.log(`FAIL  ${v.id.padEnd(10)} ${why}`); unexpected.push(`${v.id}: ${why}`); }
    else { console.log(`FIXED ${v.id.padEnd(10)} [${fid}] now agrees — remove it from EXPECTED_FAIL`); fixed.push(`${v.id} [${fid}]`); }
  }
  console.log(`\nmcp-auth: ${pass} pass, ${xfail} expected-fail, ${skipped} skipped (op T), ${unexpected.length} unexpected, ${fixed.length} fixed`);
  assert.deepEqual(unexpected, [], "vectors disagreeing with mcp-auth");
  assert.deepEqual(fixed, [], "vectors now passing; drop them from EXPECTED_FAIL");
});
