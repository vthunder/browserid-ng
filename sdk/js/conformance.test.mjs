// Security audit 2026-11, WS2 — conformance-vector runner for
// @browserid-ng/verify (sdk/js).
//
// The SDK delegates to the hosted /verify service, so this runner replays
// the response the in-process hosted verifier recorded for each vector
// (test-vectors/conformance-2026-11.hosted.json, written by
// browserid-verifier/tests/audit_2026_11_ws2_runner.rs) through an injected
// fetch. What is under test here is the SDK's own contribution: the request
// it builds (presentation and audience must reach the verifier unchanged)
// and the verdict and fields it derives from the response. A request that
// does not carry the vector's audience and bundle verbatim is answered with
// a failure and reported as `request diverged`.
//
// Vectors the SDK gets wrong today are listed in EXPECTED_FAIL with the
// audit id they pin (`AUDIT-2026-11 <id>`); the test fails on any other
// disagreement and also when a listed vector starts agreeing, so removing
// an entry is the acceptance test for the fix. Operation-A vectors are
// skipped: the SDK has no record-validation API.
//
// Report: docs/security-audit-2026-11-ws2-conformance.md.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createVerifier } from "./index.mjs";

const VECTORS = JSON.parse(readFileSync(new URL("../../test-vectors/conformance-2026-11.json", import.meta.url), "utf8"));
const HOSTED = JSON.parse(readFileSync(new URL("../../test-vectors/conformance-2026-11.hosted.json", import.meta.url), "utf8")).responses;

const EXPECTED_FAIL = {
  // AUDIT-2026-11 D7: the hosted response flattens scope entries to strings; the SDK relays them as-is (scopes: string[]).
  "P-OK-07": "D7",
  "P-OK-08": "D7",
  // AUDIT-2026-11 W6-1 (inherited from the hosted verifier): grantor domain compared byte-exact.
  "P-OK-12": "W6-1",
  // AUDIT-2026-11 D16 (inherited): no lower bound on iat.
  "P-TIME-05": "D16",
  "P-TIME-06": "D16",
  "P-TIME-07": "D16",
  "P-TIME-08": "D16",
  "P-TIME-09": "D16",
  // AUDIT-2026-11 S3 (inherited): v1 warrants still verify.
  "P-TYP-01": "S3",
  "P-TYP-02": "S3",
  // AUDIT-2026-11 W6-4 (inherited): cert status.uri host never compared to iss.
  "P-STAT-06": "W6-4",
  // AUDIT-2026-11 S5 (inherited): a satisfied §4.7 constraint verifies although the spec says any constraints claim rejects.
  "P-CONS-01": "S5",
  "P-CONS-06": "S5",
};

/** fetch stub bound to one vector: answers the recorded hosted response only
 *  when the SDK's request carries the vector's bundle and audience verbatim. */
function fetchFor(v, diverged) {
  return async (url, init) => {
    const body = JSON.parse(init.body);
    if (body.presentation !== v.bundle || body.audience !== v.audience) {
      diverged.push(`audience sent ${JSON.stringify(body.audience)}, presentation ${body.presentation === v.bundle ? "intact" : "altered"}`);
      return { ok: true, status: 200, json: async () => ({ status: "failure", reason: "runner: request diverged from the vector" }) };
    }
    return { ok: true, status: 200, json: async () => HOSTED[v.id] };
  };
}

function mismatch(expect, r) {
  const wantAccept = expect.verdict === "accept";
  if (wantAccept && !r.ok) return `expected accept, got reject: ${r.reason}`;
  if (!wantAccept && r.ok) return `expected reject (${expect.reason_class}), got accept as ${r.email}`;
  if (!wantAccept) return null;
  const d = [];
  if (r.email !== expect.email) d.push(`email ${expect.email} != ${r.email}`);
  if (r.grantee !== expect.grantee) d.push(`grantee ${expect.grantee} != ${r.grantee}`);
  try { assert.deepEqual(r.scopes, expect.scopes); } catch { d.push(`scopes ${JSON.stringify(expect.scopes)} != ${JSON.stringify(r.scopes)}`); }
  return d.length ? d.join("; ") : null;
}

test("sdk/js conformance vectors", async () => {
  let pass = 0, xfail = 0, skipped = 0;
  const unexpected = [], fixed = [];
  for (const v of VECTORS.vectors) {
    if (v.op !== "P") { skipped++; continue; }
    const diverged = [];
    const r = await createVerifier({ fetch: fetchFor(v, diverged) }).verify(v.bundle, v.audience);
    let why = mismatch(v.expect, r);
    if (diverged.length) why = `request diverged: ${diverged.join("; ")}${why ? ` → ${why}` : ""}`;
    const fid = EXPECTED_FAIL[v.id];
    if (!why && !fid) { pass++; console.log(`ok    ${v.id.padEnd(10)} ${r.ok ? `accept ${r.email}` : `reject: ${r.reason}`}`); }
    else if (why && fid) { xfail++; console.log(`XFAIL ${v.id.padEnd(10)} [${fid}] ${why}`); }
    else if (why) { console.log(`FAIL  ${v.id.padEnd(10)} ${why}`); unexpected.push(`${v.id}: ${why}`); }
    else { console.log(`FIXED ${v.id.padEnd(10)} [${fid}] now agrees — remove it from EXPECTED_FAIL`); fixed.push(`${v.id} [${fid}]`); }
  }
  console.log(`\nsdk/js: ${pass} pass, ${xfail} expected-fail, ${skipped} skipped (op A/T), ${unexpected.length} unexpected, ${fixed.length} fixed`);
  assert.deepEqual(unexpected, [], "vectors disagreeing with sdk/js");
  assert.deepEqual(fixed, [], "vectors now passing; drop them from EXPECTED_FAIL");
});
