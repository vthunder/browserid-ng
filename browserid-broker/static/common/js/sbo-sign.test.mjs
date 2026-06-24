// End-to-end test of the SBO typed-signing path (browserid-ng Phase 7.4).
//
// Exercises the agent's signing logic the same way the browser will: bind the
// envelope to the identity, build canonical bytes via sbo-wasm, sign with
// WebCrypto Ed25519, then VERIFY the detached signature against the public key
// (Node's crypto.subtle ≈ the browser's). Also checks identity-binding rejects
// an Owner mismatch and that the cert/pubkey round-trip into assembleWire.
//
// Requires a nodejs-target sbo-wasm build; point SBO_WASM_NODE at it, or it
// builds one from the sbo repo via build-web.sh.
//
// Run:  node sbo-sign.test.mjs
import { createRequire } from "node:module";
import { execFileSync } from "node:child_process";
import { mkdtempSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { webcrypto } from "node:crypto";

const require = createRequire(import.meta.url);
const sboSign = require("./sbo-sign.js");
const subtle = webcrypto.subtle;

function assert(cond, msg) {
  if (!cond) throw new Error("FAIL: " + msg);
}

// Locate (or build) a nodejs-target sbo-wasm package.
function loadSboWasmPath() {
  if (process.env.SBO_WASM_NODE && existsSync(process.env.SBO_WASM_NODE)) {
    return process.env.SBO_WASM_NODE;
  }
  const buildScript = join(
    dirname(fileURLToPath(import.meta.url)),
    "..", "..", "..", "..", "..", "sbo", "reference_impl", "sbo-wasm", "build-web.sh"
  );
  if (!existsSync(buildScript)) {
    throw new Error("set SBO_WASM_NODE to a nodejs-target sbo-wasm dir (build-web.sh not found at " + buildScript + ")");
  }
  const out = mkdtempSync(join(tmpdir(), "sbo-wasm-node-"));
  execFileSync(buildScript, ["nodejs", out], { stdio: "inherit" });
  return out;
}

const sbo = await import(join(loadSboWasmPath(), "sbo_wasm.js"));

// 1. A fresh Ed25519 identity, exported to the JWK shape browserid stores.
const kp = await subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
const privJwk = await subtle.exportKey("jwk", kp.privateKey);
const pubJwk = await subtle.exportKey("jwk", kp.publicKey);

const email = "alice@mingo.place";
const identity = {
  email,
  pubkeyHex: sboSign.pubkeyHexFromJwkX(pubJwk.x),
  cert: "FAKE.CERT.JWT" // the agent's Auth-Cert (opaque here)
};

// 2. A caller-built post envelope (sbo-wasm shape).
const payload = sbo.payloadPost("first post via the agent", undefined, undefined);
const spec = {
  action: "",
  path: "/communities/cooks/spaces/general/",
  id: "p1",
  public_key: "ed25519:" + "00".repeat(32), // caller's guess; agent overrides
  content_schema: "post.v1",
  owner: email,
  payload: Array.from(payload),
  hlc: "1703001234567.0"
};

// 3. The agent signs.
const res = await sboSign.signEnvelope(sbo, spec, identity, privJwk);
assert(res.pubkey === identity.pubkeyHex, "agent returns its own pubkey");
assert(res.cert === identity.cert, "agent returns its own cert");
assert(res.bound.public_key === identity.pubkeyHex, "Public-Key overridden to agent key");
assert(res.bound.auth_cert === identity.cert, "Auth-Cert overridden to agent cert");
assert(/^[0-9a-f]{128}$/.test(res.signature), "signature is 64-byte hex");

// 4. The signature verifies over the exact canonical bytes the kit produced.
const signingBytes = sbo.signingBytes(res.bound);
const sigBytes = Uint8Array.from(res.signature.match(/../g).map((h) => parseInt(h, 16)));
const ok = await subtle.verify({ name: "Ed25519" }, kp.publicKey, sigBytes, signingBytes);
assert(ok, "detached signature verifies against the identity public key");

// 5. assembleWire with the returned signature yields a Signature-bearing wire.
const wire = sbo.assembleWire(res.bound, res.signature);
const wireText = new TextDecoder().decode(wire);
assert(wireText.includes("Signature:"), "assembled wire carries the signature");
assert(wireText.startsWith("SBO-Version:"), "wire is a well-formed SBO envelope");

// 6. Identity binding rejects an Owner that is not the signing email.
let rejected = false;
try {
  sboSign.bindEnvelopeToIdentity({ ...spec, owner: "mallory@evil.example" }, identity);
} catch {
  rejected = true;
}
assert(rejected, "binding rejects Owner != signing identity");

console.log("sbo-sign typed signing path: ALL TESTS PASSED");
