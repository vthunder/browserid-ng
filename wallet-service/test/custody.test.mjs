import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { EnvKeyWrapper } from "../src/custody.mjs";

test("wrap/unwrap round-trips", () => {
  const w = new EnvKeyWrapper(randomBytes(32));
  const secret = JSON.stringify({ device_key: "seed", agent_device_cert: "jwt" });
  const env = w.wrap(secret);
  assert.doesNotMatch(env, /seed/, "ciphertext must not contain plaintext");
  assert.equal(w.unwrap(env), secret);
});

test("distinct IVs per wrap", () => {
  const w = new EnvKeyWrapper(randomBytes(32));
  assert.notEqual(w.wrap("x"), w.wrap("x"));
});

test("tampered ciphertext fails closed", () => {
  const w = new EnvKeyWrapper(randomBytes(32));
  const env = JSON.parse(w.wrap("secret"));
  const ct = Buffer.from(env.ct, "base64url");
  ct[0] ^= 0xff;
  env.ct = ct.toString("base64url");
  assert.throws(() => w.unwrap(JSON.stringify(env)));
});

test("wrong KEK fails closed", () => {
  const a = new EnvKeyWrapper(randomBytes(32));
  const b = new EnvKeyWrapper(randomBytes(32));
  assert.throws(() => b.unwrap(a.wrap("secret")));
});

test("short KEK is rejected", () => {
  assert.throws(() => new EnvKeyWrapper(randomBytes(16)));
});
