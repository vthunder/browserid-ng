// Key custody (design doc §8): tenant credentials are envelope-encrypted at
// rest. The KeyWrapper interface is the seam — the env-KEK implementation here
// can be swapped for a cloud KMS without touching the store.
//
// Nothing outside store.mjs ever sees plaintext credential material, and
// nothing here persists it: wrap/unwrap are pure transforms.
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

/**
 * AES-256-GCM under a key held in the environment (or a dev file). Each wrap
 * uses a fresh IV; the auth tag rides along, so tampered ciphertext fails
 * closed on unwrap.
 */
export class EnvKeyWrapper {
  #kek;

  /** @param {Buffer} kek 32-byte key-encryption key */
  constructor(kek) {
    if (!Buffer.isBuffer(kek) || kek.length < 32) throw new Error("KEK must be >= 32 bytes");
    this.#kek = kek.subarray(0, 32);
  }

  /** @param {string} plaintext @returns {string} compact JSON envelope */
  wrap(plaintext) {
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.#kek, iv);
    const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
    return JSON.stringify({
      v: 1,
      alg: "A256GCM",
      iv: iv.toString("base64url"),
      ct: ct.toString("base64url"),
      tag: cipher.getAuthTag().toString("base64url"),
    });
  }

  /** @param {string} envelope @returns {string} plaintext */
  unwrap(envelope) {
    const { v, alg, iv, ct, tag } = JSON.parse(envelope);
    if (v !== 1 || alg !== "A256GCM") throw new Error(`unknown envelope (v=${v}, alg=${alg})`);
    const decipher = createDecipheriv("aes-256-gcm", this.#kek, Buffer.from(iv, "base64url"));
    decipher.setAuthTag(Buffer.from(tag, "base64url"));
    return Buffer.concat([
      decipher.update(Buffer.from(ct, "base64url")),
      decipher.final(),
    ]).toString("utf8");
  }
}
