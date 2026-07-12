// Ed25519 + JWS primitives for @browserid/agent, matching browserid-core exactly:
// keys are raw 32-byte Ed25519, encoded base64url (no padding); a JWS is
//   base64url(header) + "." + base64url(payload) + "." + base64url(sig)
// where the signature is raw Ed25519 over the UTF-8 bytes of the first two
// segments joined by ".". (browserid-core/src/certificate.rs::encode_and_sign,
// keys.rs — URL_SAFE_NO_PAD, SigningKey::sign over `header.payload`.)
import { createPrivateKey, createPublicKey, sign as nodeSign, verify as nodeVerify, createHash } from "node:crypto";

const ED_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex"); // 32-byte seed follows
const ED_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex"); // 32-byte pubkey follows

export const b64u = (buf) => Buffer.from(buf).toString("base64url");
export const b64uJson = (obj) => b64u(Buffer.from(JSON.stringify(obj)));
export const fromB64u = (s) => new Uint8Array(Buffer.from(s, "base64url"));

/** A keypair backed by node KeyObjects, plus the raw/base64url public key. */
export class KeyPair {
  #priv;
  constructor(privKeyObject, publicRaw) {
    this.#priv = privKeyObject;
    this.publicRaw = publicRaw; // Uint8Array(32)
    this.publicKeyB64 = b64u(publicRaw); // the `x` / publicKey field
  }

  /** From a 32-byte Ed25519 seed (how a credential stores its provisioning key). */
  static fromSeed(seed) {
    const s = Buffer.from(seed);
    if (s.length !== 32) throw new Error("Ed25519 seed must be 32 bytes");
    const priv = createPrivateKey({ key: Buffer.concat([ED_PKCS8_PREFIX, s]), format: "der", type: "pkcs8" });
    const publicRaw = createPublicKey(priv).export({ format: "der", type: "spki" }).subarray(-32);
    const kp = new KeyPair(priv, new Uint8Array(publicRaw));
    kp.seed = new Uint8Array(s); // retained so the key can be persisted + reloaded
    return kp;
  }

  /** A fresh random keypair (agent identity / assertion key). */
  static generate() {
    // Derive a random seed, then reuse fromSeed so `seed` is recoverable for storage.
    const seed = new Uint8Array(32);
    globalThis.crypto.getRandomValues(seed);
    const kp = KeyPair.fromSeed(seed);
    kp.seed = seed;
    return kp;
  }

  /** Raw Ed25519 signature (Uint8Array) over `message` (string or bytes). */
  signRaw(message) {
    const data = typeof message === "string" ? Buffer.from(message, "utf8") : Buffer.from(message);
    return new Uint8Array(nodeSign(null, data, this.#priv));
  }

  /** base64url signature. */
  sign(message) {
    return b64u(this.signRaw(message));
  }

  /** Build a compact JWS: `b64u(header).b64u(payload).b64u(sig)`. */
  jws(header, payload) {
    const signingInput = `${b64uJson(header)}.${b64uJson(payload)}`;
    return `${signingInput}.${this.sign(signingInput)}`;
  }
}

/** A public key for verification, from raw 32 bytes or base64url. */
export class PublicKey {
  #pub;
  constructor(publicKeyObject, publicRaw) {
    this.#pub = publicKeyObject;
    this.publicRaw = publicRaw;
    this.publicKeyB64 = b64u(publicRaw);
  }
  static fromRaw(raw) {
    const r = Buffer.from(raw);
    if (r.length !== 32) throw new Error("Ed25519 public key must be 32 bytes");
    const pub = createPublicKey({ key: Buffer.concat([ED_SPKI_PREFIX, r]), format: "der", type: "spki" });
    return new PublicKey(pub, new Uint8Array(r));
  }
  static fromB64u(s) {
    return PublicKey.fromRaw(fromB64u(s));
  }
  /** Verify a base64url signature over `message`. */
  verify(message, sigB64u) {
    const data = typeof message === "string" ? Buffer.from(message, "utf8") : Buffer.from(message);
    return nodeVerify(null, data, this.#pub, Buffer.from(fromB64u(sigB64u)));
  }
}

/** The browserid-core public-key embedding: {algorithm:"Ed25519", publicKey:"<b64url>"}. */
export const publicKeyField = (publicKeyB64) => ({ algorithm: "Ed25519", publicKey: publicKeyB64 });

/** A short, human-comparable fingerprint of a public key: first 3 bytes of
 *  SHA-256(rawPubkey) as "4F-2A-9C". Deterministic — the broker computes the
 *  same value to show on the pairing page for confirmation. */
export function fingerprint(publicKeyB64) {
  const h = createHash("sha256").update(Buffer.from(fromB64u(publicKeyB64))).digest();
  return [...h.subarray(0, 3)].map((b) => b.toString(16).padStart(2, "0").toUpperCase()).join("-");
}

/** Decode a JWS payload segment (no signature verification). */
export function decodeJwtClaims(token) {
  const parts = token.split(".");
  if (parts.length < 2) throw new Error("not a JWS");
  return JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
}

/** Verify a JWS's signature against a PublicKey (checks `header.payload`). */
export function verifyJws(token, publicKey) {
  const parts = token.split(".");
  if (parts.length !== 3) return false;
  return publicKey.verify(`${parts[0]}.${parts[1]}`, parts[2]);
}
