// The agent credential a human downloads from browserid.me/agents — the
// delegation that lets this SDK provision agent identities. Mirrors the Rust
// AgentCredential (browserid-agent/src/lib.rs):
//   { secret_key, delegation: "U_cert~P_cert", broker, idp }
// secret_key is base64url(no-pad) of the provisioning key's 32-byte Ed25519 seed.
// The reserved names/patterns live in the P_cert's `constraint` claim.
import { readFileSync } from "node:fs";
import { KeyPair, fromB64u, decodeJwtClaims } from "./crypto.mjs";
import { NeedCredentialError, InvalidCredentialError } from "./errors.mjs";

const host = (url) =>
  url.replace(/^https?:\/\//, "").split("/")[0];

export class Credential {
  constructor({ secret_key, delegation, broker, idp }) {
    if (!secret_key || !delegation || !broker || !idp) {
      throw new InvalidCredentialError("credential needs secret_key, delegation, broker, idp");
    }
    this.secretKey = secret_key;
    this.delegation = delegation;
    this.broker = broker;
    this.idp = idp;
  }

  /** Load from a file path, or accept an already-parsed object. Throws
   *  NeedCredentialError if the file is missing (so the caller can prompt). */
  static load(pathOrObject) {
    if (pathOrObject instanceof Credential) return pathOrObject;
    if (pathOrObject && typeof pathOrObject === "object") return new Credential(pathOrObject);
    let raw;
    try {
      raw = readFileSync(pathOrObject, "utf8");
    } catch {
      throw new NeedCredentialError(pathOrObject);
    }
    let json;
    try {
      json = JSON.parse(raw);
    } catch {
      throw new InvalidCredentialError(`credential at ${pathOrObject} is not valid JSON`);
    }
    return new Credential(json);
  }

  /** The credential file shape ({secret_key, delegation, broker, idp}) — for
   *  persisting a paired-provisioned credential locally (it was generated here,
   *  never transmitted). */
  toJSON() {
    return { secret_key: this.secretKey, delegation: this.delegation, broker: this.broker, idp: this.idp };
  }

  /** The provisioning key that signs provisioning/warrant requests. */
  provisioningKey() {
    const seed = fromB64u(this.secretKey);
    if (seed.length !== 32) throw new InvalidCredentialError("secret_key is not a 32-byte seed");
    return KeyPair.fromSeed(seed);
  }

  get brokerDomain() {
    return host(this.broker);
  }
  get idpDomain() {
    return host(this.idp);
  }

  /** The P_cert (second segment of the delegation bundle). */
  get provisioningCert() {
    const parts = this.delegation.split("~");
    if (parts.length !== 2) throw new InvalidCredentialError("delegation must be U_cert~P_cert");
    return parts[1];
  }

  /** The names/patterns this credential authorizes (from the P_cert constraint). */
  constraint() {
    const claims = decodeJwtClaims(this.provisioningCert);
    const c = claims.constraint || {};
    return { names: c.names || [], patterns: c.patterns || [] };
  }

  /** The identity this credential provisions as with no explicit name:
   *  - a single reserved name → that name
   *  - a `<prefix>+*` pattern → { generated: true, prefix }
   *  - several names / none  → null (ambiguous; caller must choose)
   *  Mirrors browserid-agent provision(None). */
  defaultIdentity() {
    const { names, patterns } = this.constraint();
    const prefix = patterns.map(patternPrefix).find(Boolean);
    if (prefix) return { name: null, generated: true, prefix, domain: this.idpDomain };
    if (names.length === 1) return { name: names[0], generated: false, domain: this.idpDomain };
    return null;
  }
}

/** `<prefix>+*` → `<prefix>`; otherwise null. (Matches Constraint::pattern_prefix.) */
export function patternPrefix(pattern) {
  const m = /^(.+)\+\*$/.exec(pattern);
  return m ? m[1] : null;
}
