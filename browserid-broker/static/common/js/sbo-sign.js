/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Typed signing extension — SBO envelopes (browserid-ng Phase 7.4).
 *
 * The agent already holds a cert-bound Ed25519 key for an email identity. This
 * module lets it sign a *typed, parsed-and-bound* SBO envelope with that key —
 * a second domain-separated capability alongside assertions. It NEVER signs
 * opaque caller bytes:
 *
 *   1. The agent takes the structured envelope spec (not raw bytes) and
 *      **rebuilds the canonical signing bytes itself via sbo-wasm** — the single
 *      source of truth for SBO's signing-byte layout. So it provably signs only
 *      well-formed SBO content (validation "recompute" step, strongest form).
 *   2. It **binds to its own identity**: the envelope `Owner` MUST equal the
 *      signing email, and `Public-Key`/`Auth-Cert` are overridden with the
 *      agent's own key + cert (a caller cannot get a write signed as a different
 *      owner or under a different key).
 *   3. Domain separation is by construction: SBO canonical content begins with
 *      the `SBO-Version:` header block, never a valid JWS assertion preimage.
 *
 * The caller MUST use the returned `pubkey`/`cert` when assembling the wire, so
 * its envelope matches exactly what was signed.
 *
 * Pure helpers (binding + encoding) are exported for Node tests; `signEnvelope`
 * uses WebCrypto (present in browsers and Node ≥ 20).
 */
(function(root, factory) {
  var api = factory();
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api; // Node (tests)
  }
  if (root) {
    if (root.BrowserID) root.BrowserID.SboSign = api; // full agent (comm iframe)
    root.SboSign = api; // global fallback (the minimal signer popup)
  }
})(typeof self !== "undefined" ? self : this, function() {
  "use strict";

  function bytesToHex(bytes) {
    var out = "";
    for (var i = 0; i < bytes.length; i++) {
      out += (bytes[i] >>> 4).toString(16) + (bytes[i] & 0xf).toString(16);
    }
    return out;
  }

  // Decode unpadded base64url (the JWK `x`/`d` encoding) to a Uint8Array.
  function base64urlToBytes(b64u) {
    var b64 = b64u.replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4) b64 += "=";
    var bin = (typeof atob === "function")
      ? atob(b64)
      : Buffer.from(b64, "base64").toString("binary");
    var bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }

  // The SBO `Public-Key` header form from a JWK `x` (base64url, 32 bytes).
  function pubkeyHexFromJwkX(x) {
    var bytes = base64urlToBytes(x);
    if (bytes.length !== 32) throw new Error("Ed25519 public key must be 32 bytes");
    return "ed25519:" + bytesToHex(bytes);
  }

  /**
   * Validate + bind an envelope spec to the signing identity. Throws if the
   * envelope's Owner does not match the identity's email. Returns a *new* spec
   * with `public_key` and `auth_cert` set to the agent's own — the only fields
   * the agent is authoritative for.
   *
   * @param {object} spec      caller-built EnvelopeSpec (sbo-wasm shape)
   * @param {object} identity  { email, pubkeyHex, cert }
   */
  function bindEnvelopeToIdentity(spec, identity) {
    if (!spec || typeof spec !== "object") throw new Error("envelope spec required");
    if (!identity || !identity.email) throw new Error("signing identity required");
    if (!spec.owner) throw new Error("envelope Owner is required for a typed identity write");
    if (spec.owner !== identity.email) {
      throw new Error(
        "envelope Owner (" + spec.owner + ") must equal the signing identity (" + identity.email + ")"
      );
    }
    var bound = {};
    for (var k in spec) if (Object.prototype.hasOwnProperty.call(spec, k)) bound[k] = spec[k];
    bound.public_key = identity.pubkeyHex;
    bound.auth_cert = identity.cert;
    return bound;
  }

  /**
   * Sign a typed SBO envelope. Rebuilds canonical bytes via `sbo` (the loaded
   * sbo-wasm module), signs them with the identity's private key, and returns
   * the detached signature (hex) plus the cert + pubkey the caller must assemble
   * with.
   *
   * @param {object} sbo        loaded sbo-wasm module (signingBytes/...)
   * @param {object} spec       caller-built EnvelopeSpec
   * @param {object} identity   { email, pubkeyHex, cert }
   * @param {CryptoKey|object} priv  a non-extractable Ed25519 private CryptoKey
   *                            handle (e2fi, preferred) OR a legacy { d, x } JWK
   * @param {Crypto} [subtle]   crypto.subtle (defaults to global)
   * @returns {Promise<{signature:string, cert:string, pubkey:string, bound:object}>}
   */
  async function signEnvelope(sbo, spec, identity, priv, subtle) {
    subtle = subtle || (typeof crypto !== "undefined" && crypto.subtle);
    if (!subtle) throw new Error("WebCrypto subtle unavailable");

    var bound = bindEnvelopeToIdentity(spec, identity);
    var signingBytes = sbo.signingBytes(bound); // Uint8Array of canonical content

    // Preferred path: a non-extractable CryptoKey handle from the keystore —
    // the raw private bytes never enter JS. Legacy path: import a JWK (also
    // non-extractable, but the bytes were in the caller's hands).
    var key;
    if (priv && priv.type === "private" && priv.algorithm) {
      key = priv;
    } else {
      key = await subtle.importKey(
        "jwk",
        { kty: "OKP", crv: "Ed25519", d: priv.d, x: priv.x },
        { name: "Ed25519" },
        false, // non-extractable: imported only to sign, never re-exported
        ["sign"]
      );
    }
    var sig = await subtle.sign({ name: "Ed25519" }, key, signingBytes);

    return {
      signature: bytesToHex(new Uint8Array(sig)),
      cert: identity.cert,
      pubkey: identity.pubkeyHex,
      bound: bound
    };
  }

  return {
    bytesToHex: bytesToHex,
    base64urlToBytes: base64urlToBytes,
    pubkeyHexFromJwkX: pubkeyHexFromJwkX,
    bindEnvelopeToIdentity: bindEnvelopeToIdentity,
    signEnvelope: signEnvelope
  };
});
