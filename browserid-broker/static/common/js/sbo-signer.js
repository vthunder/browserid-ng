/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * SBO signer popup (device-cert model) — cross-site typed signing.
 *
 * Runs as a TOP-LEVEL broker window (opened by an RP via window.open), so it
 * has first-party broker storage — the same partition as the login dialog,
 * where the user's device + config certs were deposited. A popup is
 * first-party; an embedded iframe would get a partitioned bucket, so this is
 * what makes signing work for a cross-site RP under storage partitioning.
 *
 * No user interaction: the consent was granted once at login (the dialog's
 * SBO-signing screen set `sbo_sign_granted` for the origin). Per sign request
 * the popup: mints a fresh-key ACCESS CERT for the identity (device key →
 * /access/mint), signs the typed SBO envelope with that access key, and hands
 * back the 4-object PRESENTATION (access_cert~assertion~warrant~config_cert) as
 * the write's attribution — exactly what sbo-core's verify_device_attribution
 * consumes (envelope-signer key == access cert key; warrant audience == the
 * write's audience).
 *
 * Protocol (postMessage):
 *   popup → opener : { type: "sbo:signer-ready" }
 *   opener → popup : { type: "sbo:sign", id, email, envelope, audience }
 *   popup → opener : { type: "sbo:signed", id, signature, cert, pubkey }
 *                  | { type: "sbo:sign-error", id, error, message }
 *
 * `cert` is the presentation (the write's `Auth-Cert` value); `pubkey` is the
 * access key in SBO `ed25519:<hex>` form (the write's `Public-Key`).
 */
(function () {
  "use strict";

  var opener = window.opener;
  function log(msg) {
    var el = document.getElementById("status");
    if (el) el.textContent = msg;
  }
  if (!opener) {
    log("error: opened without an opener window");
    return;
  }

  // --- per-origin grant (the same siteInfo map the dialog wrote on consent) ---
  function grantedFor(origin) {
    try {
      var s = JSON.parse(localStorage.getItem("siteInfo") || "{}");
      return !!(s[origin] && s[origin].sbo_sign_granted);
    } catch (e) {
      return false;
    }
  }

  // --- tiny JWS toolkit (Ed25519 via the non-extractable keystore key) -------
  var enc = new TextEncoder();
  function b64urlJson(o) {
    var bytes = enc.encode(JSON.stringify(o));
    var bin = "";
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  var JWS_HDR = b64urlJson({ alg: "EdDSA", typ: "JWT" });
  var nowS = function () { return Math.floor(Date.now() / 1000); };
  function rndHex() {
    var a = new Uint8Array(16);
    crypto.getRandomValues(a);
    var out = "";
    for (var i = 0; i < a.length; i++) out += ("0" + a[i].toString(16)).slice(-2);
    return out;
  }
  function signJws(privateKey, claims) {
    var payload = b64urlJson(claims);
    return window.Keystore.sign(privateKey, JWS_HDR + "." + payload).then(function (sig) {
      return JWS_HDR + "." + payload + "." + sig;
    });
  }
  function decodeJws(jws) {
    try {
      var p = jws.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
      return JSON.parse(atob(p));
    } catch (e) { return null; }
  }
  function jwsExpired(jws, skewS) {
    var c = decodeJws(jws);
    if (!c || !c.exp) return true;
    return nowS() + (skewS || 60) >= c.exp;
  }

  // --- device-cert keystore --------------------------------------------------
  // A stored, unexpired device + config cert pair for `email` (any issuer;
  // there is one pair per issuer, so take the first valid one).
  function devicePairFor(email) {
    return window.Keystore.allDevice().then(function (recs) {
      var byKind = { device: null, config: null };
      var issuer = null;
      recs.forEach(function (r) {
        if (r.email !== String(email).toLowerCase() || !r.privateKey || !r.cert) return;
        if (jwsExpired(r.cert)) return;
        if ((r.kind === "device" || r.kind === "config") && !byKind[r.kind]) {
          byKind[r.kind] = r;
          issuer = r.issuer;
        }
      });
      if (!byKind.device || !byKind.config) return null;
      return { device: byKind.device, config: byKind.config, issuer: issuer };
    });
  }

  // The headless mint URL for `issuer`. Our own domain mints same-origin;
  // a primary IdP's mint is discovered via address_info.
  function mintUrlFor(email, issuer) {
    if (issuer === location.hostname || issuer === location.host) {
      return Promise.resolve("/access/mint");
    }
    return fetch("/wsapi/address_info?email=" + encodeURIComponent(email))
      .then(function (r) { return r.json(); })
      .then(function (info) {
        if (info && info.access_mint) return info.access_mint;
        throw new Error("no mint endpoint for " + issuer);
      });
  }

  // Mint a fresh-key access cert + build the presentation for `audience`.
  // Returns { presentation, accessKey: {privateKey, publicKeyX} }.
  function mintPresentation(email, audience, pair, mintUrl) {
    return window.Keystore.generate().then(function (access) {
      var deviceClaims = decodeJws(pair.device.cert);
      var domain = deviceClaims.iss;
      var areqP = signJws(pair.device.privateKey, {
        typ: "browserid-access-request-v1",
        iat: nowS(), exp: nowS() + 600, jti: rndHex(),
        domain: domain, identity: email, holder: deviceClaims.holder,
        "access-key": { algorithm: "Ed25519", publicKey: access.publicKeyX }
      });
      return areqP.then(function (accessRequest) {
        return fetch(mintUrl, {
          method: "POST",
          headers: { "content-type": "application/json", accept: "application/json" },
          credentials: mintUrl.charAt(0) === "/" ? "include" : "omit",
          body: JSON.stringify({ device_cert: pair.device.cert, access_request: accessRequest })
        });
      }).then(function (r) { return r.json(); }).then(function (minted) {
        if (!minted.access_cert) throw new Error(minted.reason || "mint failed");
        // Warrant (config key): (email, user) → audience, audience-only (the
        // per-origin grant is the consent gate; scope tightening is a later step).
        var warrantP = signJws(pair.config.privateKey, {
          typ: "browserid-warrant-v1",
          iat: nowS(), exp: nowS() + 90 * 86400,
          identifier: email, holder: deviceClaims.holder, audience: audience, scopes: []
        });
        // Assertion (access key): binds the fresh key to `audience`.
        var assertionP = signJws(access.privateKey, { exp: nowS() + 300, aud: audience });
        return Promise.all([warrantP, assertionP]).then(function (parts) {
          var presentation = minted.access_cert + "~" + parts[1] + "~" + parts[0] + "~" + pair.config.cert;
          return { presentation: presentation, accessKey: access };
        });
      });
    });
  }

  // --- sbo-wasm (lazy) -------------------------------------------------------
  var sboPromise = null;
  function loadSbo() {
    if (!sboPromise) {
      sboPromise = import("/common/js/sbo-wasm/sbo_wasm.js").then(function (m) {
        return Promise.resolve(m.default && m.default()).then(function () { return m; });
      });
    }
    return sboPromise;
  }

  function reply(origin, msg) { opener.postMessage(msg, origin); }

  // Persistent session service: stays open and serves many sign requests from
  // its opener. Requests carry an `id` for correlation.
  var signedCount = 0;

  window.addEventListener("message", function (e) {
    if (e.source !== opener) return; // only our opener may drive us
    var d = e.data;
    if (!d || d.type !== "sbo:sign") return;
    var rpOrigin = e.origin; // browser-set, unforgeable; replies target this
    var id = d.id;

    if (!grantedFor(rpOrigin)) {
      reply(rpOrigin, { type: "sbo:sign-error", id: id, error: "not_granted",
        message: "origin " + rpOrigin + " has not been granted SBO signing" });
      return;
    }
    if (!d.audience) {
      reply(rpOrigin, { type: "sbo:sign-error", id: id, error: "bad_request",
        message: "audience is required (the SBO database reference the warrant binds)" });
      return;
    }
    log("signing…");

    devicePairFor(d.email).then(function (pair) {
      if (!pair) throw new Error("no device certs for " + d.email + " — sign in first");
      return mintUrlFor(d.email, pair.issuer).then(function (mintUrl) {
        return mintPresentation(d.email, d.audience, pair, mintUrl);
      });
    }).then(function (res) {
      var identity = {
        email: d.email,
        // The access key in SBO ed25519:<hex> form (the write's Public-Key), and
        // the presentation as the write's Auth-Cert.
        pubkeyHex: SboSign.pubkeyHexFromJwkX(res.accessKey.publicKeyX),
        cert: res.presentation
      };
      return loadSbo().then(function (sbo) {
        // Sign with the non-extractable access CryptoKey (raw bytes never in JS).
        return SboSign.signEnvelope(sbo, d.envelope, identity, res.accessKey.privateKey);
      });
    }).then(function (out) {
      reply(rpOrigin, { type: "sbo:signed", id: id,
        signature: out.signature, cert: out.cert, pubkey: out.pubkey });
      signedCount += 1;
      log("ready — signed " + signedCount); // stay open for reuse
    }).catch(function (err) {
      reply(rpOrigin, { type: "sbo:sign-error", id: id, error: "sign_failed",
        message: (err && err.message) || String(err) });
      log("error: " + ((err && err.message) || String(err)));
    });
  });

  // Announce readiness. We don't yet know the opener's origin, so use "*" — the
  // message carries no secret; the request is validated by its origin + grant.
  log("connecting…");
  opener.postMessage({ type: "sbo:signer-ready" }, "*");
})();
