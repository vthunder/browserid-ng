/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * SBO signer popup (browserid-ng Phase 7.4) — cross-site typed signing.
 *
 * Runs as a TOP-LEVEL broker window (opened by an RP via window.open), so it
 * has first-party broker storage — the same partition as the login dialog
 * popup, where the cert-bound key, cert, and per-origin grant were stored. This
 * is what makes signing work for a cross-site RP under storage partitioning: an
 * embedded iframe gets a partitioned bucket, but a popup is first-party.
 *
 * No user interaction: the consent was granted once at login. The popup reads
 * the grant for the opener's origin, signs the typed envelope with the stored
 * key (via sbo-sign.js + sbo-wasm), posts the result back to the opener, and
 * closes. The opening window.open() must occur during a user gesture (the RP's
 * Post/Vote click), which it naturally does.
 *
 * Protocol (postMessage):
 *   popup → opener : { type: "sbo:signer-ready" }
 *   opener → popup : { type: "sbo:sign", email, envelope, issuer? }
 *   popup → opener : { type: "sbo:signed", signature, cert, pubkey }
 *                  | { type: "sbo:sign-error", error, message }
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

  // Read the per-origin grant from broker first-party storage (the same
  // siteInfo map the login dialog wrote on consent).
  function grantedFor(origin) {
    try {
      var s = JSON.parse(localStorage.getItem("siteInfo") || "{}");
      return !!(s[origin] && s[origin].sbo_sign_granted);
    } catch (e) {
      return false;
    }
  }

  // Read the stored cert-bound identity from the non-extractable keystore (e2fi)
  // — the dialog saved a { publicKeyX, privateKey (CryptoKey), cert } record in
  // IndexedDB, shared first-party with this popup. Returns a Promise of the
  // matching record (issuer-filtered when the request names one), or null.
  function identityFor(email, issuer) {
    if (!window.Keystore) return Promise.resolve(null);
    return window.Keystore.forEmail(email).then(function (recs) {
      for (var i = 0; i < recs.length; i++) {
        var r = recs[i];
        if (!r.privateKey || !r.cert) continue;
        if (issuer && r.issuer !== issuer) continue;
        return r;
      }
      return null;
    });
  }

  var sboPromise = null;
  function loadSbo() {
    if (!sboPromise) {
      sboPromise = import("/common/js/sbo-wasm/sbo_wasm.js").then(function (m) {
        return Promise.resolve(m.default && m.default()).then(function () {
          return m;
        });
      });
    }
    return sboPromise;
  }

  function reply(origin, msg) {
    opener.postMessage(msg, origin);
  }

  // The signer is a PERSISTENT session service: it stays open and serves many
  // sign requests from its opener (no per-write popup). The opener holds the
  // window and reuses it; only the first open needs a user gesture. Requests
  // carry an `id` so the opener can correlate concurrent replies.
  var signedCount = 0;

  window.addEventListener("message", function (e) {
    // Only the window that opened this popup may drive it (defense in depth;
    // the substantive gate is the per-origin grant below).
    if (e.source !== opener) return;
    var d = e.data;
    if (!d || d.type !== "sbo:sign") return;
    var rpOrigin = e.origin; // browser-set, unforgeable; replies target this
    var id = d.id;           // opaque correlation id chosen by the opener

    if (!grantedFor(rpOrigin)) {
      reply(rpOrigin, { type: "sbo:sign-error", id: id, error: "not_granted",
        message: "origin " + rpOrigin + " has not been granted SBO signing" });
      return;
    }
    log("signing…");
    identityFor(d.email, d.issuer).then(function (rec) {
      if (!rec) {
        reply(rpOrigin, { type: "sbo:sign-error", id: id, error: "no_identity",
          message: "no cert-bound key for " + d.email });
        return;
      }
      var identity = {
        email: d.email,
        pubkeyHex: SboSign.pubkeyHexFromJwkX(rec.publicKeyX),
        cert: rec.cert
      };
      return loadSbo().then(function (sbo) {
        // Sign with the non-extractable CryptoKey handle (e2fi) — raw key bytes
        // never enter JS.
        return SboSign.signEnvelope(sbo, d.envelope, identity, rec.privateKey);
      }).then(function (res) {
        reply(rpOrigin, { type: "sbo:signed", id: id,
          signature: res.signature, cert: res.cert, pubkey: res.pubkey });
        signedCount += 1;
        log("ready — signed " + signedCount); // stay open for reuse
      });
    }).catch(function (err) {
      reply(rpOrigin, { type: "sbo:sign-error", id: id, error: "sign_failed",
        message: (err && err.message) || String(err) });
      log("error: " + ((err && err.message) || String(err)));
    });
  });

  // If this popup is somehow the first page to touch storage this session,
  // carry any legacy localStorage keys into the keystore before serving.
  if (window.Keystore && window.Keystore.migrateFromLocalStorage) {
    try { window.Keystore.migrateFromLocalStorage(); } catch (e) {}
  }

  // Announce readiness. We don't yet know the opener's origin, so use "*" — the
  // message carries no secret; the actual request is validated by its origin and
  // the per-origin grant.
  log("connecting…");
  opener.postMessage({ type: "sbo:signer-ready" }, "*");
})();
