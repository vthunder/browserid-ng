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

  // Read the stored cert-bound identity (the keypair JWK + Auth-Cert the dialog
  // saved under emails[issuer][email]).
  function identityFor(email, issuer) {
    try {
      var all = JSON.parse(localStorage.getItem("emails") || "{}");
      var ns = all[issuer || "default"] || {};
      return ns[email] || null;
    } catch (e) {
      return null;
    }
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

  window.addEventListener("message", function (e) {
    var d = e.data;
    if (!d || d.type !== "sbo:sign") return;
    var rpOrigin = e.origin; // the requesting RP; replies target this exactly

    if (!grantedFor(rpOrigin)) {
      reply(rpOrigin, { type: "sbo:sign-error", error: "not_granted",
        message: "origin " + rpOrigin + " has not been granted SBO signing" });
      return;
    }
    var rec = identityFor(d.email, d.issuer);
    if (!rec || !rec.priv || !rec.cert) {
      reply(rpOrigin, { type: "sbo:sign-error", error: "no_identity",
        message: "no cert-bound key for " + d.email });
      return;
    }

    log("signing…");
    var identity = {
      email: d.email,
      pubkeyHex: SboSign.pubkeyHexFromJwkX(rec.pub ? rec.pub.x : rec.priv.x),
      cert: rec.cert
    };

    loadSbo().then(function (sbo) {
      return SboSign.signEnvelope(sbo, d.envelope, identity, rec.priv);
    }).then(function (res) {
      reply(rpOrigin, { type: "sbo:signed",
        signature: res.signature, cert: res.cert, pubkey: res.pubkey });
      log("signed ✓");
      setTimeout(function () { try { window.close(); } catch (_) {} }, 250);
    }).catch(function (err) {
      reply(rpOrigin, { type: "sbo:sign-error", error: "sign_failed",
        message: (err && err.message) || String(err) });
      log("error: " + ((err && err.message) || String(err)));
    });
  });

  // Announce readiness. We don't yet know the opener's origin, so use "*" — the
  // message carries no secret; the actual request is validated by its origin and
  // the per-origin grant.
  log("connecting…");
  opener.postMessage({ type: "sbo:signer-ready" }, "*");
})();
