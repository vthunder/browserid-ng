/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * SBO signer popup (device-cert model) — the user's WALLET for cross-site
 * typed signing.
 *
 * Runs as a TOP-LEVEL broker window (opened by an RP via window.open), so it
 * has first-party broker storage — the same partition as the login dialog,
 * where the user's device + config certs AND signing-grant records were
 * deposited. A popup is first-party; an embedded iframe would get a
 * partitioned bucket, so this is what makes signing work for a cross-site RP
 * under storage partitioning.
 *
 * Enforcement point (spec §6.6 invariant 9): every incoming request must be
 * covered by a STORED signing-grant record — a browserid-warrant-v2
 * self-grant whose binding set is {holder: this device, requester: the
 * asking origin}, with a sign:sbo:<action> scope matching the envelope. The
 * requester entry is checked against the browser-verified event.origin,
 * which page JS cannot forge, and the same origin is stamped into the fresh
 * assertion (`req_origin`) so verifiers re-check it downstream (invariant
 * 13). This popup NEVER authors a warrant (invariant 11 — the pre-M9
 * fabrication is gone); it only exercises records the dialog's consent
 * ceremony minted. Prompt-mode scopes render the envelope in this window and
 * wait for the user's approval before signing.
 *
 * Protocol (postMessage):
 *   popup → opener : { type: "sbo:signer-ready" }
 *   opener → popup : { type: "sbo:sign", id, email, envelope, audience }
 *   popup → opener : { type: "sbo:signed", id, signature, cert, pubkey }
 *                  | { type: "sbo:sign-error", id, error, message }
 *                    error ∈ { not_granted, scope_not_granted,
 *                              prompt_declined, bad_request, sign_failed }
 *   opener → popup : { type: "sbo:grant-info", id [, audience] }
 *   popup → opener : { type: "sbo:grant-info", id, grants: [
 *                        { email, audience, scopes, exp } ] }
 *                    (the asking origin's grants only; others get [])
 *
 * `cert` is the presentation (the write's `Auth-Cert` value); `pubkey` is the
 * access key in SBO `ed25519:<hex>` form (the write's `Public-Key`).
 *
 * All enforcement and signing lives in /common/js/wallet-signer.js (the one
 * signer shared with the dialog's `signature` request kind); this file is
 * the postMessage transport plus the in-window prompt.
 */
(function () {
  "use strict";

  var W = window.WalletSigner;
  var opener = window.opener;
  function log(msg) {
    var el = document.getElementById("status");
    if (el) el.textContent = msg;
  }
  if (!opener) {
    log("error: opened without an opener window");
    return;
  }

  // --- prompt mode (spec §5 `mode: "prompt"`) --------------------------------
  var promptBusy = Promise.resolve();
  function promptApproval(action, envelope) {
    var run = function () {
      return new Promise(function (resolve) {
        var box = document.getElementById("prompt");
        var spinner = document.getElementById("spinner");
        var title = document.getElementById("prompt-title");
        var detail = document.getElementById("prompt-detail");
        var ok = document.getElementById("prompt-approve");
        var no = document.getElementById("prompt-decline");
        if (!box || !ok || !no) return resolve(false); // no surface ⇒ refuse
        title.textContent = "Approve this " + action + "?";
        detail.textContent = JSON.stringify(W.objectSummary(action, envelope), null, 2);
        box.className = "active";
        if (spinner) spinner.style.display = "none";
        log("waiting for your approval…");
        var done = function (v) {
          box.className = "";
          if (spinner) spinner.style.display = "";
          ok.onclick = no.onclick = null;
          resolve(v);
        };
        ok.onclick = function () { done(true); };
        no.onclick = function () { done(false); };
        try { window.focus(); } catch (e) { /* best-effort */ }
      });
    };
    var p = promptBusy.then(run);
    promptBusy = p.then(function () { }, function () { });
    return p;
  }

  function reply(origin, msg) { opener.postMessage(msg, origin); }

  // --- request handling ------------------------------------------------------
  var signedCount = 0;

  function handleSign(rpOrigin, d) {
    var id = d.id;
    log("checking grant…");
    W.signObject({
      origin: rpOrigin, email: d.email, audience: d.audience, envelope: d.envelope,
      prompt: function (action, envelope) { log("signing…"); return promptApproval(action, envelope); }
    }).then(function (out) {
      reply(rpOrigin, { type: "sbo:signed", id: id,
        signature: out.signature, cert: out.cert, pubkey: out.pubkey });
      signedCount += 1;
      log("ready — signed " + signedCount); // stay open for reuse
    }).catch(function (err) {
      var code = (err && err.error) || "sign_failed";
      var message = (err && err.message) || String(err);
      reply(rpOrigin, { type: "sbo:sign-error", id: id, error: code, message: message });
      log(code === "sign_failed" ? "error: " + message : "ready — " + code);
    });
  }

  // Grant introspection: the asking origin's own grants only — every other
  // origin gets a uniform empty reply (no oracle).
  function handleGrantInfo(rpOrigin, d) {
    var grants = [];
    var records = W.storedGrants(rpOrigin);
    Object.keys(records).forEach(function (aud) {
      if (d.audience && d.audience !== aud) return;
      var c = W.decodeJws(records[aud]);
      if (!c || W.jwsExpired(records[aud])) return;
      grants.push({ email: c.grantee, audience: c.audience, scopes: c.scopes, exp: c.exp });
    });
    reply(rpOrigin, { type: "sbo:grant-info", id: d.id, grants: grants });
  }

  window.addEventListener("message", function (e) {
    if (e.source !== opener) return; // only our opener may drive us
    var d = e.data;
    if (!d) return;
    // e.origin is browser-set and unforgeable — the authenticated requesting
    // channel the grant's requester entry is checked against.
    if (d.type === "sbo:sign") handleSign(e.origin, d);
    else if (d.type === "sbo:grant-info") handleGrantInfo(e.origin, d);
  });

  // Announce readiness. We don't yet know the opener's origin, so use "*" — the
  // message carries no secret; each request is validated by its origin + grant.
  log("connecting…");
  opener.postMessage({ type: "sbo:signer-ready" }, "*");
})();
