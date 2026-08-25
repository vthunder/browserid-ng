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

  // --- signing-grant records (spec §5) ---------------------------------------
  // The dialog's consent ceremony stores one record per (origin, audience) in
  // siteInfo[origin].signing_grants — the same first-party map it always
  // owned. This popup only READS records; it can author nothing.
  function storedGrants(origin) {
    try {
      var s = JSON.parse(localStorage.getItem("siteInfo") || "{}");
      return (s[origin] && s[origin].signing_grants) || {};
    } catch (e) {
      return {};
    }
  }

  // `*` covers all; `<ns>.*` covers the namespace; else exact.
  function matcherCovers(matcher, holder) {
    if (!matcher || !holder) return false;
    if (matcher === "*") return true;
    if (matcher.slice(-2) === ".*") return holder.indexOf(matcher.slice(0, -1)) === 0;
    return matcher === holder;
  }

  function scopeName(entry) {
    return typeof entry === "string" ? entry : (entry && entry.scope);
  }
  function scopeMode(entry) {
    return (entry && typeof entry === "object" && entry.mode) || "auto";
  }

  // Find the stored record covering (origin, email, audience, action) and
  // evaluate its channel set + scope. Returns { jws, claims, mode } or
  // { error, message } — never signs outside a covering record.
  function coveringRecord(origin, email, audience, action, deviceHolder) {
    var jws = storedGrants(origin)[audience];
    var refuse = function (error, message) { return { error: error, message: message }; };
    if (!jws) {
      return refuse("not_granted", "no signing grant for " + origin + " → " + audience);
    }
    var c = decodeJws(jws);
    if (!c || c.typ !== "browserid-warrant-v2") {
      return refuse("not_granted", "stored record is malformed");
    }
    if (jwsExpired(jws)) {
      return refuse("not_granted", "signing grant expired — sign in again to renew");
    }
    if (c.grantee !== String(email).toLowerCase() && c.grantee !== email) {
      return refuse("not_granted", "signing grant covers a different identity");
    }
    if (c.audience !== audience) {
      return refuse("not_granted", "signing grant covers a different audience");
    }
    // Channel set: conjunctive; this wallet honors exactly {holder, requester}.
    var entries = Array.isArray(c.binding) ? c.binding : (c.binding ? [c.binding] : []);
    var sawRequester = false, sawHolder = false;
    for (var i = 0; i < entries.length; i++) {
      var e = entries[i];
      if (!e || typeof e !== "object") return refuse("not_granted", "malformed channel entry");
      if (e.kind === "requester") {
        sawRequester = true;
        if (e.origin !== origin) {
          return refuse("not_granted", "signing grant names a different requesting site");
        }
      } else if (e.kind === "holder") {
        sawHolder = true;
        if (!matcherCovers(e.matcher, deviceHolder)) {
          return refuse("not_granted", "signing grant covers a different device");
        }
      } else {
        // Unknown kind ⇒ reject (spec §6.6 invariant 14) — fail closed.
        return refuse("not_granted", "signing grant carries an unknown channel kind");
      }
    }
    if (!sawRequester || !sawHolder) {
      return refuse("not_granted", "stored record is not a signing grant");
    }
    // Scope: the envelope's action must be granted; parameters attenuate.
    var want = "sign:sbo:" + action;
    var entry = null;
    for (var j = 0; j < (c.scopes || []).length; j++) {
      if (scopeName(c.scopes[j]) === want) { entry = c.scopes[j]; break; }
    }
    if (!entry) {
      return refuse("scope_not_granted", "'" + want + "' is not in this site's grant");
    }
    var mode = scopeMode(entry);
    if (mode !== "auto" && mode !== "prompt") {
      // Unknown parameter value ⇒ refuse (invariant 14 / scope rule 2).
      return refuse("scope_not_granted", "grant carries an unimplemented scope parameter");
    }
    return { jws: jws, claims: c, mode: mode };
  }

  // --- prompt mode (spec §5 `mode: "prompt"`) --------------------------------
  var promptBusy = Promise.resolve();
  function promptApproval(action, envelope) {
    // Serialize prompts; each renders the object to be signed and resolves
    // true (approve) / false (decline).
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
        var summary = { action: action, path: envelope && envelope.path, id: envelope && envelope.id };
        if (envelope && envelope.payload != null) {
          var body = String(envelope.payload);
          summary.payload = body.length > 400 ? body.slice(0, 400) + "…" : body;
        }
        detail.textContent = JSON.stringify(summary, null, 2);
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

  // Mint a fresh-key access cert and assemble the presentation: the STORED
  // warrant (never a fabricated one — invariant 11), a fresh assertion with
  // the requesting origin stamped in (`req_origin`, invariant 13).
  // Returns { presentation, accessKey: {privateKey, publicKeyX} }.
  function mintPresentation(email, audience, pair, mintUrl, warrantJws, reqOrigin) {
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
        // Assertion (access key): binds the fresh key to `audience` and stamps
        // the authenticated requesting channel for downstream verifiers.
        var assertionP = signJws(access.privateKey, {
          exp: nowS() + 300, aud: audience, req_origin: reqOrigin
        });
        return assertionP.then(function (assertion) {
          var presentation = minted.access_cert + "~" + assertion + "~" + warrantJws + "~" + pair.config.cert;
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

  function handleSign(rpOrigin, d) {
    var id = d.id;
    if (!d.audience) {
      reply(rpOrigin, { type: "sbo:sign-error", id: id, error: "bad_request",
        message: "audience is required (the SBO database reference the grant binds)" });
      return;
    }
    // Classify the object to be signed: the payload discipline is a TYPED SBO
    // envelope whose action selects the sign:sbo:<action> scope (an absent
    // action is the SBO content spec's default, `post`). An envelope we
    // cannot classify is refused (invariant 9).
    var action = "post";
    if (d.envelope && d.envelope.action != null && d.envelope.action !== "") {
      action = d.envelope.action;
    }
    if (typeof action !== "string" || !/^[a-z][a-z0-9_-]{0,31}$/.test(action)) {
      reply(rpOrigin, { type: "sbo:sign-error", id: id, error: "bad_request",
        message: "envelope carries no classifiable action" });
      return;
    }
    log("checking grant…");

    devicePairFor(d.email).then(function (pair) {
      if (!pair) throw { error: "not_granted",
        message: "no device certs for " + d.email + " — sign in first" };
      var deviceHolder = (decodeJws(pair.device.cert) || {}).holder;
      var rec = coveringRecord(rpOrigin, d.email, d.audience, action, deviceHolder);
      if (rec.error) throw rec;
      var gate = rec.mode === "prompt"
        ? promptApproval(action, d.envelope).then(function (approved) {
            if (!approved) throw { error: "prompt_declined",
              message: "the user declined this " + action };
          })
        : Promise.resolve();
      return gate.then(function () {
        log("signing…");
        return mintUrlFor(d.email, pair.issuer).then(function (mintUrl) {
          return mintPresentation(d.email, d.audience, pair, mintUrl, rec.jws, rpOrigin);
        });
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
    var records = storedGrants(rpOrigin);
    Object.keys(records).forEach(function (aud) {
      if (d.audience && d.audience !== aud) return;
      var c = decodeJws(records[aud]);
      if (!c || jwsExpired(records[aud])) return;
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
