// Wallet signer — the ONE signing interface of the web wallet (spec §7.3
// "one signer", request-kinds side spec). Loaded by the dialog (request
// kinds `warrant` and `signature`) and by the legacy signer popup
// (/sign, `sbo:sign` messages), so both surfaces enforce the same rules:
//
//   * a signature happens only under a STORED signing-grant record whose
//     channel set covers (requesting origin, this device) — spec §6.6
//     invariant 9 — and only while the record is unrevoked;
//   * the requesting origin is always the browser-verified one the caller
//     passes in (never a declared value);
//   * a record is authored only by a consent card, with a registrar status
//     ref (no ref ⇒ no record).
//
// Records live in localStorage `siteInfo[origin].signing_grants` (audience →
// JWS), the first-party map the dialog has always owned.
(function () {
  "use strict";

  // --- JWS toolkit (Ed25519 via the non-extractable keystore key) ---------
  var enc = new TextEncoder();
  function b64urlJson(o) {
    var bytes = enc.encode(JSON.stringify(o));
    var bin = "";
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  var JWS_HDR = b64urlJson({ alg: "EdDSA", typ: "JWT" });
  function nowS() { return Math.floor(Date.now() / 1000); }
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
      var p = String(jws).split(".")[1];
      var s = atob(p.replace(/-/g, "+").replace(/_/g, "/"));
      var bytes = new Uint8Array(s.length);
      for (var i = 0; i < s.length; i++) bytes[i] = s.charCodeAt(i);
      return JSON.parse(new TextDecoder().decode(bytes));
    } catch (e) {
      return null;
    }
  }
  function jwsExpired(jws, skewS) {
    var c = decodeJws(jws);
    if (!c || !c.exp) return true;
    return nowS() + (skewS || 60) >= c.exp;
  }

  // --- stored signing-grant records ----------------------------------------
  function readSiteInfo() {
    try { return JSON.parse(localStorage.getItem("siteInfo") || "{}"); } catch (e) { return {}; }
  }
  function storedGrants(origin) {
    var s = readSiteInfo();
    return (s[origin] && s[origin].signing_grants) || {};
  }
  function storeGrant(origin, audience, jws) {
    var si = readSiteInfo();
    si[origin] = si[origin] || {};
    si[origin].signing_grants = si[origin].signing_grants || {};
    si[origin].signing_grants[audience] = jws;
    localStorage.setItem("siteInfo", JSON.stringify(si));
  }
  function dropGrant(origin, audience) {
    try {
      var si = readSiteInfo();
      if (si[origin] && si[origin].signing_grants) {
        delete si[origin].signing_grants[audience];
        localStorage.setItem("siteInfo", JSON.stringify(si));
      }
    } catch (e) { /* best-effort */ }
  }

  // The claims of a self-grant signing record (spec §5 "Signing grants"):
  // grantor == grantee, channel set {holder: this device, requester: the
  // verified origin}, one exact audience, a registrar status ref.
  function warrantV2Claims(p) {
    return {
      typ: "browserid-warrant-v2",
      iat: nowS(),
      exp: nowS() + 90 * 86400,
      grantor: p.email,
      grantee: p.email,
      binding: [
        { kind: "holder", matcher: p.holder },
        { kind: "requester", origin: p.origin }
      ],
      audience: p.audience,
      scopes: p.scopes,
      status: { uri: p.status.uri, idx: p.status.idx }
    };
  }

  // The record's live revocation state, from this broker's own list
  // (same-origin, authoritative). "valid" | "revoked" | "unavailable".
  function checkGrantStatus(claims) {
    if (!claims.status || !claims.status.uri) return Promise.resolve("unavailable");
    return fetch("/status/check", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ refs: [{ uri: claims.status.uri, idx: claims.status.idx }] })
    }).then(function (r) { return r.json(); }).then(function (j) {
      if (j && j.revoked) return "revoked";
      if (j && j.ok) return "valid";
      return "unavailable";
    }).catch(function () { return "unavailable"; });
  }

  function matcherCovers(matcher, holder) {
    if (!matcher || !holder) return false;
    if (matcher === "*") return true;
    if (matcher.slice(-2) === ".*") return holder.indexOf(matcher.slice(0, -1)) === 0;
    return matcher === holder;
  }
  function scopeName(entry) { return typeof entry === "string" ? entry : (entry && entry.scope); }
  function scopeMode(entry) { return (entry && typeof entry === "object" && entry.mode) || "auto"; }

  // The stored record covering (origin, email, audience, action) with its
  // channel set and scope evaluated. { jws, claims, mode } or
  // { error, message } — never signs outside a covering record.
  function coveringRecord(origin, email, audience, action, deviceHolder) {
    var jws = storedGrants(origin)[audience];
    var refuse = function (error, message) { return { error: error, message: message }; };
    if (!jws) return refuse("not_granted", "no signing grant for " + origin + " → " + audience);
    var c = decodeJws(jws);
    if (!c || c.typ !== "browserid-warrant-v2") return refuse("not_granted", "stored record is malformed");
    if (jwsExpired(jws)) return refuse("not_granted", "signing grant expired — sign in again to renew");
    if (c.grantee !== String(email).toLowerCase() && c.grantee !== email) {
      return refuse("not_granted", "signing grant covers a different identity");
    }
    if (c.audience !== audience) return refuse("not_granted", "signing grant covers a different audience");
    var entries = Array.isArray(c.binding) ? c.binding : (c.binding ? [c.binding] : []);
    var sawRequester = false, sawHolder = false;
    for (var i = 0; i < entries.length; i++) {
      var e = entries[i];
      if (!e || typeof e !== "object") return refuse("not_granted", "malformed channel entry");
      if (e.kind === "requester") {
        sawRequester = true;
        if (e.origin !== origin) return refuse("not_granted", "signing grant names a different requesting site");
      } else if (e.kind === "holder") {
        sawHolder = true;
        if (!matcherCovers(e.matcher, deviceHolder)) return refuse("not_granted", "signing grant covers a different device");
      } else {
        return refuse("not_granted", "signing grant carries an unknown channel kind"); // invariant 14
      }
    }
    if (!sawRequester || !sawHolder) return refuse("not_granted", "stored record is not a signing grant");
    var want = "sign:sbo:" + action;
    var entry = null;
    for (var j = 0; j < (c.scopes || []).length; j++) {
      if (scopeName(c.scopes[j]) === want) { entry = c.scopes[j]; break; }
    }
    if (!entry) return refuse("scope_not_granted", "'" + want + "' is not in this site's grant");
    var mode = scopeMode(entry);
    if (mode !== "auto" && mode !== "prompt") {
      return refuse("scope_not_granted", "grant carries an unimplemented scope parameter");
    }
    return { jws: jws, claims: c, mode: mode };
  }

  // The typed SBO envelope's action selects the sign:sbo:<action> scope; an
  // envelope we cannot classify is refused (invariant 9). Returns the action
  // or { error, message }.
  function classifyAction(envelope) {
    var action = "post";
    if (envelope && envelope.action != null && envelope.action !== "") action = envelope.action;
    if (typeof action !== "string" || !/^[a-z][a-z0-9_-]{0,31}$/.test(action)) {
      return { error: "bad_request", message: "envelope carries no classifiable action" };
    }
    return action;
  }

  // --- device-cert keystore -------------------------------------------------
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

  function mintUrlFor(email, issuer) {
    if (issuer === location.hostname || issuer === location.host) return Promise.resolve("/access/mint");
    return fetch("/wsapi/address_info?email=" + encodeURIComponent(email))
      .then(function (r) { return r.json(); })
      .then(function (info) {
        if (info && info.access_mint) return info.access_mint;
        throw new Error("no mint endpoint for " + issuer);
      });
  }

  // Fresh-key access cert + assertion stamping the requesting origin
  // (`req_origin`, invariant 13), around the STORED warrant (invariant 11).
  // Returns { presentation, accessKey: {privateKey, publicKeyX} }.
  function mintPresentation(email, audience, pair, mintUrl, warrantJws, reqOrigin) {
    return window.Keystore.generate().then(function (access) {
      var deviceClaims = decodeJws(pair.device.cert);
      var domain = deviceClaims.iss;
      return signJws(pair.device.privateKey, {
        typ: "browserid-access-request-v1",
        iat: nowS(), exp: nowS() + 600, jti: rndHex(),
        domain: domain, identity: email, holder: deviceClaims.holder,
        "access-key": { algorithm: "Ed25519", publicKey: access.publicKeyX }
      }).then(function (accessRequest) {
        return fetch(mintUrl, {
          method: "POST",
          headers: { "content-type": "application/json", accept: "application/json" },
          credentials: mintUrl.charAt(0) === "/" ? "include" : "omit",
          body: JSON.stringify({ device_cert: pair.device.cert, access_request: accessRequest })
        });
      }).then(function (r) { return r.json(); }).then(function (minted) {
        if (!minted.access_cert) throw new Error(minted.reason || "mint failed");
        return signJws(access.privateKey, { exp: nowS() + 300, aud: audience, req_origin: reqOrigin })
          .then(function (assertion) {
            return {
              presentation: minted.access_cert + "~" + assertion + "~" + warrantJws + "~" + pair.config.cert,
              accessKey: access
            };
          });
      });
    });
  }

  // --- sbo-wasm (lazy) --------------------------------------------------------
  var sboPromise = null;
  function loadSbo() {
    if (!sboPromise) {
      sboPromise = import("/common/js/sbo-wasm/sbo_wasm.js").then(function (m) {
        return Promise.resolve(m.default && m.default()).then(function () { return m; });
      });
    }
    return sboPromise;
  }

  // --- sign(kind: "signature") ----------------------------------------------
  // Sign a typed SBO envelope for `origin` under the covering stored record.
  // `prompt(action, envelope)` resolves true/false for prompt-mode scopes.
  // Resolves { signature, cert, pubkey, email }; rejects { error, message }
  // with error ∈ not_granted | scope_not_granted | prompt_declined |
  // bad_request | sign_failed.
  function signObject(p) {
    var origin = p.origin, email = p.email, audience = p.audience, envelope = p.envelope;
    if (!audience) {
      return Promise.reject({ error: "bad_request", message: "audience is required (the SBO database reference the grant binds)" });
    }
    var action = classifyAction(envelope);
    if (action && action.error) return Promise.reject(action);
    return devicePairFor(email).then(function (pair) {
      if (!pair) throw { error: "not_granted", message: "no device certs for " + email + " — sign in first" };
      var deviceHolder = (decodeJws(pair.device.cert) || {}).holder;
      var rec = coveringRecord(origin, email, audience, action, deviceHolder);
      if (rec.error) throw rec;
      return checkGrantStatus(rec.claims).then(function (st) {
        if (st === "revoked") {
          dropGrant(origin, audience);
          throw { error: "not_granted", message: "the signing grant was revoked — sign in again to re-approve" };
        }
        if (st !== "valid") throw { error: "sign_failed", message: "grant status check unavailable (fail-closed)" };
        var gate = rec.mode === "prompt"
          ? Promise.resolve(p.prompt ? p.prompt(action, envelope) : false).then(function (ok) {
              if (!ok) throw { error: "prompt_declined", message: "the user declined this " + action };
            })
          : Promise.resolve();
        return gate.then(function () {
          return mintUrlFor(email, pair.issuer).then(function (mintUrl) {
            return mintPresentation(email, audience, pair, mintUrl, rec.jws, origin);
          });
        });
      });
    }).then(function (res) {
      var identity = {
        email: email,
        pubkeyHex: window.SboSign.pubkeyHexFromJwkX(res.accessKey.publicKeyX),
        cert: res.presentation
      };
      return loadSbo().then(function (sbo) {
        return window.SboSign.signEnvelope(sbo, envelope, identity, res.accessKey.privateKey);
      });
    }).then(function (out) {
      return { signature: out.signature, cert: out.cert, pubkey: out.pubkey, email: email };
    }, function (err) {
      if (err && err.error) throw err;
      throw { error: "sign_failed", message: (err && err.message) || String(err) };
    });
  }

  // A short, human summary of the object to be signed, rendered from its
  // TYPED fields only (never a requester-supplied summary).
  function objectSummary(action, envelope) {
    var summary = { action: action, path: envelope && envelope.path, id: envelope && envelope.id };
    if (envelope && envelope.payload != null) {
      var body = String(envelope.payload);
      summary.payload = body.length > 400 ? body.slice(0, 400) + "…" : body;
    }
    return summary;
  }

  window.WalletSigner = {
    b64urlJson: b64urlJson, decodeJws: decodeJws, jwsExpired: jwsExpired, nowS: nowS, rndHex: rndHex,
    signJws: signJws,
    storedGrants: storedGrants, storeGrant: storeGrant, dropGrant: dropGrant,
    warrantV2Claims: warrantV2Claims,
    checkGrantStatus: checkGrantStatus, matcherCovers: matcherCovers,
    scopeName: scopeName, scopeMode: scopeMode,
    coveringRecord: coveringRecord, classifyAction: classifyAction,
    devicePairFor: devicePairFor, mintUrlFor: mintUrlFor, mintPresentation: mintPresentation,
    loadSbo: loadSbo, signObject: signObject, objectSummary: objectSummary
  };
})();
