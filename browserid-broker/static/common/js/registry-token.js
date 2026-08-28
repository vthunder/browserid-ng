// Registry API token client (registry-api-v1 §3, bean 71vt): the web wallet
// as a first-class registry client — the SAME standardized /api/v1 surface
// any native wallet uses, authenticated with a real sender-constrained
// token instead of the parallel cookie /wsapi lane.
//
// configure() takes the active identity's device pair; getToken() builds a
// self-presentation for this origin (fresh access-cert mint + a short-lived
// unregistered `registry`-scope warrant) and exchanges it at
// POST /api/v1/token; call() sends DPoP-style requests, re-exchanging once
// on 401 (there are no refresh tokens — a fresh presentation IS the
// refresh). The token is bound to the config cert, so configure() with a
// different pair (identity/holder switch) drops the cached token.
//
// Depends on window.Keystore (sign). Loaded after keystore.js.
(function () {
  "use strict";

  var PROOF_TYP = "browserid-registry-proof-v1";

  var pair = null;      // {deviceCert, devicePrivateKey, configCert, configPrivateKey}
  var identity = null;  // the pair's email
  var issuer = null;    // the pair's issuing domain
  var mintUrl = null;   // the issuer's access-cert mint
  var token = null;
  var tokenExp = 0;

  function nowS() { return Math.floor(Date.now() / 1000); }
  function rndHex() {
    var a = new Uint8Array(16);
    crypto.getRandomValues(a);
    return Array.from(a).map(function (b) { return b.toString(16).padStart(2, "0"); }).join("");
  }
  function b64url(bytes) {
    var s = "";
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function b64urlJson(obj) {
    return b64url(new TextEncoder().encode(JSON.stringify(obj)));
  }
  var JWS_HDR = b64urlJson({ alg: "EdDSA", typ: "JWT" });
  var PROOF_HDR = b64urlJson({ alg: "EdDSA", typ: PROOF_TYP });

  function signWith(privateKey, header, claims) {
    var payload = b64urlJson(claims);
    return window.Keystore.sign(privateKey, header + "." + payload).then(function (sig) {
      return header + "." + payload + "." + sig;
    });
  }

  function decode(jws) {
    try {
      var p = jws.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
      return JSON.parse(atob(p));
    } catch (e) { return null; }
  }

  async function postJson(url, body) {
    var r = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify(body),
    });
    var data = await r.json().catch(function () { return {}; });
    return { ok: r.ok, status: r.status, data: data };
  }

  // The §3.1 exchange credential: access_cert~assertion~warrant~config_cert
  // for THIS origin, self-granted, `registry` scope, warrant unregistered
  // and short-lived (it exists only to mint the token; v1 warrants need no
  // status ref at the exchange).
  async function buildTokenPresentation() {
    var holder = (decode(pair.deviceCert) || {}).holder || "";
    var matcher = holder.indexOf(".") !== -1 ? holder.slice(0, holder.indexOf(".")) + ".*" : holder;
    var origin = window.location.origin;

    var accessKp = await window.Keystore.generate();
    var reqClaims = {
      typ: "browserid-access-request-v1",
      iat: nowS(),
      exp: nowS() + 600,
      jti: rndHex(),
      domain: issuer,
      identity: identity,
      holder: holder,
      "access-key": { algorithm: "Ed25519", publicKey: accessKp.publicKeyX },
    };
    var dc = decode(pair.deviceCert);
    if (dc && dc.managed === true) reqClaims.audience = origin;
    var accessRequest = await signWith(pair.devicePrivateKey, JWS_HDR, reqClaims);
    var minted = await postJson(mintUrl, { device_cert: pair.deviceCert, access_request: accessRequest });
    if (!minted.ok || !minted.data.access_cert) {
      throw new Error(minted.data.reason || "access mint failed");
    }
    var warrant = await signWith(pair.configPrivateKey, JWS_HDR, {
      typ: "browserid-warrant-v1",
      iat: nowS(),
      exp: nowS() + 3600,
      grantor: identity,
      grantee: identity,
      holder: matcher,
      audience: origin,
      scopes: ["login", "registry"],
    });
    var assertion = await signWith(accessKp.privateKey, JWS_HDR, { exp: nowS() + 300, aud: origin });
    return minted.data.access_cert + "~" + assertion + "~" + warrant + "~" + pair.configCert;
  }

  async function getToken() {
    if (token && nowS() < tokenExp - 60) return token;
    if (!pair) throw new Error("RegistryToken not configured");
    var p = await buildTokenPresentation();
    var r = await postJson("/api/v1/token", { presentation: p });
    if (!r.ok || !r.data.access_token) {
      throw new Error(r.data.error_description || r.data.error || "token exchange failed");
    }
    token = r.data.access_token;
    tokenExp = nowS() + (r.data.expires_in || 0);
    return token;
  }

  async function proofFor(method, path, tok) {
    var htu = window.location.origin + path;
    var digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(tok)));
    return signWith(pair.configPrivateKey, PROOF_HDR, {
      htm: method,
      htu: htu,
      iat: nowS(),
      jti: rndHex(),
      ath: b64url(digest),
    });
  }

  // Token-authed API call. `path` may carry a query — the proof's htu never
  // does (§3.2). Throws on any error; 204 resolves to {}.
  async function call(method, path, body, retried) {
    var tok = await getToken();
    var htuPath = path.split("?")[0];
    var r = await fetch(path, {
      method: method,
      headers: {
        "content-type": "application/json",
        accept: "application/json",
        authorization: "DPoP " + tok,
        dpop: await proofFor(method, htuPath, tok),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    if (r.status === 401 && !retried) {
      token = null;
      return call(method, path, body, true);
    }
    var data = r.status === 204 ? {} : await r.json().catch(function () { return {}; });
    if (r.status >= 400) {
      var e = new Error(method + " " + path + ": " + (data.error_description || data.error || r.status));
      e.status = r.status;
      e.reason = data.reason;
      throw e;
    }
    return data;
  }

  window.RegistryToken = {
    // pair: {deviceCert, devicePrivateKey, configCert, configPrivateKey};
    // identity/issuer/mintUrl describe it. Reconfiguring (identity or
    // holder switch) drops the cached token — it was bound to the old cert.
    configure: function (opts) {
      // Same config cert → same binding: keep the cached token (repeat
      // logins with one identity must not re-exchange every time).
      var sameCert = pair && pair.configCert === opts.pair.configCert;
      pair = {
        deviceCert: opts.pair.deviceCert,
        devicePrivateKey: opts.pair.devicePrivateKey,
        configCert: opts.pair.configCert,
        configPrivateKey: opts.pair.configPrivateKey,
      };
      identity = opts.identity;
      issuer = opts.issuer;
      mintUrl = opts.mintUrl;
      if (!sameCert) {
        token = null;
        tokenExp = 0;
      }
    },
    configured: function () { return !!pair; },
    call: call,
  };
})();
