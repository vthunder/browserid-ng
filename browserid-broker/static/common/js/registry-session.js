// Registry API session client (registry-api-v1 §4.2, §4.4–§4.5, §5.2): the
// web wallet as a first-class registry client on the SAME standardized
// /api/v1 surface any native wallet uses.
//
// configure() takes the active identity's device pair (and the password
// the user just typed, when the dialog has it). ensure() yields a session:
// by `stored_key` with this browser's login cert for the account, else by
// looking the account up with the identity cert, logging in through the
// registry's login page — answered directly on this origin with the
// password, or opened in a popup for a foreign registry — and, first time
// on this browser, minting a login cert and attaching the pair. call()
// sends `Authorization: Bearer` + a `Proof` JWS (kid in the header, bh
// binding POST bodies) signed by a session member, re-logging in once on
// 401 invalid_session.
//
// Depends on window.Keystore. Loaded after keystore.js.
(function () {
  "use strict";

  var PROOF_TYP = "browserid-registry-proof-v1";

  var pair = null;      // {deviceCert, devicePrivateKey, configCert, configPrivateKey}
  var identity = null;
  var password = null;  // the password the user typed this run, if any
  var token = null;
  var tokenExp = 0;
  var kids = null;      // {device, config}
  var loginKey = null;  // {privateKey, publicKeyX, kid, cert} for the account
  var members = [];     // kids the current session holds
  var account = null;

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
  function b64urlToBytes(s) {
    s = s.replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "=";
    var bin = atob(s), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  function b64urlJson(obj) { return b64url(new TextEncoder().encode(JSON.stringify(obj))); }
  function decode(jws) {
    try { return JSON.parse(new TextDecoder().decode(b64urlToBytes(jws.split(".")[1]))); } catch (e) { return null; }
  }
  async function sha256(bytes) {
    return b64url(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)));
  }
  async function kidOfX(x) { return sha256(b64urlToBytes(x)); }
  async function kidOfCert(cert) {
    var c = decode(cert) || {};
    var pk = c["public-key"];
    var x = pk && (pk.publicKey || pk.x || pk);
    if (typeof x !== "string") throw new Error("cert carries no readable public key");
    return kidOfX(x);
  }

  function signWith(privateKey, header, claims) {
    var payload = b64urlJson(claims);
    return window.Keystore.sign(privateKey, header + "." + payload).then(function (sig) {
      return header + "." + payload + "." + sig;
    });
  }
  // A §4.4 proof by `key` ({privateKey, kid}); `body` (string) → bh.
  async function proofBy(key, method, path, body, jti) {
    var header = b64urlJson({ alg: "EdDSA", typ: PROOF_TYP, kid: key.kid });
    var claims = { htm: method, htu: window.location.origin + path, iat: nowS(), jti: jti || rndHex() };
    if (body !== undefined && body !== null) claims.bh = await sha256(new TextEncoder().encode(body));
    return signWith(key.privateKey, header, claims);
  }
  function deviceKey() { return { privateKey: pair.devicePrivateKey, kid: kids.device }; }
  function configKey() { return { privateKey: pair.configPrivateKey, kid: kids.config }; }
  // The key that signs a session call: a member. The login key when the
  // session holds it, else the config cert.
  function memberKey() {
    if (loginKey && members.indexOf(loginKey.kid) !== -1) return loginKey;
    if (members.indexOf(kids.config) !== -1) return configKey();
    if (members.indexOf(kids.device) !== -1) return deviceKey();
    return null;
  }

  async function postRaw(path, bodyStr, headers) {
    var h = { "content-type": "application/json", accept: "application/json" };
    for (var k in headers) h[k] = headers[k];
    var r = await fetch(path, { method: "POST", headers: h, body: bodyStr });
    var data = r.status === 204 ? {} : await r.json().catch(function () { return {}; });
    return { ok: r.ok, status: r.status, data: data };
  }
  function took(body) {
    token = body.token;
    tokenExp = Math.floor(new Date(body.expires_at).getTime() / 1000) || (nowS() + 3600);
    members = (body.members || []).map(function (m) { return m.kid; });
    if (body.account) { account = body.account; rememberAccount(body.account); }
  }
  function error(r, path) {
    var e = new Error("POST " + path + ": " + (r.data.error_description || r.data.error || r.status));
    e.status = r.status;
    e.reason = r.data.reason;
    return e;
  }

  // --- what this browser remembers per identity ---------------------------
  function accountKey() { return "browserid:registry:account:" + identity; }
  function knownAccount() { try { return localStorage.getItem(accountKey()) || null; } catch (e) { return null; } }
  function rememberAccount(id) { try { localStorage.setItem(accountKey(), id); } catch (e) { /* best-effort */ } }
  // Login keys live in the keystore's device store under kind "login",
  // keyed by the registry host and the account id.
  async function loadLoginKey(acct) {
    try {
      var rec = await window.Keystore.getDevice(window.location.host, "@registry:" + acct, "login");
      if (!rec || !rec.privateKey || !rec.cert) return null;
      var c = decode(rec.cert);
      if (!c || !c.exp || c.exp <= nowS() + 60) return null;
      return { privateKey: rec.privateKey, publicKeyX: rec.publicKeyX, kid: await kidOfX(rec.publicKeyX), cert: rec.cert };
    } catch (e) { return null; }
  }
  async function storeLoginKey(acct, key) {
    try {
      await window.Keystore.putDevice(window.location.host, "@registry:" + acct, "login",
        { publicKeyX: key.publicKeyX, privateKey: key.privateKey, cert: key.cert });
    } catch (e) { /* best-effort: next run logs in through the page again */ }
  }

  // --- the calls ---------------------------------------------------------
  // Possession proofs for the pair, plus the header proof by `signer`.
  async function withCerts(path, extra, signer) {
    var jti = rndHex();
    var body = Object.assign({
      identity: identity,
      certs: [
        { cert: pair.deviceCert, proof: await proofBy(deviceKey(), "POST", path, null, jti) },
        { cert: pair.configCert, proof: await proofBy(configKey(), "POST", path, null, jti) },
      ],
    }, extra || {});
    var bodyStr = JSON.stringify(body);
    return { bodyStr: bodyStr, header: await proofBy(signer || configKey(), "POST", path, bodyStr, jti) };
  }

  async function lookupAccount() {
    var path = "/api/v1/accounts/lookup";
    var w = await withCerts(path, {});
    var r = await postRaw(path, w.bodyStr, { proof: w.header });
    if (r.ok && r.data.account) return r.data.account;
    if (r.status === 404) return null;
    throw error(r, path);
  }

  async function createAccount() {
    var path = "/api/v1/accounts";
    var w = await withCerts(path, {});
    var r = await postRaw(path, w.bodyStr, { proof: w.header });
    if (r.ok && r.data.token) { took(r.data); return; }
    throw error(r, path);
  }

  async function loginStored(acct) {
    var path = "/api/v1/login";
    var jti = rndHex();
    var pp = await proofBy(loginKey, "POST", path, null, jti);
    var bodyStr = JSON.stringify({ account: acct, method: "stored_key", proof: pp });
    var r = await postRaw(path, bodyStr, { proof: await proofBy(loginKey, "POST", path, bodyStr, jti) });
    if (r.ok && r.data.token) { took(r.data); return true; }
    return false;
  }

  async function loginPage(acct) {
    var path = "/api/v1/login";
    var r = await postRaw(path, JSON.stringify({ account: acct, method: "login_page" }), {});
    if (!(r.status === 403 && r.data.reason === "login_required" && r.data.url)) throw error(r, path);
    var url = new URL(r.data.url, window.location.origin);
    var pageToken;
    if (url.origin === window.location.origin) {
      // This registry's own page: its check is the account password, which
      // the dialog has just collected — post it straight to the page's
      // backend rather than rendering the page.
      if (!password) {
        var e = new Error("a login is needed but no password is at hand");
        e.reason = "login_needed";
        throw e;
      }
      var lr = await postRaw("/wsapi/registry_login", JSON.stringify({ account: acct, password: password }), {});
      if (!(lr.ok && lr.data.login)) throw error(lr, "/wsapi/registry_login");
      pageToken = lr.data.login;
    } else {
      pageToken = await loginPopup(url, acct);
    }
    var r2 = await postRaw(path, JSON.stringify({ account: acct, method: "login_page", token: pageToken }), {});
    if (r2.ok && r2.data.token) { took(r2.data); return; }
    throw error(r2, path);
  }

  function loginPopup(url, acct) {
    return new Promise(function (resolve, reject) {
      var frag = "#account=" + encodeURIComponent(acct) + "&return_origin=" + encodeURIComponent(window.location.origin);
      var popup = window.open(url.href + frag, "browserid_registry_login", "width=480,height=640");
      if (!popup) { reject({ popupBlocked: true }); return; }
      var done = false;
      function finish(fn, v) {
        if (done) return; done = true;
        clearTimeout(tid); clearInterval(pid);
        window.removeEventListener("message", onMsg);
        try { popup.close(); } catch (e) {}
        fn(v);
      }
      function onMsg(ev) {
        if (ev.origin !== url.origin) return;
        var d = ev.data;
        if (!d || d.type !== "browserid:login") return;
        if (d.login) finish(resolve, d.login);
        else finish(reject, new Error(d.login_error || "login refused"));
      }
      window.addEventListener("message", onMsg);
      var tid = setTimeout(function () { finish(reject, new Error("registry login timed out")); }, 3 * 60 * 1000);
      var pid = setInterval(function () { if (popup.closed) finish(reject, new Error("registry login cancelled")); }, 500);
    });
  }

  async function ensureLoginKey() {
    if (loginKey) return;
    var kp = await window.Keystore.generate();
    var r = await call("POST", "/api/v1/login-keys", { pubkey: kp.publicKeyX, label: "This browser" });
    loginKey = { privateKey: kp.privateKey, publicKeyX: kp.publicKeyX, kid: r.kid, cert: r.cert };
    await storeLoginKey(account, loginKey);
  }

  // Attach the pair under the session (idempotent on pubkey); the header
  // proof is by a member when we have one, else by the config cert itself.
  async function attach() {
    var path = "/api/v1/account/attach";
    var w = await withCerts(path, {}, memberKey() || configKey());
    var r = await postRaw(path, w.bodyStr, { proof: w.header, authorization: "Bearer " + token });
    if (r.ok && r.data.token) { took(r.data); return; }
    throw error(r, path);
  }

  // A live session with the pair attached.
  async function ensure() {
    if (token && nowS() < tokenExp - 60 && memberKey()) return token;
    if (!pair) throw new Error("Registry not configured");
    token = null; members = [];
    var acct = account || knownAccount();
    if (acct) {
      if (!loginKey) loginKey = await loadLoginKey(acct);
      if (loginKey && await loginStored(acct)) {
        if (!memberKey() || members.indexOf(kids.config) === -1) await attach();
        return token;
      }
      loginKey = null;
    }
    acct = await lookupAccount();
    if (!acct) {
      await createAccount();          // the pair is recorded by creation
    } else {
      await loginPage(acct);
      await attach();
    }
    try { await ensureLoginKey(); } catch (e) { console.warn("login key not minted:", e.message || e); }
    return token;
  }

  // Session-authed API call (§4.4). `path` may carry a query — htu never
  // does. 204 resolves to {}; any error throws with status/reason.
  async function call(method, path, body, retried) {
    await ensure();
    var key = memberKey();
    if (!key) throw new Error("no session member to sign with");
    var htuPath = path.split("?")[0];
    var bodyStr = body !== undefined ? JSON.stringify(body) : undefined;
    var r = await fetch(path, {
      method: method,
      headers: {
        "content-type": "application/json",
        accept: "application/json",
        authorization: "Bearer " + token,
        proof: await proofBy(key, method, htuPath, method === "GET" ? null : (bodyStr || ""), null),
      },
      body: bodyStr,
    });
    var data = r.status === 204 ? {} : await r.json().catch(function () { return {}; });
    if (r.status === 401 && data.error === "invalid_session" && !retried) {
      token = null;
      return call(method, path, body, true);
    }
    if (r.status >= 400) {
      var e = new Error(method + " " + path + ": " + (data.error_description || data.error || r.status));
      e.status = r.status;
      e.reason = data.reason;
      throw e;
    }
    return data;
  }

  window.Registry = {
    // pair: {deviceCert, devicePrivateKey, configCert, configPrivateKey};
    // identity: its email; password: what the user typed this run, if
    // any (used only against this origin's own login page). A different
    // config cert drops the session.
    configure: async function (opts) {
      var sameCert = pair && pair.configCert === opts.pair.configCert;
      pair = {
        deviceCert: opts.pair.deviceCert,
        devicePrivateKey: opts.pair.devicePrivateKey,
        configCert: opts.pair.configCert,
        configPrivateKey: opts.pair.configPrivateKey,
      };
      if (identity !== opts.identity) { account = null; loginKey = null; }
      identity = opts.identity;
      if (opts.password) password = opts.password;
      kids = { device: await kidOfCert(pair.deviceCert), config: await kidOfCert(pair.configCert) };
      if (!sameCert) { token = null; tokenExp = 0; members = []; }
    },
    configured: function () { return !!pair; },
    ensure: ensure,
    call: call,
  };
})();
