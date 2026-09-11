// Registry API session client (registry-api-v1 §4.2, §4.4–§4.5, §5.2): the
// web wallet as a first-class registry client on the SAME standardized
// /api/v1 surface any native wallet uses.
//
// A session is bound to this browser's LOGIN KEY for the account (§4.5):
// one key per account, generated here, non-extractable, kept in the
// keystore's device store under kind "login". ensure() yields a session:
// `stored_key` when the registry still knows the key; else the login page
// — answered straight on this origin with the password the page collected
// (or askPassword()), opened in a popup for a foreign registry — which
// enrols the key; `accounts` on first use, which enrols it too. call()
// sends `Authorization: Bearer` + a `Proof` JWS by the login key (kid in
// the header, bh binding POST bodies), re-logging in once on 401.
//
// ONE registry login per wallet (bean mojx). This browser remembers a single
// wallet account for this registry host and holds one login key for it; every
// identity signs in to THAT account and its certs are attached there — an
// identity held by no account joins, one held by another account is
// transferred after the person confirms (askTakeover). A registry account is
// created only when the wallet has none at all. Never per identity: that is
// how a freshly minted identity once ended up with its own account.
//
// Two shapes. configure({pair, identity, password?, askTakeover?}): the dialog
// with an identity's device pair; after any login it attaches the pair
// (idempotent on pubkey). configureKeyless({account, password?, askPassword?}):
// a page that is its own device (the registry's /account page) — knows the
// account id, has no certs, shares the browser's key for that account.
//
// Depends on window.Keystore. Loaded after keystore.js.
(function () {
  "use strict";

  var PROOF_TYP = "browserid-registry-proof-v1";

  var pair = null;      // {deviceCert, devicePrivateKey, configCert, configPrivateKey}
  var identity = null;
  var password = null;  // the password the user typed this run, if any
  var askPassword = null; // keyless: () => Promise<string>, the page's own prompt
  var token = null;
  var tokenExp = 0;
  var kids = null;      // {device, config}
  var loginKey = null;  // {privateKey, publicKeyX, kid} for the account
  var account = null;
  var askTakeover = null; // (identity) => Promise<boolean>: may this identity move to the wallet's account?

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
    if (body.account) { account = body.account; rememberWallet(body.account); }
  }
  function error(r, path) {
    var e = new Error("POST " + path + ": " + (r.data.error_description || r.data.error || r.status));
    e.status = r.status;
    e.reason = r.data.reason;
    return e;
  }

  // --- what this browser remembers: ONE wallet account for this registry ---
  var WALLET_KEY = "browserid:registry:wallet";
  function walletAccount() { try { return localStorage.getItem(WALLET_KEY) || null; } catch (e) { return null; } }
  function rememberWallet(id) { try { localStorage.setItem(WALLET_KEY, id); } catch (e) { /* best-effort */ } }
  function forgetWallet() { try { localStorage.removeItem(WALLET_KEY); } catch (e) { /* best-effort */ } }
  // The login key lives in the keystore's device store under kind "login",
  // keyed by the registry host and the account id — shared by the dialog
  // and the account page.
  async function loadLoginKey(acct) {
    try {
      var rec = await window.Keystore.getDevice(window.location.host, "@registry:" + acct, "login");
      if (!rec || !rec.privateKey || !rec.publicKeyX) return null;
      return { privateKey: rec.privateKey, publicKeyX: rec.publicKeyX, kid: await kidOfX(rec.publicKeyX) };
    } catch (e) { return null; }
  }
  async function storeLoginKey(acct, key) {
    try {
      await window.Keystore.putDevice(window.location.host, "@registry:" + acct, "login",
        { publicKeyX: key.publicKeyX, privateKey: key.privateKey, cert: "" });
    } catch (e) { /* best-effort: next run logs in through the page again */ }
  }
  async function freshLoginKey() {
    var kp = await window.Keystore.generate();
    return { privateKey: kp.privateKey, publicKeyX: kp.publicKeyX, kid: await kidOfX(kp.publicKeyX) };
  }

  // --- the calls ---------------------------------------------------------
  // Possession proofs for the pair (and the login key when `withKey`), plus
  // the header proof by `signer`.
  async function withCerts(path, extra, signer, withKey) {
    var jti = rndHex();
    var body = Object.assign({ identity: identity }, extra || {});
    if (pair) {
      body.certs = [
        { cert: pair.deviceCert, proof: await proofBy(deviceKey(), "POST", path, null, jti) },
        { cert: pair.configCert, proof: await proofBy(configKey(), "POST", path, null, jti) },
      ];
    }
    if (withKey) body.login_key = await loginKeyArg(path, jti);
    var bodyStr = JSON.stringify(body);
    return { bodyStr: bodyStr, header: await proofBy(signer, "POST", path, bodyStr, jti) };
  }
  async function loginKeyArg(path, jti) {
    // No label: the registry names the device from the User-Agent.
    return { pubkey: loginKey.publicKeyX, proof: await proofBy(loginKey, "POST", path, null, jti) };
  }

  async function lookupAccount() {
    var path = "/api/v1/accounts/lookup";
    var w = await withCerts(path, {}, configKey(), false);
    var r = await postRaw(path, w.bodyStr, { proof: w.header });
    if (r.ok && r.data.account) return r.data.account;
    if (r.status === 404) return null;
    throw error(r, path);
  }

  // §5.2.1: a new account around the identity; the pair recorded and the
  // login key enrolled by creation.
  async function createAccount() {
    var path = "/api/v1/accounts";
    loginKey = await freshLoginKey();
    var w = await withCerts(path, {}, loginKey, true);
    var r = await postRaw(path, w.bodyStr, { proof: w.header });
    if (r.ok && r.data.token) { took(r.data); await storeLoginKey(account, loginKey); return; }
    throw error(r, path);
  }

  // §4.2 stored_key. False when the registry sends us to the page
  // (login_required: unknown, expired, or revoked key).
  async function loginStored(acct) {
    var path = "/api/v1/login";
    var jti = rndHex();
    var pp = await proofBy(loginKey, "POST", path, null, jti);
    var bodyStr = JSON.stringify({ account: acct, method: "stored_key", proof: pp });
    var r = await postRaw(path, bodyStr, { proof: await proofBy(loginKey, "POST", path, bodyStr, jti) });
    if (r.ok && r.data.token) { took(r.data); return true; }
    if (r.status === 403 && r.data.reason === "login_required") return false;
    throw error(r, path);
  }

  // §4.2 login_page: the page's token, then login with the login key, which
  // enrols (or re-enrols) it.
  async function loginPage(acct) {
    var path = "/api/v1/login";
    var r = await postRaw(path, JSON.stringify({ account: acct, method: "login_page" }), {});
    if (!(r.status === 403 && r.data.reason === "login_required" && r.data.url)) throw error(r, path);
    var url = new URL(r.data.url, window.location.origin);
    var pageToken;
    if (url.origin === window.location.origin && !password && askPassword) password = await askPassword();
    if (url.origin === window.location.origin && password) {
      // This registry's own page: its check is the account password, which
      // the page has just collected — post it straight to the page's
      // backend rather than rendering the page.
      var lr = await postRaw("/wsapi/registry_login", JSON.stringify({ account: acct, password: password }), {});
      if (!(lr.ok && lr.data.login)) throw error(lr, "/wsapi/registry_login");
      pageToken = lr.data.login;
    } else {
      // No password at hand (a remembered session), or a foreign registry:
      // the page itself asks.
      pageToken = await loginPopup(url, acct);
    }
    if (!loginKey) loginKey = await freshLoginKey();
    var jti = rndHex();
    var bodyStr = JSON.stringify({ account: acct, method: "login_page", token: pageToken, login_key: await loginKeyArg(path, jti) });
    var r2 = await postRaw(path, bodyStr, { proof: await proofBy(loginKey, "POST", path, bodyStr, jti) });
    if (r2.ok && r2.data.token) { took(r2.data); await storeLoginKey(acct, loginKey); return; }
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

  // §5.2.4: record the pair under the session (idempotent on pubkey). The
  // session is unchanged.
  async function attach(confirmTakeover) {
    var path = "/api/v1/account/attach";
    var w = await withCerts(path, confirmTakeover ? { confirm_takeover: true } : {}, loginKey, false);
    var r = await postRaw(path, w.bodyStr, { proof: w.header, authorization: "Bearer " + token });
    if (r.ok) return;
    throw error(r, path);
  }
  // Attach the configured identity's pair to the session's account: a join
  // for an identity held by no account, a TRANSFER — with the person's
  // explicit yes — for one held elsewhere (registry-api-v1 §5.2.4, §4.1).
  async function attachHere() {
    try { await attach(false); return; }
    catch (e) {
      if (!(e.status === 409 && e.reason === "identity_held")) throw e;
      if (!askTakeover || !(await askTakeover(identity))) throw e;
      await attach(true);
    }
  }

  // A live session bound to this browser's login key for the account; with
  // a pair, the pair recorded under it.
  async function ensure() {
    if (token && nowS() < tokenExp - 60 && loginKey) return token;
    if (!pair && !account) throw new Error("Registry not configured");
    token = null;
    // The wallet's one account: an explicit one (keyless pages name the
    // session's), else the remembered one. Every identity signs in there.
    var acct = account || walletAccount();
    if (acct) {
      if (!loginKey) loginKey = await loadLoginKey(acct);
      if (loginKey && await loginStored(acct)) {
        if (pair) await attachHere();
        return token;
      }
      // Known account, no usable key: the account's own login (password /
      // page) enrols a fresh key. Never a different account.
      await loginPage(acct);
      if (pair) await attachHere();
      return token;
    }
    // No wallet account yet. Adopt the one that holds this identity — with a
    // key this browser may already have for it (pre-mojx browsers), else its
    // login page — and only when nothing holds it, create one.
    if (pair) acct = await lookupAccount();
    if (acct) {
      loginKey = await loadLoginKey(acct);
      if (!(loginKey && await loginStored(acct))) await loginPage(acct);
      rememberWallet(acct);
      if (pair) await attachHere();
      return token;
    }
    await createAccount();          // the pair recorded, the key enrolled
    return token;
  }

  // Session-authed API call (§4.4). `path` may carry a query — htu never
  // does. 204 resolves to {}; any error throws with status/reason.
  async function call(method, path, body, retried) {
    await ensure();
    var htuPath = path.split("?")[0];
    var bodyStr = body !== undefined ? JSON.stringify(body) : undefined;
    var r = await fetch(path, {
      method: method,
      headers: {
        "content-type": "application/json",
        accept: "application/json",
        authorization: "Bearer " + token,
        proof: await proofBy(loginKey, method, htuPath, method === "GET" ? null : (bodyStr || ""), null),
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
      // A new identity does NOT mean a new account or key: the wallet has one
      // of each. Only the attach (which identity's pair) changes.
      identity = opts.identity;
      if (opts.password) password = opts.password;
      askPassword = null;
      askTakeover = opts.askTakeover || null;
      kids = { device: await kidOfCert(pair.deviceCert), config: await kidOfCert(pair.configCert) };
      if (!sameCert) { token = null; tokenExp = 0; }
    },
    // Keyless (a page as its own device): account is the registry's public
    // account id; password, when the page has just collected it;
    // askPassword() the page's prompt for when it has not.
    configureKeyless: function (opts) {
      pair = null; kids = null; identity = null;
      if (account !== opts.account) { loginKey = null; token = null; tokenExp = 0; }
      account = opts.account;
      password = opts.password || null;
      askPassword = opts.askPassword || null;
    },
    configured: function () { return !!pair || !!account; },
    // Whether this browser already holds a login key for the account, so a
    // page can tell "headless from here" from "will ask for the password".
    hasLoginKey: async function () {
      if (!account) return false;
      if (!loginKey) loginKey = await loadLoginKey(account);
      return !!loginKey;
    },
    // Forget this browser's login key for the account (after revoking it).
    forgetLoginKey: async function () {
      if (!account) return;
      try { await window.Keystore.delDevice(window.location.host, "@registry:" + account, "login"); } catch (e) {}
      if (walletAccount() === account) forgetWallet();
      loginKey = null; token = null;
    },
    walletAccount: walletAccount,
    account: function () { return account; },
    loginKid: function () { return loginKey ? loginKey.kid : null; },
    // Keyless mode: record certs this page just had issued under its
    // session (§5.2.4), so they belong to this device. certs:
    // [{cert, privateKey}] (1–2, one identity).
    attachCerts: async function (identityEmail, certs) {
      await ensure();
      var path = "/api/v1/account/attach";
      var jti = rndHex();
      var entries = [];
      for (var i = 0; i < certs.length; i++) {
        var key = { privateKey: certs[i].privateKey, kid: await kidOfCert(certs[i].cert) };
        entries.push({ cert: certs[i].cert, proof: await proofBy(key, "POST", path, null, jti) });
      }
      var bodyStr = JSON.stringify({ identity: identityEmail, certs: entries });
      var r = await postRaw(path, bodyStr, { proof: await proofBy(loginKey, "POST", path, bodyStr, jti), authorization: "Bearer " + token });
      if (!r.ok) throw error(r, path);
      return r.data;
    },
    ensure: ensure,
    call: call,
  };
})();
