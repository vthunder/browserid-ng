// Registry API session client (registry-api-v1 §4.4–§4.5, §5.2; bean 0c49
// phase 2): the web wallet as a first-class registry client on the SAME
// standardized /api/v1 surface any native wallet uses.
//
// configure() takes the active identity's device pair. ensure() opens a
// session: possession proofs by both keys against the account the pair was
// last attached to, or — when nothing is recorded yet — an `attach`, which
// may hit the account's guard (§4.2). For the broker's own dialog the guard
// is answered in place (a fresh password session passes by itself; an
// older session needs the user's click on the guard screen); a foreign
// registry's guard page opens in a popup. call() sends
// `Authorization: Bearer` + a `Proof` JWS signed by the config key (kid in
// the header, bh binding POST bodies), re-opening the session once on
// 401 invalid_session.
//
// Depends on window.Keystore (sign). Loaded after keystore.js.
(function () {
  "use strict";

  var PROOF_TYP = "browserid-registry-proof-v1";
  var GUARD_PENDING_KEY = "browserid:registry:guard_pending";

  var pair = null;      // {deviceCert, devicePrivateKey, configCert, configPrivateKey}
  var identity = null;
  var token = null;
  var tokenExp = 0;
  var kids = null;      // {device, config}
  var guardHook = null; // (info) => Promise<token>, the dialog's in-place guard

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
  // kid = base64url(SHA-256(raw public key)) (§4.4), from the cert's claim.
  async function kidOf(cert) {
    var c = decode(cert) || {};
    var pk = c["public-key"];
    var x = pk && (pk.publicKey || pk.x || pk);
    if (typeof x !== "string") throw new Error("cert carries no readable public key");
    return sha256(b64urlToBytes(x));
  }

  function signWith(privateKey, header, claims) {
    var payload = b64urlJson(claims);
    return window.Keystore.sign(privateKey, header + "." + payload).then(function (sig) {
      return header + "." + payload + "." + sig;
    });
  }
  async function proof(which, method, path, body, jti) {
    var kid = which === "device" ? kids.device : kids.config;
    var key = which === "device" ? pair.devicePrivateKey : pair.configPrivateKey;
    var header = b64urlJson({ alg: "EdDSA", typ: PROOF_TYP, kid: kid });
    var claims = { htm: method, htu: window.location.origin + path, iat: nowS(), jti: jti || rndHex() };
    if (body !== undefined && body !== null) claims.bh = await sha256(new TextEncoder().encode(body));
    return signWith(key, header, claims);
  }

  function accountKey() { return "browserid:registry:account:" + identity; }
  function knownAccount() { try { return localStorage.getItem(accountKey()) || null; } catch (e) { return null; } }
  function rememberAccount(id) { try { localStorage.setItem(accountKey(), id); } catch (e) { /* best-effort */ } }

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
    if (body.account) rememberAccount(body.account);
  }

  // §4.5: a session from possession proofs on the known account.
  async function openSession() {
    var account = knownAccount();
    if (!account) return false;
    var path = "/api/v1/session";
    var jti = rndHex();
    var proofs = [await proof("device", "POST", path, null, jti), await proof("config", "POST", path, null, jti)];
    var bodyStr = JSON.stringify({ account: account, proofs: proofs });
    var r = await postRaw(path, bodyStr, { proof: await proof("config", "POST", path, bodyStr, jti) });
    if (r.ok && r.data.token) { took(r.data); return true; }
    // unknown_key / unknown account: the certs are not (or no longer)
    // recorded there — attach decides.
    return false;
  }

  // §5.2.1: record this pair for the identity, on the account that holds
  // it (guard) or a new one.
  async function attach(guard) {
    var path = "/api/v1/account/attach";
    var jti = rndHex();
    var body = {
      identity: identity,
      certs: [
        { cert: pair.deviceCert, proof: await proof("device", "POST", path, null, jti) },
        { cert: pair.configCert, proof: await proof("config", "POST", path, null, jti) },
      ],
    };
    var account = knownAccount();
    if (account && token) body.account = account;
    if (guard) body.guard = guard;
    var bodyStr = JSON.stringify(body);
    var headers = { proof: await proof("config", "POST", path, bodyStr, jti) };
    if (token && account) headers.authorization = "Bearer " + token;
    var r = await postRaw(path, bodyStr, headers);
    if (r.ok && r.data.token) { took(r.data); return; }
    if (r.status === 403 && r.data.reason === "guard_required" && !guard) {
      var kinds = r.data.guard_kinds || [];
      var page = kinds.filter(function (k) { return k.kind === "page" && k.url; })[0];
      if (!page) throw error(r, path);
      return attach(await passGuard(page.url));
    }
    throw error(r, path);
  }

  function error(r, path) {
    var e = new Error("POST " + path + ": " + (r.data.error_description || r.data.error || r.status));
    e.status = r.status;
    e.reason = r.data.reason;
    return e;
  }

  // The guard (§4.2). Same origin: the dialog's own screen answers it
  // through /wsapi/guard (the registry is this broker). Elsewhere: the
  // registry's page, in a popup, handing the token back by postMessage.
  // A guard already pending in another dialog window is never nested: a
  // login opened FROM a guard page must not open a second guard.
  async function passGuard(url) {
    var pending = 0;
    try { pending = Number(localStorage.getItem(GUARD_PENDING_KEY) || 0); } catch (e) {}
    if (pending && Date.now() - pending < 5 * 60 * 1000) {
      var e = new Error("a device approval is already pending");
      e.reason = "guard_pending";
      throw e;
    }
    try { localStorage.setItem(GUARD_PENDING_KEY, String(Date.now())); } catch (e) {}
    try {
      var origin = new URL(url, window.location.origin).origin;
      if (origin === window.location.origin) {
        if (!guardHook) throw new Error("no guard handler configured");
        return await guardHook({ identity: identity, certs: [pair.deviceCert, pair.configCert], kids: kids });
      }
      return await guardPopup(url);
    } finally {
      try { localStorage.removeItem(GUARD_PENDING_KEY); } catch (e) {}
    }
  }

  function guardPopup(url) {
    return new Promise(function (resolve, reject) {
      var target = new URL(url, window.location.origin);
      var frag = "#certs=" + encodeURIComponent([pair.deviceCert, pair.configCert].join(",")) +
        "&identity=" + encodeURIComponent(identity) +
        "&return_origin=" + encodeURIComponent(window.location.origin);
      var popup = window.open(target.href + frag, "browserid_guard", "width=480,height=640");
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
        if (ev.origin !== target.origin) return;
        var d = ev.data;
        if (!d || d.type !== "browserid:guard") return;
        if (d.guard) finish(resolve, d.guard);
        else finish(reject, new Error(d.guard_error || "guard refused"));
      }
      window.addEventListener("message", onMsg);
      var tid = setTimeout(function () { finish(reject, new Error("device approval timed out")); }, 3 * 60 * 1000);
      var pid = setInterval(function () { if (popup.closed) finish(reject, new Error("device approval cancelled")); }, 500);
    });
  }

  // A live session, opening or attaching as needed.
  async function ensure() {
    if (token && nowS() < tokenExp - 60) return token;
    if (!pair) throw new Error("Registry not configured");
    token = null;
    if (await openSession()) return token;
    await attach(null);
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
        proof: await proof("config", method, htuPath, method === "GET" ? null : (bodyStr || ""), null),
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
    // identity: its email. A different config cert drops the session.
    configure: async function (opts) {
      var sameCert = pair && pair.configCert === opts.pair.configCert;
      pair = {
        deviceCert: opts.pair.deviceCert,
        devicePrivateKey: opts.pair.devicePrivateKey,
        configCert: opts.pair.configCert,
        configPrivateKey: opts.pair.configPrivateKey,
      };
      identity = opts.identity;
      kids = { device: await kidOf(pair.deviceCert), config: await kidOf(pair.configCert) };
      if (!sameCert) { token = null; tokenExp = 0; }
    },
    // The dialog's in-place guard for a same-origin registry:
    // ({identity, certs, kids}) → Promise<guard token>.
    onGuard: function (fn) { guardHook = fn; },
    configured: function () { return !!pair; },
    ensure: ensure,
    attach: function () { return attach(null); },
    call: call,
  };
})();
