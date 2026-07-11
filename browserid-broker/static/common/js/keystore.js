// Non-extractable key custody (bean e2fi). Identity + RP-facing assertion keys
// live as NON-EXTRACTABLE WebCrypto CryptoKeys in IndexedDB — JS holds only a
// signing handle, never the raw private bytes, so XSS / a malicious extension /
// a storage dump cannot exfiltrate the key. Zero UX: no prompts, same crypto
// (Ed25519 via crypto.subtle), just a different place to keep the key.
//
// Shared across the browserid origin's pages (dialog, consent, /account) via
// one IndexedDB database. Replaces the old localStorage `emails` blob (which
// stored the private JWK `d` in the clear). Record shape:
//   { issuer, email, publicKeyX (base64url), privateKey (CryptoKey), cert }
//
// The provisioning key an agent exports is NOT stored here — it must leave the
// browser, so it stays an ordinary extractable key elsewhere.
(function () {
  "use strict";

  var DB = "browserid-keys";
  var STORE = "keys";
  var enc = new TextEncoder();

  function b64url(buf) {
    return btoa(String.fromCharCode.apply(null, new Uint8Array(buf)))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function key(issuer, email) { return issuer + "\n" + email.toLowerCase(); }

  function openDb() {
    return new Promise(function (res, rej) {
      var req = indexedDB.open(DB, 1);
      req.onupgradeneeded = function () {
        if (!req.result.objectStoreNames.contains(STORE)) req.result.createObjectStore(STORE);
      };
      req.onsuccess = function () { res(req.result); };
      req.onerror = function () { rej(req.error); };
    });
  }
  function tx(mode, fn) {
    return openDb().then(function (db) {
      return new Promise(function (res, rej) {
        var t = db.transaction(STORE, mode);
        var store = t.objectStore(STORE);
        var out = fn(store);
        t.oncomplete = function () { res(out && out.result !== undefined ? out.result : out); };
        t.onerror = function () { rej(t.error); };
        t.onabort = function () { rej(t.error); };
      });
    });
  }

  // Generate a fresh Ed25519 keypair whose private key is NON-EXTRACTABLE.
  // Returns { privateKey: CryptoKey, publicKeyX: base64url } — the public part
  // is exportable (public keys always are) so it can be certified.
  function generate() {
    return crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]).then(function (kp) {
      return crypto.subtle.exportKey("jwk", kp.publicKey).then(function (jwk) {
        return { privateKey: kp.privateKey, publicKeyX: jwk.x };
      });
    });
  }

  // Sign a string with a non-extractable private CryptoKey. Returns base64url
  // of the raw Ed25519 signature (JWS third segment).
  function sign(privateKey, message) {
    return crypto.subtle.sign({ name: "Ed25519" }, privateKey, enc.encode(message)).then(b64url);
  }

  function put(issuer, email, rec) {
    return tx("readwrite", function (store) {
      store.put({ issuer: issuer, email: email.toLowerCase(), publicKeyX: rec.publicKeyX,
                  privateKey: rec.privateKey, cert: rec.cert }, key(issuer, email));
    });
  }
  function get(issuer, email) {
    return tx("readonly", function (store) { return store.get(key(issuer, email)); })
      .then(function (r) { return r || null; });
  }
  function del(issuer, email) {
    return tx("readwrite", function (store) { store.delete(key(issuer, email)); });
  }
  // All records (across issuers) for one email.
  function forEmail(email) {
    var want = (email || "").toLowerCase();
    return tx("readonly", function (store) {
      var acc = [];
      store.openCursor().onsuccess = function (e) {
        var c = e.target.result;
        if (!c) return;
        if (c.value && c.value.email === want) acc.push(c.value);
        c.continue();
      };
      return { get result() { return acc; } };
    });
  }

  // One-time migration off the legacy localStorage `emails` blob: re-import each
  // stored JWK as a NON-EXTRACTABLE CryptoKey (the raw bytes were already
  // exposed in localStorage; after import they're locked), then wipe the blob.
  function migrateFromLocalStorage() {
    var raw;
    try { raw = JSON.parse(localStorage.getItem("emails") || "{}"); } catch (e) { return Promise.resolve(); }
    var jobs = [];
    Object.keys(raw).forEach(function (issuer) {
      Object.keys(raw[issuer] || {}).forEach(function (email) {
        var rec = raw[issuer][email];
        if (!rec || !rec.priv || !rec.priv.d || !rec.cert) return;
        var jwk = { kty: "OKP", crv: "Ed25519", x: rec.priv.x, d: rec.priv.d };
        jobs.push(
          crypto.subtle.importKey("jwk", jwk, { name: "Ed25519" }, false, ["sign"])
            .then(function (pk) { return put(issuer, email, { privateKey: pk, publicKeyX: rec.priv.x, cert: rec.cert }); })
            .catch(function () {})
        );
      });
    });
    return Promise.all(jobs).then(function () {
      if (Object.keys(raw).length) { try { localStorage.removeItem("emails"); } catch (e) {} }
    });
  }

  window.Keystore = {
    generate: generate, sign: sign, put: put, get: get, del: del,
    forEmail: forEmail, migrateFromLocalStorage: migrateFromLocalStorage
  };
})();
