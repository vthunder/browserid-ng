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
  // Staging store for the same-tab provisioning handshake (mingo-ytrs). A
  // non-extractable CryptoKey can't survive a top-level navigation via
  // sessionStorage (it isn't a string), but IndexedDB structured-clones it, so we
  // stash the PENDING keypair + handshake metadata here while the tab is at the
  // IdP minting the cert, and consume it when the IdP redirects back.
  var PENDING = "pending";
  var PENDING_KEY = "current";
  var enc = new TextEncoder();

  function b64url(buf) {
    return btoa(String.fromCharCode.apply(null, new Uint8Array(buf)))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function key(issuer, email) { return issuer + "\n" + email.toLowerCase(); }

  function openDb() {
    return new Promise(function (res, rej) {
      // v2 adds the `pending` staging store (mingo-ytrs). onupgradeneeded runs for
      // fresh DBs and for existing v1 DBs; create whatever's missing either way.
      var req = indexedDB.open(DB, 2);
      req.onupgradeneeded = function () {
        if (!req.result.objectStoreNames.contains(STORE)) req.result.createObjectStore(STORE);
        if (!req.result.objectStoreNames.contains(PENDING)) req.result.createObjectStore(PENDING);
      };
      req.onsuccess = function () { res(req.result); };
      req.onerror = function () { rej(req.error); };
    });
  }
  function tx(mode, fn) { return txOn(STORE, mode, fn); }
  function txOn(storeName, mode, fn) {
    return openDb().then(function (db) {
      return new Promise(function (res, rej) {
        var t = db.transaction(storeName, mode);
        var store = t.objectStore(storeName);
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
  // Every record in the keystore.
  function all() {
    return tx("readonly", function (store) {
      var acc = [];
      store.openCursor().onsuccess = function (e) {
        var c = e.target.result;
        if (!c) return;
        acc.push(c.value);
        c.continue();
      };
      return { get result() { return acc; } };
    });
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

  // --- Same-tab provisioning staging (mingo-ytrs) --------------------------
  // A single in-flight handshake at a time. `rec` carries the non-extractable
  // privateKey (CryptoKey) plus the metadata needed to validate the returned
  // cert: { privateKey, publicKeyX, email, issuer, nonce, returnTo }.
  function putPending(rec) {
    return txOn(PENDING, "readwrite", function (store) { store.put(rec, PENDING_KEY); });
  }
  function getPending() {
    return txOn(PENDING, "readonly", function (store) { return store.get(PENDING_KEY); })
      .then(function (r) { return r || null; });
  }
  function clearPending() {
    return txOn(PENDING, "readwrite", function (store) { store.delete(PENDING_KEY); });
  }

  window.Keystore = {
    generate: generate, sign: sign, put: put, get: get, del: del,
    forEmail: forEmail, all: all, migrateFromLocalStorage: migrateFromLocalStorage,
    putPending: putPending, getPending: getPending, clearPending: clearPending
  };
})();
