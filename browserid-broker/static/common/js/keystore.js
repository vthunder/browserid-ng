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
  // Device-cert model records (v3): the durable device (authentication) and
  // config (authorization) keys + their IdP-signed certs, per (issuer, email).
  // Record: { issuer, email, kind: 'device'|'config', publicKeyX,
  //           privateKey (non-extractable CryptoKey), cert }
  var DEVICE = "device";
  var enc = new TextEncoder();

  function b64url(buf) {
    return btoa(String.fromCharCode.apply(null, new Uint8Array(buf)))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function key(issuer, email) { return issuer + "\n" + email.toLowerCase(); }

  function openDb() {
    return new Promise(function (res, rej) {
      // v3 adds the `device` store (device-cert model). onupgradeneeded runs for
      // fresh DBs and for older DBs; create whatever's missing either way.
      var req = indexedDB.open(DB, 3);
      req.onupgradeneeded = function () {
        if (!req.result.objectStoreNames.contains(STORE)) req.result.createObjectStore(STORE);
        if (!req.result.objectStoreNames.contains(PENDING)) req.result.createObjectStore(PENDING);
        if (!req.result.objectStoreNames.contains(DEVICE)) req.result.createObjectStore(DEVICE);
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

  // Purge everything from the CLASSIC protocol era: the old identity-cert
  // store, the same-tab provisioning staging area, and the legacy localStorage
  // key blob. (`siteInfo` stays — it holds per-site login state + SBO signing
  // grants, not certificates.) The device-cert model keeps only the `device`
  // store. Idempotent — safe to call on every page boot.
  function purgeLegacy() {
    try { localStorage.removeItem("emails"); } catch (e) {}
    var clearStore = function (name) {
      return txOn(name, "readwrite", function (store) { store.clear(); }).catch(function () {});
    };
    return Promise.all([clearStore(STORE), clearStore(PENDING)]);
  }

  // --- Device-cert model records (device-cert login) -----------------------
  function deviceKey(issuer, email, kind) {
    return issuer + "\n" + email.toLowerCase() + "\n" + kind;
  }
  // rec: { publicKeyX, privateKey, cert }
  function putDevice(issuer, email, kind, rec) {
    return txOn(DEVICE, "readwrite", function (store) {
      store.put({ issuer: issuer, email: email.toLowerCase(), kind: kind,
                  publicKeyX: rec.publicKeyX, privateKey: rec.privateKey, cert: rec.cert },
                deviceKey(issuer, email, kind));
    });
  }
  function getDevice(issuer, email, kind) {
    return txOn(DEVICE, "readonly", function (store) { return store.get(deviceKey(issuer, email, kind)); })
      .then(function (r) { return r || null; });
  }
  function delDevice(issuer, email, kind) {
    return txOn(DEVICE, "readwrite", function (store) { store.delete(deviceKey(issuer, email, kind)); });
  }
  // Every device-store record (across issuers/emails/kinds).
  function allDevice() {
    return txOn(DEVICE, "readonly", function (store) {
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

  // --- Local-store health check (browserid-ng-y9vr) -------------------------
  // Hygiene, never enforcement: the server's gates stay load-bearing; an
  // honest client just avoids ever PRESENTING a credential it can already
  // know is dead. Dropping a pair is always safe — the worst case is one
  // re-issue through the proper ceremony, which is the designed path.
  function certClaims(cert) {
    try {
      var p = String(cert).split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
      return JSON.parse(atob(p));
    } catch (e) { return null; }
  }
  // No network: drop expired (within 60s) and unparseable device records.
  // Cheap enough to run on every page load.
  function healthLocal() {
    return allDevice().then(function (recs) {
      var now = Math.floor(Date.now() / 1000);
      var drops = [];
      (recs || []).forEach(function (r) {
        var c = r && r.cert ? certClaims(r.cert) : null;
        if (!c || !c.exp || c.exp <= now + 60) {
          drops.push(delDevice(r.issuer, r.email, r.kind).catch(function () {}));
        }
      });
      return Promise.all(drops).then(function () { return drops.length; });
    });
  }
  // With a broker session: `registryCerts` = /wsapi/device_certs rows,
  // `proofs` = list_emails proofs. Drops pairs whose registry row is revoked
  // (any issuer) or missing (broker-issued only — foreign issuers own their
  // own lists), and pairs whose issued-under class (`prov` claim, absent =
  // smtp) no longer matches the address's current proof class.
  function healthRemote(registryCerts, proofs, brokerHost) {
    var byPub = {};
    (registryCerts || []).forEach(function (c) { if (c.pubkey) byPub[c.pubkey] = c; });
    var proofOf = {};
    (proofs || []).forEach(function (p) { proofOf[(p.email || "").toLowerCase()] = p.proof; });
    return allDevice().then(function (recs) {
      var drops = [];
      (recs || []).forEach(function (r) {
        var c = r && r.cert ? certClaims(r.cert) : null;
        if (!c) return; // healthLocal's job
        var dead = false;
        var row = r.publicKeyX ? byPub[r.publicKeyX] : null;
        if (row && row.revoked) dead = true;
        if (!row && c.iss === brokerHost) dead = true;
        var current = proofOf[(r.email || "").toLowerCase()];
        if (current && (current === "oidc" || current === "atproto")
            && (c.prov || "smtp") !== current) dead = true;
        if (dead) {
          drops.push(delDevice(r.issuer, r.email, r.kind).catch(function () {}));
        }
      });
      return Promise.all(drops).then(function () { return drops.length; });
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
    forEmail: forEmail, all: all, purgeLegacy: purgeLegacy,
    putPending: putPending, getPending: getPending, clearPending: clearPending,
    putDevice: putDevice, getDevice: getDevice, delDevice: delDevice, allDevice: allDevice,
    healthLocal: healthLocal, healthRemote: healthRemote
  };
})();
