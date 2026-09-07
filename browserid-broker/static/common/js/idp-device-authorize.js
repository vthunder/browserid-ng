// Hosted-primary device-authorization page (bean g5qt).
//
// The login dialog opens this in a popup with a URL fragment
//   #email=…&device_pubkey=…&config_pubkey=…[&holder=…][&hold=1]
//     &return_origin=…[&return_url=…]
// (never query — the fragment stays out of server logs). Here the tenant
// user authenticates FIRST-PARTY with a password, this page calls the
// hosted IdP's own /idp/device_cert for those pubkeys, and posts
//   {type:'browserid:device_certs', device_cert, config_cert}
// back to window.opener (targetOrigin = return_origin), then closes. This
// matches the exact contract the dialog already speaks for external
// primaries — the dialog is not modified.
(function () {
  "use strict";

  var $ = function (id) { return document.getElementById(id); };

  // --- Parse + strip the fragment -----------------------------------------
  var params = new URLSearchParams((location.hash || "").replace(/^#/, ""));
  var email = params.get("email") || "";
  var devicePubkey = params.get("device_pubkey") || "";
  var configPubkey = params.get("config_pubkey") || "";
  var holder = params.get("holder") || "";
  var hold = params.get("hold") === "1";
  var returnUrl = params.get("return_url") || "";
  var returnOriginRaw = params.get("return_origin") || "";
  // Accepted return origins (fallback-idp-api-v1 §3.1): loopback and
  // custom-scheme origins always (only code on the user's machine can
  // receive them); http(s) only if the issuer lists it in `wallet-origins`
  // (own origin included). The issuance endpoint enforces the same rule —
  // this check exists so a refused wallet fails BEFORE the user signs in.
  var returnOrigin = null;      // normalized origin string
  var returnIsWeb = false;      // http(s): needs the issuer's list
  (function () {
    var m = /^([A-Za-z][A-Za-z0-9+.-]*):\/\/([^\/?#]+)$/.exec(returnOriginRaw.trim());
    if (!m) return;
    var scheme = m[1].toLowerCase(), rest = m[2];
    if (scheme !== "http" && scheme !== "https") {
      returnOrigin = scheme + "://" + rest;  // custom scheme: return_url lane only
      return;
    }
    if (rest.indexOf("@") !== -1) return;
    try {
      var u = new URL(scheme + "://" + rest);
      returnOrigin = u.origin;
      var h = u.hostname.toLowerCase();
      returnIsWeb = !(h === "127.0.0.1" || h === "[::1]" || h === "localhost");
    } catch (e) { returnOrigin = null; }
  })();
  function sameOrigin(url) {
    if (!returnOrigin) return false;
    var m = /^([A-Za-z][A-Za-z0-9+.-]*):\/\/([^\/?#]+)/.exec(url);
    if (!m) return false;
    var scheme = m[1].toLowerCase();
    if (scheme !== "http" && scheme !== "https") return (scheme + "://" + m[2]) === returnOrigin;
    try { return new URL(url).origin === returnOrigin; } catch (e) { return false; }
  }
  // Resolves true when a web return origin is on the issuer's list.
  function originAccepted() {
    if (!returnOrigin) return Promise.resolve(false);
    if (!returnIsWeb) return Promise.resolve(true);
    if (returnOrigin === window.location.origin) return Promise.resolve(true);
    return fetch("/.well-known/browserid", { headers: { accept: "application/json" } })
      .then(function (r) { return r.json(); })
      .then(function (doc) {
        var list = (doc && doc["wallet-origins"]) || [];
        return list.some(function (o) {
          return String(o).replace(/\/+$/, "").toLowerCase() === returnOrigin.toLowerCase();
        });
      }).catch(function () { return false; });
  }
  // The certs certify the fragment's pubkeys, so the return_url delivery
  // lane must never navigate to a foreign origin: honor return_url only
  // when it is same-origin with the validated return_origin (bean 9it0).
  if (returnUrl && !sameOrigin(returnUrl)) returnUrl = "";
  // Drop the fragment from the address bar (defense in depth).
  try { history.replaceState(null, "", location.pathname + location.search); } catch (e) {}

  $("subtitle").textContent = email ? "Signing in as " + email : "Continue to your account";

  function post(type, extra) {
    // postMessage needs an http(s) target; a custom-scheme wallet only has
    // the return_url lane.
    if (!returnOrigin || !/^https?:/.test(returnOrigin) || !window.opener) return;
    var msg = { type: type };
    if (extra) for (var k in extra) msg[k] = extra[k];
    window.opener.postMessage(msg, returnOrigin);
  }

  function fail(reason) {
    // Mirror the dialog's device_error contract (echo the pubkey so the
    // strict redirect-lane pairing can match it).
    if (returnUrl) {
      try {
        var sep = returnUrl.indexOf("#") === -1 ? "#" : "&";
        location.replace(returnUrl + sep + "device_error=" + encodeURIComponent(reason) +
          "&device_pubkey=" + encodeURIComponent(devicePubkey));
        return;
      } catch (e) {}
    }
    post("browserid:device_error", { reason: reason, device_pubkey: devicePubkey });
  }

  function api(path, body) {
    return fetch(path, {
      method: "POST",
      headers: { "content-type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify(body),
    }).then(function (r) {
      return r.json().then(function (j) { return { ok: r.ok, body: j }; });
    });
  }

  // --- Issue certs once authenticated -------------------------------------
  function issueCerts() {
    return api("/idp/device_cert", {
      email: email,
      device_pubkey: devicePubkey,
      config_pubkey: configPubkey,
      holder: holder || undefined,
      return_origin: returnOriginRaw,
    }).then(function (res) {
      if (!res.ok || !res.body.success) {
        throw new Error(res.body.reason || "issuance failed");
      }
      return res.body;
    });
  }

  function deliver(certs) {
    if (returnUrl) {
      try {
        var sep = returnUrl.indexOf("#") === -1 ? "#" : "&";
        location.replace(returnUrl + sep +
          "device_cert=" + encodeURIComponent(certs.device_cert) +
          "&config_cert=" + encodeURIComponent(certs.config_cert));
        return;
      } catch (e) {}
    }
    post("browserid:device_certs", {
      device_cert: certs.device_cert,
      config_cert: certs.config_cert,
    });
    if (hold) {
      // Keep open for a possible reissue hop under a corrected holder.
      window.addEventListener("message", function (ev) {
        if (ev.origin !== returnOrigin || !ev.data) return;
        if (ev.data.type === "browserid:reissue") {
          holder = ev.data.holder || holder;
          issueCerts().then(function (c2) {
            post("browserid:device_certs", { device_cert: c2.device_cert, config_cert: c2.config_cert });
          }).catch(function (e) { post("browserid:device_error", { reason: String(e.message || e), device_pubkey: devicePubkey }); });
        } else if (ev.data.type === "browserid:done") {
          window.close();
        }
      });
    } else {
      setTimeout(function () { window.close(); }, 100);
    }
  }

  function showChangeForm() {
    $("login-form").classList.add("hidden");
    $("forgot").classList.add("hidden");
    $("change-form").classList.remove("hidden");
    $("title").textContent = "Choose your password";
    $("subtitle").textContent = "Set a password for " + email + " to finish signing in.";
    $("cur").focus();
  }

  function proceed(mustChange) {
    if (mustChange) { showChangeForm(); return; }
    issueCerts().then(deliver).catch(function (e) { fail(String(e.message || e)); });
  }

  // --- Preconditions -------------------------------------------------------
  if (!email || !devicePubkey || !configPubkey || !returnOrigin) {
    $("login-form").classList.add("hidden");
    $("login-err").textContent = "This sign-in link is malformed. Close this window and try again.";
    return;
  }

  // A wallet this issuer does not deliver to is told so BEFORE any password
  // is typed (fallback-idp-api-v1 §3.1). There is no accepted origin to
  // return the error to, so it is shown here and nowhere else.
  originAccepted().then(function (ok) {
    if (ok) {
      // If a session already exists (revisit within the window), skip the prompt.
      return fetch("/idp/whoami", { credentials: "same-origin" })
        .then(function (r) { return r.json(); })
        .then(function (j) {
          if (j && j.email && j.email.toLowerCase() === email.toLowerCase()) {
            proceed(!!j.must_change_password);
          }
        })
        .catch(function () {});
    }
    $("login-form").classList.add("hidden");
    $("subtitle").textContent = "This identity provider does not deliver sign-ins to " + returnOrigin + ".";
    $("login-err").textContent = "return_origin_not_allowed";
    returnOrigin = null;  // no delivery lane at all
    returnUrl = "";
  });

  // --- Login ---------------------------------------------------------------
  $("login-form").addEventListener("submit", function (e) {
    e.preventDefault();
    var btn = $("login-btn");
    btn.disabled = true;
    $("login-err").textContent = "";
    api("/idp/login", { email: email, password: $("password").value })
      .then(function (res) {
        if (!res.ok || !res.body.success) throw new Error(res.body.reason || "sign-in failed");
        proceed(!!res.body.must_change_password);
      })
      .catch(function (err) {
        $("login-err").textContent = String(err.message || err);
        btn.disabled = false;
      });
  });

  // --- Forced password change ---------------------------------------------
  $("change-form").addEventListener("submit", function (e) {
    e.preventDefault();
    $("change-err").textContent = "";
    var n1 = $("new1").value, n2 = $("new2").value;
    if (n1 !== n2) { $("change-err").textContent = "New passwords do not match."; return; }
    if (n1.length < 8) { $("change-err").textContent = "New password must be at least 8 characters."; return; }
    var btn = $("change-btn");
    btn.disabled = true;
    api("/idp/password", { email: email, current_password: $("cur").value, new_password: n1 })
      .then(function (res) {
        if (!res.ok || !res.body.success) throw new Error(res.body.reason || "could not set password");
        issueCerts().then(deliver).catch(function (er) { fail(String(er.message || er)); });
      })
      .catch(function (err) {
        $("change-err").textContent = String(err.message || err);
        btn.disabled = false;
      });
  });
})();
