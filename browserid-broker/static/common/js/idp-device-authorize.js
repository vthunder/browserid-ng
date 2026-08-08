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
  var returnOrigin = null;
  try {
    if (returnOriginRaw) {
      var u = new URL(returnOriginRaw);
      if (u.protocol === "https:" || u.protocol === "http:") returnOrigin = u.origin;
    }
  } catch (e) { /* invalid */ }
  // Drop the fragment from the address bar (defense in depth).
  try { history.replaceState(null, "", location.pathname + location.search); } catch (e) {}

  $("subtitle").textContent = email ? "Signing in as " + email : "Continue to your account";

  function post(type, extra) {
    if (!returnOrigin || !window.opener) return;
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
    $("title").textContent = "Set a new password";
    $("subtitle").textContent = "Your administrator requires a password change before continuing.";
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

  // If a session already exists (revisit within the window), skip the prompt.
  fetch("/idp/whoami", { credentials: "same-origin" })
    .then(function (r) { return r.json(); })
    .then(function (j) {
      if (j && j.email && j.email.toLowerCase() === email.toLowerCase()) {
        proceed(!!j.must_change_password);
      }
    })
    .catch(function () {});

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
