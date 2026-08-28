// Fallback-IdP device-authorization page (beans d0xb / 2jfh).
//
// The broker's own ceremony page for identities it vouches for
// (fallback-idp-api-v1 §3): a wallet opens this page with a URL fragment
//   #email=…&device_pubkey=…&config_pubkey=…&return_origin=…[&return_url=…]
// (never query — the fragment stays out of server logs), the user
// authenticates FIRST-PARTY with their broker password (or confirms with a
// click on a live session — never silently, bean mxcn), and the page issues
// the pair through the session-authed /device/issue core — the same
// chokepoint (authorize_mint) and wildcard rule as every broker issuance.
// Delivery follows the standard return contract:
//   return_url#device_cert=…&config_cert=…      success
//   return_url#device_error=…                   refusal
// with the postMessage lane (targetOrigin = return_origin) as the fallback
// when no return_url is given.
(function () {
  "use strict";

  var $ = function (id) { return document.getElementById(id); };

  // --- Parse + validate the fragment ---------------------------------------
  var params = new URLSearchParams((location.hash || "").replace(/^#/, ""));
  var email = (params.get("email") || "").trim().toLowerCase();
  var devicePubkey = params.get("device_pubkey") || "";
  var configPubkey = params.get("config_pubkey") || "";
  var returnUrl = params.get("return_url") || "";
  var returnOriginRaw = params.get("return_origin") || "";
  var returnOrigin = null;
  try {
    if (returnOriginRaw) {
      var u = new URL(returnOriginRaw);
      if (u.protocol === "https:" || u.protocol === "http:") returnOrigin = u.origin;
    }
  } catch (e) { /* invalid */ }
  // The certs certify the fragment's pubkeys, so the return_url delivery
  // lane must never navigate to a foreign origin: honor return_url only
  // when it is same-origin with the validated return_origin (bean 9it0).
  if (returnUrl) {
    try {
      if (!returnOrigin || new URL(returnUrl).origin !== returnOrigin) returnUrl = "";
    } catch (e) { returnUrl = ""; }
  }
  // Drop the fragment from the address bar (defense in depth).
  try { history.replaceState(null, "", location.pathname + location.search); } catch (e) {}

  function post(type, extra) {
    if (!returnOrigin || !window.opener) return;
    var msg = { type: type };
    if (extra) for (var k in extra) msg[k] = extra[k];
    window.opener.postMessage(msg, returnOrigin);
  }

  function fail(reason) {
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
    setTimeout(function () { window.close(); }, 100);
  }

  function api(path, body) {
    var opts = { credentials: "same-origin", headers: { accept: "application/json" } };
    if (body) {
      opts.method = "POST";
      opts.headers["content-type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    return fetch(path, opts).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (j) {
        return { ok: r.ok, status: r.status, body: j };
      });
    });
  }

  // --- Screens --------------------------------------------------------------
  function show(id) {
    ["confirm-form", "login-form", "verify-form", "fatal"].forEach(function (s) {
      $(s).classList.toggle("hidden", s !== id);
    });
  }

  function fatal(msg) {
    $("fatal-msg").textContent = msg;
    show("fatal");
  }

  function showLogin(err) {
    $("title").textContent = "Sign in";
    $("subtitle").textContent = "Enter your password to authorize this device for " + email + ".";
    show("login-form");
    if (err) $("login-err").textContent = err;
    $("password").focus();
  }

  function showConfirm() {
    $("title").textContent = "Authorize this device?";
    $("subtitle").textContent = "A device is asking to sign in as " + email + ".";
    show("confirm-form");
  }

  // --- Issuance over the session core ---------------------------------------
  // /device/issue enforces ownership + the mint chokepoint server-side; no
  // holder is passed, so the issuer assigns a fresh one — the device is the
  // WALLET that opened this page, never this browser session
  // (fallback-idp-api-v1 §3.2).
  function issueCerts() {
    return api("/wsapi/session_context").then(function (ctx) {
      if (!ctx.body.authenticated || !ctx.body.csrf_token) {
        var e = new Error("not signed in");
        e.step_up = true;
        throw e;
      }
      return api("/device/issue", {
        csrf: ctx.body.csrf_token,
        email: email,
        device_pubkey: devicePubkey,
        config_pubkey: configPubkey,
      });
    }).then(function (res) {
      if (res && res.ok && res.body.device_cert) return res.body;
      var reason = (res && res.body && res.body.reason) || "issuance failed";
      var err = new Error(reason);
      // 401 = the chokepoint wants the account password (step-up); a stale
      // SMTP verification (uboq) re-runs the mailbox ceremony; anything
      // else is a policy refusal the wallet should hear about.
      err.step_up = res && res.status === 401;
      err.reverify = res && res.status === 403 && /verification expired/i.test(reason);
      throw err;
    });
  }

  function issueAndDeliver() {
    return issueCerts().then(deliver).catch(function (e) {
      if (e.step_up) { showLogin(""); return; }
      if (e.reverify) { startReverify(); return; }
      // Refused at the chokepoint (wrong account, primary identity, …):
      // tell the wallet, and show the reason here too.
      fatal(String(e.message || e));
      fail("policy_refused");
    });
  }

  // --- Stale verification (uboq): fresh mailbox code, then retry ------------
  function startReverify() {
    api("/wsapi/session_context").then(function (ctx) {
      return api("/wsapi/stage_email", { email: email, csrf: ctx.body.csrf_token || "" });
    }).then(function (res) {
      if (!res.ok || !res.body.success) {
        throw new Error(res.body.reason || "could not send a verification code");
      }
      $("title").textContent = "Check your email";
      $("subtitle").textContent =
        "It has been a while — we sent a fresh verification code to " + email + ".";
      show("verify-form");
      $("code").focus();
    }).catch(function (e) {
      fatal(String(e.message || e));
      fail("policy_refused");
    });
  }

  // --- Preconditions --------------------------------------------------------
  if (!email || !devicePubkey || !configPubkey || !returnOrigin) {
    fatal("This sign-in link is malformed. Close this window and try again.");
    return;
  }
  $("subtitle").textContent = "Signing in as " + email;

  // A live session skips the password but NEVER the human: issuance needs an
  // explicit click (bean mxcn — a session-holding visitor merely loading
  // this page must not mint).
  api("/wsapi/session_context").then(function (ctx) {
    if (ctx.body.authenticated) {
      showConfirm();
    } else {
      showLogin("");
    }
  }).catch(function () { showLogin(""); });

  $("confirm-form").addEventListener("submit", function (e) {
    e.preventDefault();
    $("confirm-btn").disabled = true;
    issueAndDeliver();
  });
  $("confirm-cancel").addEventListener("click", function () { fail("cancelled"); });
  $("login-cancel").addEventListener("click", function () { fail("cancelled"); });
  $("verify-cancel").addEventListener("click", function () { fail("cancelled"); });

  $("verify-form").addEventListener("submit", function (e) {
    e.preventDefault();
    var btn = $("verify-btn");
    btn.disabled = true;
    $("verify-err").textContent = "";
    api("/wsapi/session_context").then(function (ctx) {
      return api("/wsapi/complete_email_addition", {
        email: email,
        token: $("code").value.trim(),
        csrf: ctx.body.csrf_token || "",
      });
    }).then(function (res) {
      if (!res.ok || !res.body.success) {
        throw new Error(res.body.reason || "wrong or expired code");
      }
      return issueAndDeliver();
    }).catch(function (err) {
      $("verify-err").textContent = String(err.message || err);
      btn.disabled = false;
    });
  });

  $("login-form").addEventListener("submit", function (e) {
    e.preventDefault();
    var btn = $("login-btn");
    btn.disabled = true;
    $("login-err").textContent = "";
    api("/wsapi/authenticate_user", { email: email, pass: $("password").value })
      .then(function (res) {
        if (!res.ok || !res.body.success) {
          throw new Error(res.body.reason || "sign-in failed");
        }
        return issueAndDeliver();
      })
      .catch(function (err) {
        $("login-err").textContent = String(err.message || err);
        btn.disabled = false;
      });
  });
})();
