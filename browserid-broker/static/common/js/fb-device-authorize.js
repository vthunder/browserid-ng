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
    ["confirm-form", "login-form", "verify-form", "bridge-form", "fatal"].forEach(function (s) {
      $(s).classList.toggle("hidden", s !== id);
    });
  }

  // A refusal the user can actually READ: show the message and only return
  // the device_error to the wallet when they dismiss it (the old
  // navigate-immediately behavior reduced every refusal to a red flash).
  var fatalReason = null;
  function fatal(msg, reason) {
    $("fatal-msg").textContent = msg;
    fatalReason = reason || null;
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
      // A bridge-verified identity refused for want of a live bridge proof:
      // run the bridge hop rather than giving up (defensive — the proof
      // route below normally catches this before issuance is attempted).
      if (bridge.claim && /bridge proof/i.test(String(e.message || ""))) {
        showBridge("");
        return;
      }
      // Refused at the chokepoint (wrong account, primary identity, …):
      // show the reason; the device_error returns when the user dismisses.
      fatal(String(e.message || e), "policy_refused");
    });
  }

  // --- Bridge-verified identities (Google / Bluesky) ------------------------
  // The mint bar for these is a LIVE bridge proof (fallback-idp-api-v1
  // §3.2: "bridge proof" is this page's own UX obligation) — a password
  // session is deliberately not enough. The proof runs in a popup at the
  // bridge, exactly as the login dialog does it; the button click is also
  // the consent gesture, so no separate confirm screen.
  var bridge = { proof: null, claim: null };
  // Set when a password confirm must be followed by something other than
  // direct issuance (the bridge attach leg, kts0).
  var afterLogin = null;

  function providerName() {
    return bridge.proof === "atproto" ? "Bluesky" : "Google";
  }

  function showBridge(err) {
    $("title").textContent = "Authorize this device?";
    $("subtitle").textContent = "A device is asking to sign in as " + email +
      ". Continue with " + providerName() + " to approve it.";
    $("bridge-btn").textContent = "Continue with " + providerName();
    $("bridge-btn").disabled = false;
    show("bridge-form");
    if (err) $("bridge-err").textContent = err;
  }

  function normalizeGoogleEmail(e) {
    var lower = String(e || "").toLowerCase();
    var at = lower.lastIndexOf("@");
    if (at < 0) return lower;
    var local = lower.slice(0, at);
    var domain = lower.slice(at + 1);
    if (domain === "gmail.com" || domain === "googlemail.com") {
      local = local.split("+")[0].replace(/\./g, "");
    }
    return local + "@" + domain;
  }

  // Google: popup to /oidc/claim (302 → Google). COOP severs the window
  // handle, so the result arrives on the dialog's same-origin
  // BroadcastChannel from the broker's resume page.
  function oidcPopup() {
    return new Promise(function (resolve, reject) {
      var popup = window.open(bridge.claim + "?email=" + encodeURIComponent(email),
        "browserid_oidc_claim", "width=600,height=700");
      if (!popup) return reject(new Error("The sign-in window was blocked. Allow popups and try again."));
      var chan;
      try { chan = new BroadcastChannel("browserid:oidc_claim_resume"); }
      catch (e) { try { popup.close(); } catch (e2) {} return reject(new Error("This browser cannot complete the sign-in.")); }
      var settled = false;
      var tid = setTimeout(function () { finish(new Error("Timed out waiting for " + providerName() + " sign-in")); }, 3 * 60 * 1000);
      function finish(err) {
        if (settled) return;
        settled = true;
        clearTimeout(tid);
        try { chan.close(); } catch (e) {}
        if (err) reject(err); else resolve();
      }
      chan.onmessage = function (ev) {
        var m = ev.data || {};
        if (m.type !== "browserid:oidc_claim_result") return;
        var anonymousError = !m.ok && !m.email;
        if (!anonymousError && normalizeGoogleEmail(m.email) !== normalizeGoogleEmail(email)) return;
        try { chan.postMessage({ type: "browserid:oidc_claim_ack", nonce: m.nonce }); } catch (e) {}
        if (m.ok) finish(null);
        else finish(new Error(m.reason || providerName() + " sign-in failed"));
      };
    });
  }

  // Bluesky: popup to the bridge's claim page (fragment contract), which
  // postMessages an attestation back; redeem it at the broker.
  function atprotoPopup() {
    return new Promise(function (resolve, reject) {
      var claimOrigin;
      try { claimOrigin = new URL(bridge.claim).origin; }
      catch (e) { return reject(new Error("The verification service is unavailable.")); }
      var url = bridge.claim +
        "#email=" + encodeURIComponent(email) +
        "&return_origin=" + encodeURIComponent(window.location.origin);
      var popup = window.open(url, "browserid_handle_claim", "width=600,height=700");
      if (!popup) return reject(new Error("The sign-in window was blocked. Allow popups and try again."));
      var settled = false;
      var tid = setTimeout(function () { finish(new Error("Timed out waiting for Bluesky verification")); }, 3 * 60 * 1000);
      function finish(err, attestation) {
        if (settled) return;
        settled = true;
        clearTimeout(tid);
        window.removeEventListener("message", onMessage);
        if (err) reject(err); else resolve(attestation);
      }
      function onMessage(ev) {
        if (ev.origin !== claimOrigin) return;
        var d = ev.data || {};
        if (d.email && String(d.email).toLowerCase() !== email) return;
        if (d.type === "browserid:handle_attestation") finish(null, d.attestation);
        else if (d.type === "browserid:handle_error") finish(new Error(d.reason || "handle verification failed"));
      }
      window.addEventListener("message", onMessage);
    });
  }

  function runBridge() {
    $("bridge-btn").disabled = true;
    $("bridge-err").textContent = "";
    var hop = bridge.proof === "atproto"
      ? atprotoPopup().then(function (attestation) {
          return api("/wsapi/session_context").then(function (ctx) {
            return api("/wsapi/complete_handle_claim", {
              email: email, attestation: attestation, csrf: (ctx.body.csrf_token || ""),
            });
          }).then(function (res) {
            if (!res.ok || res.body.success === false) {
              throw new Error(res.body.reason || "handle verification failed");
            }
          });
        })
      : oidcPopup();
    hop.then(function () {
      // The claim attached/created the broker session and recorded the mint
      // grant — issuance can now consume it.
      return issueAndDeliver();
    }).catch(function (e) {
      // A password-backed account links the bridge only after a password
      // confirm (kts0): collect it, then re-run the bridge hop.
      if (/password required/i.test(String(e.message || ""))) {
        afterLogin = function () { showBridge(""); };
        showLogin("Confirm your password first, then continue with " + providerName() + ".");
        return;
      }
      showBridge(String(e.message || e));
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
      fatal(String(e.message || e), "policy_refused");
    });
  }

  // --- Preconditions --------------------------------------------------------
  if (!email || !devicePubkey || !configPubkey || !returnOrigin) {
    fatal("This sign-in link is malformed. Close this window and try again.");
    return;
  }
  $("subtitle").textContent = "Signing in as " + email;

  // Route by how the identity is verified (opaque to the wallet that opened
  // us — fallback-idp-api-v1 §3.2 makes this the page's own business):
  // bridge-verified → the bridge hop (its click is the consent gesture);
  // otherwise a live session skips the password but NEVER the human —
  // issuance needs an explicit click (bean mxcn).
  Promise.all([
    api("/wsapi/session_context"),
    api("/wsapi/address_info?email=" + encodeURIComponent(email))
      .catch(function () { return { ok: false, body: {} }; }),
  ]).then(function (res) {
    var ctx = res[0], info = res[1].body || {};
    if (info.proof === "oidc" || info.proof === "atproto") {
      bridge.proof = info.proof;
      bridge.claim = info.claim || null;
      if (bridge.claim) { showBridge(""); return; }
      // Bridge unavailable: fall through — issuance will refuse and the
      // reason shows readably instead of a dead button.
    }
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
  $("bridge-cancel").addEventListener("click", function () { fail("cancelled"); });
  $("bridge-form").addEventListener("submit", function (e) {
    e.preventDefault();
    runBridge();
  });
  $("fatal-close").addEventListener("click", function () {
    if (fatalReason) { fail(fatalReason); return; }
    try { window.close(); } catch (e) {}
  });

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
        if (afterLogin) {
          var next = afterLogin;
          afterLogin = null;
          next();
          return;
        }
        return issueAndDeliver();
      })
      .catch(function (err) {
        $("login-err").textContent = String(err.message || err);
        btn.disabled = false;
      });
  });
})();
