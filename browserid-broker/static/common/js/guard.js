// The registry guard page (registry-api-v1 §4.2 `page`; bean 0c49 step 5).
//
// A wallet opens this with a URL fragment
//   #certs=<jws>[,<jws>]&identity=…&return_url=…&return_origin=…
// The page shows the identity and every key fingerprint, requires an
// explicit user action, and ends with
//   return_url#guard=<token>          passed
//   return_url#guard_error=<reason>   refused / cancelled
// The check is this registry's own: a live browserid.me session on the
// account holding the identity (one click), or the account password.
// Ambient credentials alone never complete it — the click does.
(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };

  var params = new URLSearchParams((location.hash || "").replace(/^#/, ""));
  var certs = (params.get("certs") || "").split(",").filter(Boolean);
  var identity = (params.get("identity") || "").trim().toLowerCase();
  var returnUrl = params.get("return_url") || "";
  var returnOriginRaw = params.get("return_origin") || "";
  try { history.replaceState(null, "", location.pathname + location.search); } catch (e) {}

  // Same-origin rule between return_origin and return_url (§4.2: the page
  // MUST validate return_origin). No allowlist: a stranger opening this
  // page with someone's certs cannot spend the token they get back.
  var returnOrigin = null;
  (function () {
    var m = /^([A-Za-z][A-Za-z0-9+.-]*):\/\/([^\/?#]+)$/.exec(returnOriginRaw.trim());
    if (!m) return;
    var scheme = m[1].toLowerCase();
    if (scheme !== "http" && scheme !== "https") { returnOrigin = scheme + "://" + m[2]; return; }
    try { returnOrigin = new URL(scheme + "://" + m[2]).origin; } catch (e) {}
  })();
  function sameOrigin(url) {
    if (!returnOrigin) return false;
    var m = /^([A-Za-z][A-Za-z0-9+.-]*):\/\/([^\/?#]+)/.exec(url);
    if (!m) return false;
    var scheme = m[1].toLowerCase();
    if (scheme !== "http" && scheme !== "https") return (scheme + "://" + m[2]) === returnOrigin;
    try { return new URL(url).origin === returnOrigin; } catch (e) { return false; }
  }
  if (returnUrl && !sameOrigin(returnUrl)) returnUrl = "";

  function finish(fragment) {
    if (returnUrl) {
      var sep = returnUrl.indexOf("#") === -1 ? "#" : "&";
      location.replace(returnUrl + sep + fragment);
      return;
    }
    if (window.opener && returnOrigin && /^https?:/.test(returnOrigin)) {
      var msg = { type: "browserid:guard" };
      fragment.split("&").forEach(function (kv) {
        var i = kv.indexOf("="); msg[kv.slice(0, i)] = decodeURIComponent(kv.slice(i + 1));
      });
      window.opener.postMessage(msg, returnOrigin);
      setTimeout(function () { window.close(); }, 100);
    }
  }
  function fail(reason) { finish("guard_error=" + encodeURIComponent(reason)); }
  function show(id) {
    ["approve-form", "password-form", "fatal"].forEach(function (s) { $(s).classList.toggle("hidden", s !== id); });
  }
  function fatal(msg) { $("fatal-msg").textContent = msg; show("fatal"); }

  if (!identity || !certs.length || certs.length > 2 || !returnOrigin) {
    fatal("This approval link is malformed. Close this window and try again.");
    return;
  }
  $("subtitle").textContent = "A device is asking to join your account as " + identity + ".";

  // Fingerprints = kid: base64url(SHA-256(raw public key)), from each
  // cert's `public-key` claim.
  function b64urlToBytes(s) {
    s = s.replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "=";
    var bin = atob(s), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  function bytesToB64url(buf) {
    var s = ""; var b = new Uint8Array(buf);
    for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  certs.forEach(function (jws) {
    var li = document.createElement("li");
    li.innerHTML = "<code>…</code>";
    $("fingerprints").appendChild(li);
    try {
      var payload = JSON.parse(new TextDecoder().decode(b64urlToBytes(jws.split(".")[1])));
      var pk = payload["public-key"];
      var purpose = payload.purpose === "authorization" ? "authorize warrants" : "sign in";
      crypto.subtle.digest("SHA-256", b64urlToBytes(pk)).then(function (d) {
        li.innerHTML = "<code>" + bytesToB64url(d) + "</code> <span class=\"muted\">(" + purpose + ")</span>";
      });
    } catch (e) { li.innerHTML = "<code>unreadable cert</code>"; }
  });

  function api(path, body) {
    return fetch(path, {
      method: "POST", credentials: "same-origin",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify(body),
    }).then(function (r) { return r.json().catch(function () { return {}; }).then(function (j) { return { ok: r.ok, status: r.status, body: j }; }); });
  }
  function mint(password) {
    var body = { identity: identity, certs: certs };
    if (password) body.password = password;
    return api("/wsapi/guard", body);
  }

  // A live session on this account? Then one click; else the password.
  fetch("/wsapi/session_context", { credentials: "same-origin" })
    .then(function (r) { return r.json(); })
    .then(function (ctx) { show(ctx && ctx.authenticated ? "approve-form" : "password-form"); })
    .catch(function () { show("password-form"); });

  $("approve-form").addEventListener("submit", function (e) {
    e.preventDefault();
    $("approve-btn").disabled = true;
    mint(null).then(function (res) {
      if (res.ok && res.body.guard) { finish("guard=" + encodeURIComponent(res.body.guard)); return; }
      // The session is not on the account that holds this identity:
      // fall back to the password.
      $("approve-btn").disabled = false;
      show("password-form");
      $("password").focus();
    });
  });
  $("password-form").addEventListener("submit", function (e) {
    e.preventDefault();
    $("password-btn").disabled = true;
    $("password-err").textContent = "";
    mint($("password").value).then(function (res) {
      $("password-btn").disabled = false;
      if (res.ok && res.body.guard) { finish("guard=" + encodeURIComponent(res.body.guard)); return; }
      $("password-err").textContent = res.status === 429 ? "Too many attempts. Try again later." : "That didn't work. Check the password and try again.";
    });
  });
  $("approve-cancel").addEventListener("click", function () { fail("cancelled"); });
  $("password-cancel").addEventListener("click", function () { fail("cancelled"); });
})();
