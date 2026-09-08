// The registry login page (registry-api-v1 §4.2 `login_page`).
//
// A wallet opens this with a URL fragment
//   #account=…&return_url=…&return_origin=…
// The page authenticates the user as this registry chooses — the account
// password — and ends with
//   return_url#login=<one-time token>     signed in
//   return_url#login_error=<reason>       refused / cancelled
// The wallet spends the token at POST /api/v1/login.
(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };

  var params = new URLSearchParams((location.hash || "").replace(/^#/, ""));
  var account = (params.get("account") || "").trim();
  var returnUrl = params.get("return_url") || "";
  var returnOriginRaw = params.get("return_origin") || "";
  try { history.replaceState(null, "", location.pathname + location.search); } catch (e) {}

  // Same-origin rule between return_origin and return_url (§4.2). No
  // allowlist: the token is one-time and bound to the account.
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
      var msg = { type: "browserid:login" };
      fragment.split("&").forEach(function (kv) {
        var i = kv.indexOf("="); msg[kv.slice(0, i)] = decodeURIComponent(kv.slice(i + 1));
      });
      window.opener.postMessage(msg, returnOrigin);
      setTimeout(function () { window.close(); }, 100);
    }
  }
  function fail(reason) { finish("login_error=" + encodeURIComponent(reason)); }
  function fatal(msg) { $("password-form").classList.add("hidden"); $("fatal").classList.remove("hidden"); $("fatal-msg").textContent = msg; }

  if (!account || !returnOrigin) {
    fatal("This sign-in link is malformed. Close this window and try again.");
    return;
  }

  $("password-form").addEventListener("submit", function (e) {
    e.preventDefault();
    var btn = $("password-btn");
    btn.disabled = true;
    $("password-err").textContent = "";
    fetch("/wsapi/registry_login", {
      method: "POST", credentials: "same-origin",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ account: account, password: $("password").value }),
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (j) {
        btn.disabled = false;
        if (r.ok && j.login) { finish("login=" + encodeURIComponent(j.login)); return; }
        $("password-err").textContent = r.status === 429 ? "Too many attempts. Try again later." : "That didn't work. Check the password and try again.";
      });
    });
  });
  $("password-cancel").addEventListener("click", function () { fail("cancelled"); });
})();
