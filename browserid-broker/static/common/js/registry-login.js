// The registry login page (registry-api-v1 §4.2 `login_page`).
//
// A wallet opens this with a URL fragment
//   #account=…&return_url=…&return_origin=…
// The page authenticates the user as this registry chooses — the account
// password, or approval from a device already signed in (§5.2.8) — and
// ends with
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
  var startWith = params.get("method") || "";
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
  function fatal(msg) {
    $("password-form").classList.add("hidden"); $("approval").classList.add("hidden");
    $("fatal").classList.remove("hidden"); $("fatal-msg").textContent = msg;
  }
  function postJson(path, body) {
    return fetch(path, {
      method: "POST", credentials: "same-origin",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify(body),
    }).then(function (r) { return r.json().catch(function () { return {}; }).then(function (j) { return { ok: r.ok, status: r.status, data: j }; }); });
  }

  if (!account || !returnOrigin) {
    fatal("This sign-in link is malformed. Close this window and try again.");
    return;
  }

  // --- Method 1: the account password ------------------------------------
  $("password-form").addEventListener("submit", function (e) {
    e.preventDefault();
    var btn = $("password-btn");
    btn.disabled = true;
    $("password-err").textContent = "";
    postJson("/wsapi/registry_login", { account: account, password: $("password").value }).then(function (r) {
      btn.disabled = false;
      if (r.ok && r.data.login) { finish("login=" + encodeURIComponent(r.data.login)); return; }
      $("password-err").textContent = r.status === 429 ? "Too many attempts. Try again later." : "That didn't work. Check the password and try again.";
    });
  });
  $("password-cancel").addEventListener("click", function () { fail("cancelled"); });

  // --- Method 2: approval from a device already signed in (§5.2.8) --------
  var approval = { id: null, timer: null, deadline: 0 };
  function stopPolling() { if (approval.timer) { clearTimeout(approval.timer); approval.timer = null; } }
  function showPassword() {
    stopPolling();
    $("approval").classList.add("hidden");
    $("password-form").classList.remove("hidden");
    try { $("password").focus(); } catch (e) {}
  }
  function showApproval() {
    $("password-form").classList.add("hidden");
    $("approval").classList.remove("hidden");
    $("approval-err").textContent = "";
    $("approval-wait").classList.remove("hidden");
    $("approval-code").textContent = "···-···";
    postJson("/api/v1/approvals", { account: account }).then(function (r) {
      if (!(r.ok && r.data.id && r.data.code)) {
        $("approval-wait").classList.add("hidden");
        $("approval-err").textContent = r.status === 403 ? "Too many devices are waiting for this account. Try again in a few minutes." : "Couldn't start an approval. Try the password instead.";
        return;
      }
      approval.id = r.data.id;
      approval.deadline = Date.parse(r.data.expires_at) || (Date.now() + 5 * 60 * 1000);
      $("approval-code").textContent = r.data.code;
      poll();
    });
  }
  function poll() {
    if (!approval.id) return;
    if (Date.now() > approval.deadline) { expired(); return; }
    fetch("/api/v1/approvals/" + encodeURIComponent(approval.id), { credentials: "same-origin", headers: { accept: "application/json" } })
      .then(function (r) { return r.json().catch(function () { return {}; }); })
      .then(function (j) {
        if (!approval.id) return;
        if (j.status === "approved" && j.login) { stopPolling(); finish("login=" + encodeURIComponent(j.login)); return; }
        if (j.status === "denied") { stopPolling(); approval.id = null; $("approval-wait").classList.add("hidden"); $("approval-err").textContent = "That device said no."; return; }
        if (j.status === "expired") { expired(); return; }
        approval.timer = setTimeout(poll, 2000);
      }, function () { approval.timer = setTimeout(poll, 4000); });
  }
  function expired() {
    stopPolling(); approval.id = null;
    $("approval-wait").classList.add("hidden");
    $("approval-err").textContent = "That code expired. Go back and try again.";
  }
  $("to-approval").addEventListener("click", showApproval);
  $("to-password").addEventListener("click", showPassword);
  $("approval-cancel").addEventListener("click", function () { stopPolling(); fail("cancelled"); });
  if (startWith === "approval") showApproval();
})();
