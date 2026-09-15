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
    $("password-form").classList.add("hidden"); $("approval").classList.add("hidden"); $("proofs").classList.add("hidden");
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
      if (r.ok && r.data.login) { dropApproval(); finish("login=" + encodeURIComponent(r.data.login)); return; }
      $("password-err").textContent = r.status === 429 ? "Too many attempts. Try again later." : "That didn't work. Check the password and try again.";
    });
  });
  $("password-cancel").addEventListener("click", function () { dropApproval(); fail("cancelled"); });

  // --- Method 2: approval from a device already signed in (§5.2.8) --------
  var approval = { id: null, timer: null, deadline: 0 };
  function stopPolling() { if (approval.timer) { clearTimeout(approval.timer); approval.timer = null; } }
  // Leaving the approval any way but through it: cancel so no device keeps
  // seeing a request that can no longer matter.
  function dropApproval() {
    stopPolling();
    if (approval.id) {
      fetch("/api/v1/approvals/" + encodeURIComponent(approval.id) + "/cancel", { method: "POST", credentials: "same-origin" }).catch(function () {});
      approval.id = null;
    }
  }
  function showPassword() {
    dropApproval();
    $("approval").classList.add("hidden");
    $("proofs").classList.add("hidden");
    $("password-form").classList.remove("hidden");
    try { $("password").focus(); } catch (e) {}
  }
  function showApproval() {
    $("password-form").classList.add("hidden");
    $("proofs").classList.add("hidden");
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
        if (j.status === "approved" && j.login) { stopPolling(); approval.id = null; finish("login=" + encodeURIComponent(j.login)); return; }
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
  $("approval-cancel").addEventListener("click", function () { dropApproval(); fail("cancelled"); });

  // --- Method 3: proofs of the account's identities (bean d26p) ---------
  // The page asks the wallet (navigator.id, answered by the native wallet
  // inside its own window, or by the browserid dialog) for a presentation
  // per identity; one proof unlocks masked hints for the rest; enough
  // proofs earn the token.
  var proofs = { presentations: [], proven: [], hints: [], needed: 0, watching: false };
  function proofsUi() {
    var list = $("proofs-list");
    list.innerHTML = "";
    proofs.proven.forEach(function (p) {
      var li = document.createElement("li"); li.className = "done";
      li.innerHTML = '<span class="tick">✓</span><span></span>';
      li.querySelector("span:nth-child(2)").textContent = p;
      list.appendChild(li);
    });
    proofs.hints.forEach(function (h) {
      var li = document.createElement("li");
      li.innerHTML = '<span class="tick"></span><span></span><button type="button">Sign in</button>';
      li.querySelector("span:nth-child(2)").textContent = h;
      li.querySelector("button").addEventListener("click", function () { askWallet(h); });
      list.appendChild(li);
    });
    var left = Math.max(0, proofs.needed - proofs.proven.length);
    $("proofs-lead").textContent = proofs.proven.length === 0
      ? "Sign in with the addresses on this account. Your wallet answers each one."
      : (left > 0 ? "One more: sign in with " + (left === 1 ? "one" : left) + " of the addresses below." : "That's enough. Signing you in…");
    $("proofs-start").classList.toggle("hidden", proofs.proven.length > 0);
  }
  function showProofs() {
    $("password-form").classList.add("hidden");
    $("approval").classList.add("hidden");
    $("proofs").classList.remove("hidden");
    $("proofs-err").textContent = "";
    if (!(navigator.id && typeof navigator.id.request === "function")) {
      $("proofs-err").textContent = "No wallet answered on this page. Use the password instead.";
      $("proofs-start").disabled = true;
      return;
    }
    if (!proofs.watching) {
      proofs.watching = true;
      try { navigator.id.watch({ onlogin: function () {}, onlogout: function () {} }); } catch (e) {}
    }
    proofsUi();
  }
  function askWallet(hint) {
    $("proofs-err").textContent = "";
    $("proofs-wait").classList.remove("hidden");
    var args = { siteName: "browserid.me account" };
    // A masked hint is not an address; the wallet picks the identity that
    // matches it, or asks the person.
    if (hint) args.hint = hint;
    var p;
    try { p = navigator.id.request("login", args); } catch (e) { p = Promise.reject(e); }
    if (!p || typeof p.then !== "function") p = Promise.reject(new Error("the wallet on this page cannot answer requests"));
    p.then(function (r) {
      var pres = r && r.presentation;
      if (!pres) throw new Error("no presentation");
      proofs.presentations.push(pres);
      return postJson("/wsapi/registry_login_hints", { account: account, presentations: proofs.presentations });
    }).then(function (r) {
      $("proofs-wait").classList.add("hidden");
      if (!r.ok) { proofs.presentations.pop(); $("proofs-err").textContent = "That sign-in did not prove an address on this account."; return; }
      proofs.proven = r.data.proven || []; proofs.hints = r.data.hints || []; proofs.needed = r.data.needed || 1;
      proofsUi();
      if (proofs.proven.length >= proofs.needed) {
        return postJson("/wsapi/registry_login_proofs", { account: account, presentations: proofs.presentations }).then(function (t) {
          if (t.ok && t.data.login) { finish("login=" + encodeURIComponent(t.data.login)); return; }
          $("proofs-err").textContent = "That didn't work. Try the password instead.";
        });
      }
    }).catch(function (e) {
      $("proofs-wait").classList.add("hidden");
      $("proofs-err").textContent = (e && e.error === "cancelled") ? "" : "The wallet did not answer. Try again, or use the password.";
    });
  }
  $("to-proofs").addEventListener("click", showProofs);
  $("to-password-2").addEventListener("click", showPassword);
  $("proofs-start").addEventListener("click", function () { askWallet(null); });
  $("proofs-cancel").addEventListener("click", function () { fail("cancelled"); });
  if (startWith === "approval") showApproval();
  if (startWith === "proofs") showProofs();
})();
