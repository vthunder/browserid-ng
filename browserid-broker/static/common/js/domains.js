// Hosted-primary onboarding + admin console (bean g5qt).
//
// Two views off one page:
//   /domains           → list your domains + "add a domain" wizard
//   /domains/<domain>  → that tenant's admin console (roster, admins)
// All privileged calls carry the broker session CSRF token. The add-domain
// wizard IS the roadmap's record generator + DNSSEC checker: publishing the
// generated record is the proof of domain control that seats first admin.
(function () {
  "use strict";

  var app = document.getElementById("app");
  var signedOut = document.getElementById("signed-out");
  var csrf = null;
  var identities = [];

  function esc(s) { return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
    return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
  }); }

  function getJSON(url) { return fetch(url, { credentials: "same-origin" }).then(function (r) { return r.json(); }); }
  function postJSON(url, body) {
    return fetch(url, {
      method: "POST", credentials: "same-origin",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    }).then(function (r) { return r.json().then(function (j) { return { ok: r.ok, body: j }; }); });
  }

  function currentDomain() {
    var m = location.pathname.match(/^\/domains\/([^/]+)/);
    return m ? decodeURIComponent(m[1]).toLowerCase() : null;
  }

  // --- Boot ----------------------------------------------------------------
  Promise.all([getJSON("/wsapi/session_context"), getJSON("/wsapi/list_emails")])
    .then(function (res) {
      var ctx = res[0], emails = res[1];
      if (!ctx || !ctx.authenticated) { signedOut.classList.remove("hidden"); return; }
      csrf = ctx.csrf_token;
      identities = (emails && emails.emails) || [];
      app.classList.remove("hidden");
      var domain = currentDomain();
      if (domain) renderConsole(domain); else renderList();
    })
    .catch(function () { signedOut.classList.remove("hidden"); });

  // --- List view + add-domain wizard --------------------------------------
  function renderList() {
    app.innerHTML =
      '<h1>Your domains</h1>' +
      '<p class="muted">Run browserid.me as the identity provider for a domain you control. ' +
      'Add a domain, publish one DNS record, and every site that accepts browserid.me accepts your domain — no other setup.</p>' +
      '<div id="list"></div>' +
      '<h2>Add a domain</h2>' +
      '<div class="card" id="wizard"></div>';
    loadList();
    renderWizard();
  }

  function loadList() {
    var el = document.getElementById("list");
    getJSON("/wsapi/tenant/list").then(function (j) {
      var tenants = (j && j.tenants) || [];
      if (!tenants.length) { el.innerHTML = '<p class="muted">No domains yet.</p>'; return; }
      el.innerHTML = tenants.map(function (t) {
        var active = t.status === "active";
        return '<div class="card"><div class="row">' +
          '<div><strong>' + esc(t.domain) + '</strong> ' +
          '<span class="pill ' + (active ? "active" : "pending") + '">' + esc(t.status) + '</span></div>' +
          (active ? '<a class="ghost" href="/domains/' + encodeURIComponent(t.domain) + '"><button class="ghost">Manage</button></a>'
                  : '<button class="ghost" data-check="' + esc(t.domain) + '">Check DNS</button>') +
          '</div>' +
          (active ? '' : '<div class="record"><div class="muted">Publish this TXT record, then check DNS:</div>' +
            '<code>' + esc(t.record_name) + '</code><br><code>' + esc(t.record) + '</code>' +
            '<div class="err" data-status="' + esc(t.domain) + '"></div></div>') +
          '</div>';
      }).join("");
      Array.prototype.forEach.call(el.querySelectorAll("[data-check]"), function (btn) {
        btn.addEventListener("click", function () { checkDns(btn.getAttribute("data-check")); });
      });
    });
  }

  function checkDns(domain) {
    var msg = document.querySelector('[data-status="' + CSS.escape(domain) + '"]');
    if (msg) { msg.className = "err"; msg.textContent = "Checking…"; }
    postJSON("/wsapi/tenant/check", { csrf: csrf, domain: domain }).then(function (res) {
      if (!msg) return;
      var b = res.body || {};
      if (b.dns === "validated" && b.status === "active") {
        msg.className = "err ok"; msg.textContent = "Verified — domain is active. Reloading…";
        setTimeout(loadList, 900);
      } else {
        msg.className = "err";
        msg.textContent = dnsMessage(b.dns, b.host_ok);
      }
    });
  }

  function dnsMessage(dns, hostOk) {
    switch (dns) {
      case "no_record": return "No _browserid record found yet. DNS can take a while to propagate.";
      case "insecure": return "The record isn't DNSSEC-signed. A hosted primary requires DNSSEC on the zone.";
      case "bogus": return "DNSSEC validation failed (broken chain). Check your signing setup.";
      case "wrong_key": return "A record is present but carries a different key. Make sure you published this exact record.";
      case "validated": return hostOk === false ? "Key matches, but host= doesn't point here yet." : "Verified.";
      default: return "Could not determine DNS status.";
    }
  }

  function genPassword() {
    // Readable, unambiguous alphabet; ~72 bits over 14 chars.
    var alphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    var bytes = new Uint8Array(14);
    (window.crypto || window.msCrypto).getRandomValues(bytes);
    var out = "";
    for (var i = 0; i < bytes.length; i++) out += alphabet[bytes[i] % alphabet.length];
    return out;
  }

  function renderWizard() {
    var w = document.getElementById("wizard");
    var opts = identities.map(function (e) { return '<option value="' + esc(e) + '">' + esc(e) + '</option>'; }).join("");
    w.innerHTML =
      '<label for="wiz-domain">Domain</label>' +
      '<input id="wiz-domain" placeholder="example.com" autocapitalize="off" autocorrect="off" />' +
      '<label for="wiz-id">Admin identity (manages this domain — becomes the first admin)</label>' +
      '<select id="wiz-id">' + opts + '</select>' +
      '<label for="wiz-user">First user at this domain</label>' +
      '<div class="toolbar" style="gap:8px">' +
        '<div style="flex:2"><input id="wiz-user" placeholder="alice" autocapitalize="off" autocorrect="off" /></div>' +
        '<div style="flex:2"><input id="wiz-pw" type="text" placeholder="password (min 8)" autocapitalize="off" autocorrect="off" /></div>' +
        '<div style="flex:0"><button id="wiz-gen" class="ghost" type="button">Generate</button></div>' +
      '</div>' +
      '<p class="muted" style="margin-top:6px">This login is created with the password above — no forced change on first sign-in. ' +
      'You can add more users (and require a change) from the console afterward.</p>' +
      '<div style="margin-top:16px"><button id="wiz-go">Generate DNS record</button></div>' +
      '<div class="err" id="wiz-err"></div>' +
      '<div id="wiz-out" class="hidden record"></div>';
    document.getElementById("wiz-gen").addEventListener("click", function () {
      document.getElementById("wiz-pw").value = genPassword();
    });
    document.getElementById("wiz-go").addEventListener("click", function () {
      var domain = document.getElementById("wiz-domain").value.trim().toLowerCase();
      var identity = document.getElementById("wiz-id").value;
      var user = document.getElementById("wiz-user").value.trim().toLowerCase();
      var pw = document.getElementById("wiz-pw").value;
      var err = document.getElementById("wiz-err");
      err.className = "err"; err.textContent = "";
      if (!domain) { err.textContent = "Enter a domain."; return; }
      if (!user) { err.textContent = "Enter a username for the first user."; return; }
      if (pw.length < 8) { err.textContent = "First user's password must be at least 8 characters."; return; }
      postJSON("/wsapi/tenant/create", { csrf: csrf, domain: domain, identity: identity }).then(function (res) {
        if (!res.ok || !res.body.success) { err.textContent = (res.body && res.body.reason) || "could not create"; return; }
        var out = document.getElementById("wiz-out");
        out.classList.remove("hidden");
        out.innerHTML =
          '<div class="muted">Publish this TXT record on your DNS (the zone must be DNSSEC-signed):</div>' +
          '<code>' + esc(res.body.record_name) + '</code><br><code>' + esc(res.body.record) + '</code>' +
          '<div class="muted" style="margin-top:8px">Publishing this record is what makes <strong>' + esc(identity) +
          '</strong> the admin for this domain. Your first user <strong>' + esc(user) + '@' + esc(domain) +
          '</strong> will be created when DNS verifies.</div>' +
          '<div style="margin-top:12px"><button id="wiz-check">Check DNS now</button></div>' +
          '<div class="err" id="wiz-check-err"></div>';
        document.getElementById("wiz-check").addEventListener("click", function () {
          var ce = document.getElementById("wiz-check-err");
          ce.className = "err"; ce.textContent = "Checking…";
          postJSON("/wsapi/tenant/check", { csrf: csrf, domain: domain }).then(function (r2) {
            var b = r2.body || {};
            if (b.dns === "validated" && b.status === "active") {
              ce.className = "err ok"; ce.textContent = "Verified — creating your first user…";
              // The admin chose this password, so no forced change on first login.
              postJSON("/wsapi/tenant/roster", {
                csrf: csrf, domain: domain, local_part: user, password: pw, require_password_change: false,
              }).then(function (r3) {
                if (!r3.ok || !r3.body.success) {
                  ce.className = "err"; ce.textContent = "Domain active, but the first user could not be created: " +
                    ((r3.body && r3.body.reason) || "unknown") + ". Add them from the console.";
                }
                setTimeout(function () { location.href = "/domains/" + encodeURIComponent(domain); }, 900);
              });
            } else {
              ce.className = "err"; ce.textContent = dnsMessage(b.dns, b.host_ok);
            }
          });
        });
      });
    });
  }

  // --- Admin console (per domain) -----------------------------------------
  function renderConsole(domain) {
    app.innerHTML =
      '<p class="backlink"><a href="/domains">← All domains</a></p>' +
      '<h1>' + esc(domain) + '</h1>' +
      '<div id="console-err" class="err"></div>' +
      '<h2>Users</h2>' +
      '<div class="card"><div class="toolbar">' +
        '<div><label for="nu-local">Username</label><input id="nu-local" placeholder="alice" autocapitalize="off" /></div>' +
        '<div><label for="nu-pw">Initial password</label><input id="nu-pw" type="text" placeholder="min 8 chars" /></div>' +
        '<div style="flex:0"><button id="nu-gen" class="ghost" type="button">Generate</button></div>' +
        '<div style="flex:0"><button id="nu-add">Add user</button></div>' +
      '</div>' +
      '<label style="font-weight:400;margin-top:10px"><input type="checkbox" id="nu-mc" checked style="width:auto;margin-right:6px" />' +
        'Require this user to change the password on first sign-in</label>' +
      '<div class="err" id="nu-err"></div></div>' +
      '<div id="roster"></div>' +
      '<h2>Administrators</h2>' +
      '<div id="admins" class="card"></div>' +
      '<div class="card"><div class="toolbar">' +
        '<div><label for="na-id">Add admin (an identity)</label><input id="na-id" placeholder="person@example.com" autocapitalize="off" /></div>' +
        '<div style="flex:0"><button id="na-add" class="ghost">Add admin</button></div>' +
      '</div><div class="err" id="na-err"></div></div>';

    document.getElementById("nu-add").addEventListener("click", function () { addUser(domain); });
    document.getElementById("nu-gen").addEventListener("click", function () {
      document.getElementById("nu-pw").value = genPassword();
    });
    document.getElementById("na-add").addEventListener("click", function () { addAdmin(domain); });
    loadRoster(domain);
  }

  function loadRoster(domain) {
    var q = "?domain=" + encodeURIComponent(domain) + "&csrf=" + encodeURIComponent(csrf);
    getJSON("/wsapi/tenant/roster" + q).then(function (j) {
      if (!j || !j.success) {
        document.getElementById("console-err").textContent =
          (j && j.reason) || "You are not an administrator of this domain.";
        return;
      }
      var el = document.getElementById("roster");
      var rows = (j.roster || []).map(function (r) {
        var disabled = r.state === "disabled";
        return '<tr>' +
          '<td><code>' + esc(r.email) + '</code></td>' +
          '<td>' + (disabled ? '<span class="pill">disabled</span>' : '<span class="pill active">active</span>') +
            (r.must_change_password ? ' <span class="muted">(must change pw)</span>' : '') + '</td>' +
          '<td class="muted">' + (r.last_login_at ? esc(r.last_login_at.slice(0, 10)) : "never") + '</td>' +
          '<td style="text-align:right">' +
            '<button class="ghost" data-reset="' + esc(r.local_part) + '">Reset pw</button> ' +
            '<button class="' + (disabled ? "ghost" : "danger") + '" data-toggle="' + esc(r.local_part) +
              '" data-to="' + (disabled ? "active" : "disabled") + '">' + (disabled ? "Enable" : "Disable") + '</button>' +
          '</td></tr>';
      }).join("");
      el.innerHTML = '<table><thead><tr><th>User</th><th>Status</th><th>Last login</th><th></th></tr></thead><tbody>' +
        (rows || '<tr><td colspan="4" class="muted">No users yet.</td></tr>') + '</tbody></table>';
      Array.prototype.forEach.call(el.querySelectorAll("[data-toggle]"), function (btn) {
        btn.addEventListener("click", function () {
          postJSON("/wsapi/tenant/roster/state", { csrf: csrf, domain: domain, local_part: btn.getAttribute("data-toggle"), state: btn.getAttribute("data-to") })
            .then(function () { loadRoster(domain); });
        });
      });
      Array.prototype.forEach.call(el.querySelectorAll("[data-reset]"), function (btn) {
        btn.addEventListener("click", function () {
          var pw = prompt("New password for " + btn.getAttribute("data-reset") + "@" + domain + " (min 8 chars). They will be asked to change it on next sign-in.");
          if (!pw) return;
          postJSON("/wsapi/tenant/roster/password", { csrf: csrf, domain: domain, local_part: btn.getAttribute("data-reset"), password: pw })
            .then(function (res) { if (!res.ok || !res.body.success) alert((res.body && res.body.reason) || "failed"); else loadRoster(domain); });
        });
      });
      var admins = document.getElementById("admins");
      admins.innerHTML = (j.admins || []).map(function (a) { return '<div>' + esc(a) + '</div>'; }).join("") || '<span class="muted">None</span>';
    });
  }

  function addUser(domain) {
    var local = document.getElementById("nu-local").value.trim().toLowerCase();
    var pw = document.getElementById("nu-pw").value;
    var mustChange = document.getElementById("nu-mc").checked;
    var err = document.getElementById("nu-err");
    err.className = "err"; err.textContent = "";
    postJSON("/wsapi/tenant/roster", { csrf: csrf, domain: domain, local_part: local, password: pw, require_password_change: mustChange }).then(function (res) {
      if (!res.ok || !res.body.success) { err.textContent = (res.body && res.body.reason) || "could not add"; return; }
      document.getElementById("nu-local").value = ""; document.getElementById("nu-pw").value = "";
      loadRoster(domain);
    });
  }

  function addAdmin(domain) {
    var id = document.getElementById("na-id").value.trim().toLowerCase();
    var err = document.getElementById("na-err");
    err.className = "err"; err.textContent = "";
    postJSON("/wsapi/tenant/admins", { csrf: csrf, domain: domain, identity: id }).then(function (res) {
      if (!res.ok || !res.body.success) { err.textContent = (res.body && res.body.reason) || "could not add"; return; }
      document.getElementById("na-id").value = "";
      loadRoster(domain);
    });
  }
})();
