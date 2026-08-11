// Hosted-primary onboarding + admin console (bean g5qt; redesign bean r9gn).
//
// Two views off one page:
//   /domains           → list your domains + the stepped add-domain wizard
//   /domains/<domain>  → that tenant's admin console (Users / Administrators /
//                        Managed identities / Settings)
// All privileged calls carry the broker session CSRF token. The add-domain
// wizard IS the roadmap's record generator + DNSSEC checker: publishing the
// generated record is the proof of domain control that seats first admin.
// Destructive actions use in-content two-click or typed confirms — NEVER
// window.confirm()/prompt(): browsers suppress those when the tab isn't
// frontmost, silently swallowing the click.
(function () {
  "use strict";

  var app = document.getElementById("app");
  var signedOut = document.getElementById("signed-out");
  var signoutBtn = document.getElementById("signout");
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

  function fmtMonthYear(iso) {
    var t = Date.parse(iso);
    if (!t) return "";
    return new Date(t).toLocaleDateString("en-US", { month: "short", year: "numeric" });
  }

  function fmtDay(iso) {
    var t = Date.parse(iso);
    if (!t) return "never";
    var d = new Date(t);
    var sameYear = d.getFullYear() === new Date().getFullYear();
    return d.toLocaleDateString("en-US", sameYear
      ? { month: "short", day: "numeric" }
      : { month: "short", day: "numeric", year: "numeric" });
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

  // Verified account emails that are NOT at `domain` (those go under the
  // "new address at this domain" option instead).
  function externalIdentities(domain) {
    return identities.filter(function (e) {
      var at = e.lastIndexOf("@");
      return at === -1 || e.slice(at + 1).toLowerCase() !== domain;
    });
  }

  // Copy button: clipboard write + a 1.4s "Copied" flip, no re-render.
  function wireCopyButtons(root) {
    Array.prototype.forEach.call(root.querySelectorAll("[data-copy]"), function (btn) {
      btn.addEventListener("click", function () {
        try { navigator.clipboard.writeText(btn.getAttribute("data-copy")); } catch (e) {}
        btn.textContent = "Copied";
        setTimeout(function () { btn.textContent = "Copy"; }, 1400);
      });
    });
  }

  function copyBlock(text) {
    return '<div class="coderow"><code class="codebox">' + esc(text) + '</code>' +
      '<button class="btn-copy" data-copy="' + esc(text) + '">Copy</button></div>';
  }

  // --- Boot ----------------------------------------------------------------
  Promise.all([getJSON("/wsapi/session_context"), getJSON("/wsapi/list_emails")])
    .then(function (res) {
      var ctx = res[0], emails = res[1];
      if (!ctx || !ctx.authenticated) { signedOut.hidden = false; return; }
      csrf = ctx.csrf_token;
      identities = (emails && emails.emails) || [];
      app.hidden = false;
      signoutBtn.hidden = false;
      signoutBtn.addEventListener("click", function () {
        postJSON("/wsapi/logout", { csrf: csrf }).then(
          function () { location.reload(); },
          function () { location.reload(); }
        );
      });
      var domain = currentDomain();
      if (domain) initConsole(domain); else initList();
    })
    .catch(function () { signedOut.hidden = false; });

  // =========================================================================
  // List view + stepped add-domain wizard
  // =========================================================================

  var list = {
    tenants: [],
    wiz: null, // null = closed; else { step, domain, mode, existing, pw, err, recordName, record, adminLabel }
  };

  function initList() {
    loadTenants().then(renderList);
  }

  function loadTenants() {
    return getJSON("/wsapi/tenant/list").then(function (j) {
      list.tenants = (j && j.tenants) || [];
    });
  }

  function tenantRowHtml(t) {
    var active = t.status === "active";
    var pending = t.status === "pending_dns";
    var pillCls = active ? "green" : pending ? "amber" : "gray";
    var pillText = active ? "Active" : pending ? "Waiting for DNS" : "Suspended";
    var sub = "";
    if (active) {
      var n = typeof t.users === "number" ? t.users : 0;
      sub = n + " user" + (n === 1 ? "" : "s") +
        (t.activated_at ? " · since " + fmtMonthYear(t.activated_at) : "");
    }
    var html = '<div class="card"><div class="domrow">' +
      '<span class="domname">' + esc(t.domain) + '</span>' +
      '<span class="pill ' + pillCls + '">' + pillText + '</span>' +
      (sub ? '<span class="meta">' + esc(sub) + '</span>' : "") +
      (active
        ? '<button class="ghost" data-manage="' + esc(t.domain) + '" style="margin-left:auto">Manage ›</button>'
        : "") +
      "</div>";
    if (pending) {
      html +=
        '<div class="pendbox">' +
          '<div class="pendhint">Publish this TXT record on your DNS, then check. The zone must be DNSSEC-signed.</div>' +
          '<div class="codecol">' + copyBlock(t.record_name) + copyBlock(t.record) + '</div>' +
          '<div style="display:flex;align-items:center;gap:12px;margin-top:10px">' +
            '<button class="btn" data-check="' + esc(t.domain) + '">Check DNS</button>' +
            '<span class="msg warn" data-status="' + esc(t.domain) + '"></span>' +
          "</div>" +
        "</div>";
    }
    return html + "</div>";
  }

  function renderList() {
    var w = list.wiz;
    app.innerHTML =
      '<div class="wrap">' +
        '<div class="h1row">' +
          "<h1>Your domains</h1>" +
          (list.tenants.length && !w
            ? '<button class="btn" id="wiz-start" style="margin-left:auto">+ Add a domain</button>'
            : "") +
        "</div>" +
        '<p class="intro">Run browserid.me as the identity provider for a domain you control. ' +
          "Publish one DNS record, and every site that accepts browserid.me accepts addresses at your domain " +
          "— nothing to host, nothing else to set up.</p>" +
        '<div class="domlist" id="domlist">' +
          (list.tenants.length
            ? list.tenants.map(tenantRowHtml).join("")
            : '<div class="card empty">' +
                '<div style="font:500 13px system-ui;color:#6b6b74">No domains yet.</div>' +
                (w ? "" : '<button class="btn" id="wiz-start-empty" style="margin-top:10px;padding:8px 16px">+ Add a domain</button>') +
              "</div>") +
        "</div>" +
        (w ? wizardHtml() : "") +
      "</div>";

    wireCopyButtons(app);
    var start = document.getElementById("wiz-start") || document.getElementById("wiz-start-empty");
    if (start) start.addEventListener("click", function () {
      list.wiz = { step: 1, domain: "", mode: "existing", existing: "", pw: "", err: "" };
      renderList();
    });
    Array.prototype.forEach.call(app.querySelectorAll("[data-manage]"), function (btn) {
      btn.addEventListener("click", function () {
        location.href = "/domains/" + encodeURIComponent(btn.getAttribute("data-manage"));
      });
    });
    Array.prototype.forEach.call(app.querySelectorAll("[data-check]"), function (btn) {
      btn.addEventListener("click", function () { checkPendingDns(btn.getAttribute("data-check")); });
    });
    if (w) wireWizard();
  }

  function checkPendingDns(domain) {
    var msg = document.querySelector('[data-status="' + CSS.escape(domain) + '"]');
    if (msg) { msg.className = "msg warn"; msg.textContent = "Checking…"; }
    postJSON("/wsapi/tenant/check", { csrf: csrf, domain: domain }).then(function (res) {
      if (!msg) return;
      var b = res.body || {};
      if (b.dns === "validated" && b.status === "active") {
        msg.className = "msg ok";
        msg.textContent = "Verified — " + domain + " is active.";
        setTimeout(function () { loadTenants().then(renderList); }, 900);
      } else {
        msg.className = "msg warn";
        msg.textContent = dnsMessage(b.dns, b.host_ok);
      }
    });
  }

  // --- Wizard --------------------------------------------------------------

  function wizardHtml() {
    var w = list.wiz;
    var labels = ["Domain", "Administrator", "Publish record"];
    var steps = labels.map(function (label, i) {
      var n = i + 1;
      var cls = n === w.step ? "cur" : n < w.step ? "done" : "";
      var num = n < w.step ? "✓" : String(n);
      return '<div class="wizstep ' + cls + '"><span class="n">' + num + '</span>' +
        '<span class="l">' + label + "</span></div>";
    }).join("");
    return "<h2>Add a domain</h2>" +
      '<div class="card flush">' +
        '<div class="wizsteps">' + steps + "</div>" +
        '<div class="wizbody">' +
          (w.step === 1 ? wizStep1Html() : w.step === 2 ? wizStep2Html() : wizStep3Html()) +
        "</div>" +
      "</div>";
  }

  function wizStep1Html() {
    var w = list.wiz;
    return '<label class="f" for="wiz-domain">Domain</label>' +
      '<input class="inp big" id="wiz-domain" placeholder="example.com" value="' + esc(w.domain) + '"' +
        ' autocapitalize="off" autocorrect="off" spellcheck="false" />' +
      '<div class="help" style="margin-top:8px">You\'ll need to publish one TXT record on this domain\'s DNS, ' +
        "and the zone must be DNSSEC-signed. Nothing changes for the domain's email or website.</div>" +
      '<div class="btnline">' +
        '<button class="btn lg" id="wiz-continue">Continue</button>' +
        '<button class="btn-plain" id="wiz-cancel">Cancel</button>' +
        '<span class="err" id="wiz-err">' + esc(w.err) + "</span>" +
      "</div>";
  }

  function wizStep2Html() {
    var w = list.wiz;
    var d = w.domain;
    var ext = externalIdentities(d);
    var existing = w.existing || ext[0] || "";
    var isExisting = w.mode === "existing";
    return '<div style="font:600 12px system-ui;color:#17171a;margin-bottom:8px">Who administers ' + esc(d) + "?</div>" +
      '<div style="display:flex;flex-direction:column;gap:8px">' +
        '<div class="optcard' + (isExisting ? " sel" : "") + '" data-mode="existing">' +
          '<label class="head"><input type="radio" name="wiz-mode" value="existing"' + (isExisting ? " checked" : "") + ">" +
            "An address you already have</label>" +
          '<div class="body">' +
            '<select class="inp" id="wiz-existing"' + (ext.length ? "" : " disabled") + ">" +
              (ext.length
                ? ext.map(function (e) {
                    return '<option value="' + esc(e) + '"' + (e === existing ? " selected" : "") + ">" + esc(e) + "</option>";
                  }).join("")
                : "") +
            "</select>" +
            '<div class="help" style="margin-top:6px">' +
              (ext.length
                ? "You'll keep signing in with browserid as this address."
                : "You have no browserid address outside this domain — use an address at the domain instead.") +
            "</div>" +
          "</div>" +
        "</div>" +
        '<div class="optcard' + (isExisting ? "" : " sel") + '" data-mode="local">' +
          '<label class="head"><input type="radio" name="wiz-mode" value="local"' + (isExisting ? "" : " checked") + ">" +
            "A new address at " + esc(d) + "</label>" +
          '<div class="body" style="display:flex;flex-direction:column;gap:8px">' +
            '<div class="fieldrow" style="flex-wrap:nowrap">' +
              '<input class="inp" id="wiz-local" placeholder="you" style="flex:1;min-width:0"' +
                ' autocapitalize="off" autocorrect="off" spellcheck="false" />' +
              '<span class="suffix">@' + esc(d) + "</span>" +
            "</div>" +
            '<div class="fieldrow" style="flex-wrap:nowrap">' +
              '<input class="inp" id="wiz-pw" placeholder="password (min 8 characters)" value="' + esc(w.pw) + '"' +
                ' style="flex:1;min-width:0" autocapitalize="off" autocorrect="off" spellcheck="false" />' +
              '<button class="btn-gen" id="wiz-gen" type="button">Generate</button>' +
            "</div>" +
            '<div class="help">You\'ll sign in at browserid.me with this address and password.</div>' +
          "</div>" +
        "</div>" +
      "</div>" +
      '<div class="btnline">' +
        '<button class="btn-back" id="wiz-back">← Back</button>' +
        '<button class="btn lg" id="wiz-go">Generate DNS record</button>' +
        '<span class="err" id="wiz-err">' + esc(w.err) + "</span>" +
      "</div>";
  }

  function wizStep3Html() {
    var w = list.wiz;
    return '<div style="font:12.5px/1.6 system-ui;color:#17171a;margin-bottom:10px">' +
        "Publish this TXT record on " + esc(w.domain) + "'s DNS. Once it verifies, <b>" + esc(w.adminLabel) +
        "</b> becomes the administrator.</div>" +
      '<div class="codecol">' + copyBlock(w.recordName) + copyBlock(w.record) + "</div>" +
      '<div class="help" style="margin-top:8px">The zone must be DNSSEC-signed. DNS can take a few minutes ' +
        "to propagate — you can leave this page; the domain stays listed above as waiting for DNS.</div>" +
      '<div class="btnline" style="margin-top:14px">' +
        '<button class="btn lg" id="wiz-check">Check DNS now</button>' +
        '<button class="btn-plain" id="wiz-done">Done for now</button>' +
        '<span class="msg warn" id="wiz-check-msg"></span>' +
      "</div>";
  }

  function wizardSyncInputs() {
    // Persist typed values into state before a re-render tears the DOM down.
    var w = list.wiz;
    var dom = document.getElementById("wiz-domain");
    if (dom) w.domain = dom.value.trim().toLowerCase();
    var pw = document.getElementById("wiz-pw");
    if (pw) w.pw = pw.value;
    var ex = document.getElementById("wiz-existing");
    if (ex && !ex.disabled) w.existing = ex.value;
    var local = document.getElementById("wiz-local");
    if (local) w.local = local.value.trim().toLowerCase();
  }

  function wireWizard() {
    var w = list.wiz;
    var cancel = document.getElementById("wiz-cancel") || document.getElementById("wiz-done");
    if (cancel) cancel.addEventListener("click", function () {
      list.wiz = null;
      loadTenants().then(renderList);
    });

    if (w.step === 1) {
      document.getElementById("wiz-continue").addEventListener("click", function () {
        wizardSyncInputs();
        var d = w.domain;
        if (!d || d.indexOf(".") < 1) { setWizErr("Enter a domain like example.com."); return; }
        if (list.tenants.some(function (t) { return t.domain === d; })) {
          setWizErr("That domain is already on your list."); return;
        }
        w.step = 2; w.err = "";
        renderList();
      });
    }

    if (w.step === 2) {
      Array.prototype.forEach.call(app.querySelectorAll(".optcard"), function (card) {
        card.addEventListener("click", function () {
          var mode = card.getAttribute("data-mode");
          if (w.mode === mode) return;
          wizardSyncInputs();
          w.mode = mode; w.err = "";
          renderList();
          // Restore the transient local-part input (not kept in the value attr).
          var local = document.getElementById("wiz-local");
          if (local && w.local) local.value = w.local;
        });
      });
      var localInp = document.getElementById("wiz-local");
      if (localInp && w.local) localInp.value = w.local;
      document.getElementById("wiz-gen").addEventListener("click", function (ev) {
        ev.stopPropagation();
        wizardSyncInputs();
        w.pw = genPassword();
        // Generating a password implies the new-address option.
        w.mode = "local"; w.err = "";
        renderList();
        var local2 = document.getElementById("wiz-local");
        if (local2 && w.local) local2.value = w.local;
      });
      document.getElementById("wiz-back").addEventListener("click", function () {
        wizardSyncInputs();
        w.step = 1; w.err = "";
        renderList();
      });
      document.getElementById("wiz-go").addEventListener("click", function () {
        wizardSyncInputs();
        var d = w.domain;
        var body = { csrf: csrf, domain: d };
        if (w.mode === "local") {
          if (!w.local) { setWizErr("Enter the address's username."); return; }
          if (w.pw.length < 8) { setWizErr("Password must be at least 8 characters."); return; }
          body.admin_email = w.local + "@" + d;
          body.password = w.pw;
        } else {
          var ext = externalIdentities(d);
          var chosen = w.existing || ext[0] || "";
          if (!chosen) { setWizErr("Choose an address at the domain instead."); return; }
          body.admin_email = chosen;
        }
        postJSON("/wsapi/tenant/create", body).then(function (res) {
          if (!res.ok || !res.body.success) {
            setWizErr((res.body && res.body.reason) || "could not create");
            return;
          }
          w.step = 3; w.err = "";
          w.adminLabel = body.admin_email;
          w.recordName = res.body.record_name;
          w.record = res.body.record;
          loadTenants().then(renderList);
        });
      });
    }

    if (w.step === 3) {
      document.getElementById("wiz-check").addEventListener("click", function () {
        var msg = document.getElementById("wiz-check-msg");
        msg.className = "msg warn"; msg.textContent = "Checking…";
        postJSON("/wsapi/tenant/check", { csrf: csrf, domain: w.domain }).then(function (res) {
          var b = res.body || {};
          if (b.dns === "validated" && b.status === "active") {
            msg.className = "msg ok";
            msg.textContent = "Verified — " + w.domain + " is active. Opening the console…";
            setTimeout(function () {
              location.href = "/domains/" + encodeURIComponent(w.domain);
            }, 900);
          } else {
            msg.className = "msg warn";
            msg.textContent = dnsMessage(b.dns, b.host_ok);
          }
        });
      });
    }
  }

  function setWizErr(text) {
    list.wiz.err = text;
    var el = document.getElementById("wiz-err");
    if (el) el.textContent = text;
  }

  // =========================================================================
  // Admin console (per domain)
  // =========================================================================

  var con = {
    domain: null,
    tab: "users",
    roster: [],
    admins: [],
    loadErr: "",
    // users tab
    nuPw: "", nuMc: true, nuErr: "",
    resettingLocal: null, resetPw: "",
    // admins tab
    naErr: "", adminErr: "",
    // policy tab
    mg: { enabled: false, per_audience: false, audiences: [], scopes: [], deviceDays: "", accessHours: "" },
    mgSavedEnabled: false, mgConfirm: false, mgMsg: "", mgMsgOk: false,
    // settings tab
    revokeConfirm: false, revokeMsg: "", revokeOk: false, delErr: "",
  };

  function initConsole(domain) {
    con.domain = domain;
    Promise.all([loadRoster(), loadManagement()]).then(renderConsole);
  }

  function loadRoster() {
    var q = "?domain=" + encodeURIComponent(con.domain) + "&csrf=" + encodeURIComponent(csrf);
    return getJSON("/wsapi/tenant/roster" + q).then(function (j) {
      if (!j || !j.success) {
        con.loadErr = (j && j.reason) || "You are not an administrator of this domain.";
        return;
      }
      con.loadErr = "";
      con.roster = j.roster || [];
      con.admins = j.admins || [];
    });
  }

  function loadManagement() {
    var q = "?domain=" + encodeURIComponent(con.domain) + "&csrf=" + encodeURIComponent(csrf);
    return getJSON("/wsapi/tenant/management" + q).then(function (j) {
      if (!j || !j.success) return; // loadErr already covers not-admin
      var m = j.management || {};
      var access = m.access_cert_ttl != null ? m.access_cert_ttl : m.max_ttl;
      con.mg = {
        enabled: !!m.enabled,
        per_audience: !!m.per_audience,
        audiences: m.audiences || [],
        scopes: m.scopes || [],
        deviceDays: m.device_cert_ttl ? String(Math.round(m.device_cert_ttl / 86400)) : "",
        accessHours: access ? String(Math.round(access / 3600)) : "",
      };
      con.mgSavedEnabled = !!m.enabled;
    });
  }

  function renderConsole() {
    var tabs = [
      { id: "users", label: "Users" },
      { id: "admins", label: "Administrators" },
      { id: "policy", label: "Managed identities" },
      { id: "settings", label: "Settings" },
    ];
    app.innerHTML =
      '<div class="wrap console">' +
        '<button class="backlink" id="back-to-list">← All domains</button>' +
        '<div class="h1row" style="flex-wrap:wrap;gap:10px">' +
          '<h1 class="mono">' + esc(con.domain) + "</h1>" +
          '<span class="pill green">Active</span>' +
        "</div>" +
        '<div class="consolesub">Hosted identity provider · browserid.me answers for addresses at this domain</div>' +
        (con.loadErr
          ? '<div class="err">' + esc(con.loadErr) + "</div>"
          : '<div class="tabs">' +
              tabs.map(function (t) {
                return '<button class="tab' + (t.id === con.tab ? " active" : "") + '" data-tab="' + t.id + '">' +
                  t.label + "</button>";
              }).join("") +
            "</div>" +
            '<div id="tabbody">' + tabBodyHtml() + "</div>") +
      "</div>";

    document.getElementById("back-to-list").addEventListener("click", function () {
      location.href = "/domains";
    });
    Array.prototype.forEach.call(app.querySelectorAll(".tab"), function (btn) {
      btn.addEventListener("click", function () {
        con.tab = btn.getAttribute("data-tab");
        con.mgConfirm = false; con.mgMsg = "";
        con.revokeConfirm = false; con.revokeMsg = "";
        con.delErr = ""; con.nuErr = ""; con.naErr = ""; con.adminErr = "";
        con.resettingLocal = null;
        renderConsole();
      });
    });
    if (!con.loadErr) wireTab();
  }

  function tabBodyHtml() {
    switch (con.tab) {
      case "users": return usersTabHtml();
      case "admins": return adminsTabHtml();
      case "policy": return policyTabHtml();
      case "settings": return settingsTabHtml();
    }
    return "";
  }

  // --- Users tab -----------------------------------------------------------

  function usersTabHtml() {
    var rows = con.roster.map(function (r, i) {
      var disabled = r.state === "disabled";
      var resetting = con.resettingLocal === r.local_part;
      return '<div class="rwrap">' +
        '<div class="rgrid">' +
          '<span class="remail' + (disabled ? " off" : "") + '" title="' + esc(r.email) + '">' + esc(r.email) + "</span>" +
          "<span>" +
            '<span class="pill ' + (disabled ? "gray" : "green") + '">' + (disabled ? "disabled" : "active") + "</span>" +
            (r.must_change_password ? '<span class="rmust">must change pw</span>' : "") +
          "</span>" +
          '<span class="meta">' + esc(r.last_login_at ? fmtDay(r.last_login_at) : "never") + "</span>" +
          '<span class="ractions">' +
            '<button class="btn-row" data-reset="' + esc(r.local_part) + '">Reset password</button>' +
            (disabled
              ? '<button class="btn-row" data-toggle="' + esc(r.local_part) + '" data-to="active">Enable</button>'
              : '<button class="btn-rowdanger" data-toggle="' + esc(r.local_part) + '" data-to="disabled">Disable</button>') +
          "</span>" +
        "</div>" +
        (resetting
          ? '<div class="resetrow">' +
              '<span style="font:12px system-ui;color:#17171a">New password:</span>' +
              '<code class="npw">' + esc(con.resetPw) + "</code>" +
              '<span class="help">They\'ll be asked to change it at next sign-in.</span>' +
              '<span class="tail">' +
                '<button class="btn-sm" id="reset-go">Set password</button>' +
                '<button class="btn-sm-plain" id="reset-cancel">Cancel</button>' +
              "</span>" +
            "</div>"
          : "") +
        "</div>";
    }).join("");
    return '<div class="card" style="margin-bottom:14px">' +
        '<div class="cardtitle">Add a user</div>' +
        '<div class="fieldrow">' +
          '<input class="inp" id="nu-local" placeholder="alice" style="flex:1;min-width:120px"' +
            ' autocapitalize="off" spellcheck="false" />' +
          '<span class="suffix">@' + esc(con.domain) + "</span>" +
          '<input class="inp" id="nu-pw" placeholder="initial password" value="' + esc(con.nuPw) + '"' +
            ' style="flex:1;min-width:140px" autocapitalize="off" spellcheck="false" />' +
          '<button class="btn-gen" id="nu-gen" type="button">Generate</button>' +
          '<button class="btn" id="nu-add">Add user</button>' +
        "</div>" +
        '<label style="display:flex;align-items:center;gap:7px;font:12px system-ui;color:#6b6b74;margin-top:10px;cursor:pointer">' +
          '<input type="checkbox" id="nu-mc"' + (con.nuMc ? " checked" : "") + ' style="margin:0">' +
          "Ask them to change the password at first sign-in</label>" +
        '<div class="err" id="nu-err" style="margin-top:6px;min-height:14px">' + esc(con.nuErr) + "</div>" +
      "</div>" +
      '<div class="card flush">' +
        '<div class="rgrid head"><span>User</span><span>Status</span><span>Last sign-in</span><span></span></div>' +
        (rows || '<div style="padding:14px 16px;font:12.5px system-ui;color:#8a8a93">No users yet.</div>') +
      "</div>";
  }

  function wireUsersTab() {
    document.getElementById("nu-gen").addEventListener("click", function () {
      document.getElementById("nu-pw").value = genPassword();
    });
    document.getElementById("nu-add").addEventListener("click", function () {
      var local = document.getElementById("nu-local").value.trim().toLowerCase();
      var pw = document.getElementById("nu-pw").value;
      var mustChange = document.getElementById("nu-mc").checked;
      con.nuMc = mustChange; con.nuPw = pw;
      if (!local) { setErr("nu-err", "Enter a username."); return; }
      if (pw.length < 8) { setErr("nu-err", "Password must be at least 8 characters."); return; }
      postJSON("/wsapi/tenant/roster", {
        csrf: csrf, domain: con.domain, local_part: local, password: pw,
        require_password_change: mustChange,
      }).then(function (res) {
        if (!res.ok || !res.body.success) {
          setErr("nu-err", (res.body && res.body.reason) || "could not add");
          return;
        }
        con.nuPw = ""; con.nuErr = "";
        loadRoster().then(renderConsole);
      });
    });
    Array.prototype.forEach.call(app.querySelectorAll("[data-toggle]"), function (btn) {
      btn.addEventListener("click", function () {
        postJSON("/wsapi/tenant/roster/state", {
          csrf: csrf, domain: con.domain,
          local_part: btn.getAttribute("data-toggle"),
          state: btn.getAttribute("data-to"),
        }).then(function () { loadRoster().then(renderConsole); });
      });
    });
    // Reset password: inline expanding row with a pre-generated password —
    // never prompt().
    Array.prototype.forEach.call(app.querySelectorAll("[data-reset]"), function (btn) {
      btn.addEventListener("click", function () {
        var local = btn.getAttribute("data-reset");
        if (con.resettingLocal === local) { con.resettingLocal = null; }
        else { con.resettingLocal = local; con.resetPw = genPassword(); }
        renderConsole();
      });
    });
    var resetGo = document.getElementById("reset-go");
    if (resetGo) resetGo.addEventListener("click", function () {
      postJSON("/wsapi/tenant/roster/password", {
        csrf: csrf, domain: con.domain, local_part: con.resettingLocal, password: con.resetPw,
      }).then(function (res) {
        if (!res.ok || !res.body.success) {
          setErr("nu-err", "Password reset failed: " + ((res.body && res.body.reason) || "unknown error"));
          return;
        }
        con.resettingLocal = null;
        loadRoster().then(renderConsole);
      });
    });
    var resetCancel = document.getElementById("reset-cancel");
    if (resetCancel) resetCancel.addEventListener("click", function () {
      con.resettingLocal = null;
      renderConsole();
    });
  }

  // --- Administrators tab --------------------------------------------------

  function isYou(email) {
    return identities.some(function (e) { return e.toLowerCase() === email.toLowerCase(); });
  }

  function adminsTabHtml() {
    var rows = con.admins.map(function (a) {
      var you = isYou(a);
      var removable = !you && con.admins.length > 1;
      return '<div class="adminrow">' +
        '<span class="em">' + esc(a) + "</span>" +
        (you ? '<span class="pill you">you</span>' : "") +
        (removable
          ? '<button class="btn-rowdanger right" data-remove="' + esc(a) + '" style="padding:5px 10px">Remove</button>'
          : "") +
        "</div>";
    }).join("");
    return '<p style="margin:0 0 14px;font:12.5px/1.6 system-ui;color:#6b6b74;max-width:540px">' +
        "Administrators have full control of " + esc(con.domain) + " on browserid.me — users, policy, and deletion. " +
        "They sign in with their own browserid account.</p>" +
      '<div class="card flush" style="margin-bottom:14px">' + rows + "</div>" +
      (con.adminErr ? '<div class="err" style="margin:-6px 0 14px">' + esc(con.adminErr) + "</div>" : "") +
      '<div class="card">' +
        '<div class="cardtitle">Add an administrator</div>' +
        '<div class="fieldrow">' +
          '<input class="inp" id="na-id" placeholder="person@example.com" style="flex:1;min-width:200px"' +
            ' autocapitalize="off" spellcheck="false" />' +
          '<button class="btn" id="na-add">Add admin</button>' +
        "</div>" +
        '<div class="help" style="margin-top:8px">Any browserid identity works — it doesn\'t have to be at ' +
          esc(con.domain) + ".</div>" +
        '<div class="err" id="na-err" style="margin-top:4px;min-height:14px">' + esc(con.naErr) + "</div>" +
      "</div>";
  }

  function wireAdminsTab() {
    document.getElementById("na-add").addEventListener("click", function () {
      var id = document.getElementById("na-id").value.trim().toLowerCase();
      if (!id || id.indexOf("@") < 1) {
        setErr("na-err", "Enter a full address, like person@example.com.");
        return;
      }
      if (con.admins.some(function (a) { return a.toLowerCase() === id; })) {
        setErr("na-err", "Already an administrator.");
        return;
      }
      postJSON("/wsapi/tenant/admins", { csrf: csrf, domain: con.domain, identity: id }).then(function (res) {
        if (!res.ok || !res.body.success) {
          setErr("na-err", (res.body && res.body.reason) || "could not add");
          return;
        }
        con.naErr = "";
        loadRoster().then(renderConsole);
      });
    });
    Array.prototype.forEach.call(app.querySelectorAll("[data-remove]"), function (btn) {
      btn.addEventListener("click", function () {
        postJSON("/wsapi/tenant/admins/remove", {
          csrf: csrf, domain: con.domain, identity: btn.getAttribute("data-remove"),
        }).then(function (res) {
          if (!res.ok || !res.body.success) {
            con.adminErr = (res.body && res.body.reason) || "could not remove";
            renderConsole();
            return;
          }
          con.adminErr = "";
          loadRoster().then(renderConsole);
        });
      });
    });
  }

  // --- Managed identities tab ----------------------------------------------

  function policyTabHtml() {
    var m = con.mg;
    var detail = !m.enabled ? "" :
      '<div class="divide">' +
        '<label class="checkline">' +
          '<input type="checkbox" id="mg-peraud"' + (m.per_audience ? " checked" : "") + ">" +
          "<span>" +
            '<span class="cs">Per-site credentials</span>' +
            '<span class="cd sm">Each sign-in mints for one named site — you see each site as it\'s first used.</span>' +
          "</span>" +
        "</label>" +
        "<div>" +
          '<label class="f" for="mg-aud">Allowed sites <span class="opt">— one origin per line; empty allows all</span></label>' +
          '<textarea class="inp" id="mg-aud" rows="3" placeholder="https://app.example.com">' +
            esc(m.audiences.join("\n")) + "</textarea>" +
        "</div>" +
        "<div>" +
          '<label class="f" for="mg-scopes">Allowed agent scopes <span class="opt">— empty = unrestricted</span></label>' +
          '<input class="inp" id="mg-scopes" placeholder="post read" value="' + esc(m.scopes.join(" ")) + '"' +
            ' style="width:100%" autocapitalize="off" spellcheck="false" />' +
        "</div>" +
        "<div>" +
          '<div style="font:600 12px system-ui;color:#17171a;margin-bottom:2px">Certificate lifetimes</div>' +
          '<div class="help" style="margin-bottom:8px">How long a signed-in device stays signed in, and how long ' +
            "each site credential lasts before it's silently reissued.</div>" +
          '<div class="ttls">' +
            "<div>" +
              '<label for="mg-devttl">Device certificate <span class="u">— days</span></label>' +
              '<input class="inp num" id="mg-devttl" type="number" min="1" placeholder="90" value="' + esc(m.deviceDays) + '" />' +
            "</div>" +
            "<div>" +
              '<label for="mg-accttl">Access certificate <span class="u">— hours</span></label>' +
              '<input class="inp num" id="mg-accttl" type="number" min="1" placeholder="24" value="' + esc(m.accessHours) + '" />' +
            "</div>" +
          "</div>" +
        "</div>" +
      "</div>";
    return '<div class="card" style="margin-bottom:14px">' +
        '<label class="checkline">' +
          '<input type="checkbox" id="mg-enabled"' + (m.enabled ? " checked" : "") + ">" +
          "<span>" +
            '<span class="ct">Managed identities</span>' +
            '<span class="cd">Control where addresses at ' + esc(con.domain) + " can be used and what their agents " +
              "may be granted. Users are told the domain manages issuance and may restrict — and see — where they are used.</span>" +
          "</span>" +
        "</label>" +
        detail +
        '<div class="btnline">' +
          '<button class="btn lg" id="mg-save">' +
            (con.mgConfirm ? "Confirm — signs everyone out once" : "Save policy") + "</button>" +
          '<span class="msg ' + (con.mgMsgOk ? "ok" : "warn") + '" id="mg-msg">' + esc(con.mgMsg) + "</span>" +
        "</div>" +
      "</div>";
  }

  function policySyncInputs() {
    var m = con.mg;
    var el;
    if ((el = document.getElementById("mg-enabled"))) m.enabled = el.checked;
    if ((el = document.getElementById("mg-peraud"))) m.per_audience = el.checked;
    if ((el = document.getElementById("mg-aud"))) {
      m.audiences = el.value.split("\n").map(function (s) { return s.trim(); }).filter(Boolean);
    }
    if ((el = document.getElementById("mg-scopes"))) {
      var raw = el.value.trim();
      m.scopes = raw ? raw.split(/\s+/) : [];
    }
    if ((el = document.getElementById("mg-devttl"))) m.deviceDays = el.value;
    if ((el = document.getElementById("mg-accttl"))) m.accessHours = el.value;
  }

  function wirePolicyTab() {
    document.getElementById("mg-enabled").addEventListener("change", function () {
      policySyncInputs();
      con.mgConfirm = false; con.mgMsg = "";
      renderConsole();
    });
    document.getElementById("mg-save").addEventListener("click", function () {
      policySyncInputs();
      var m = con.mg;
      // Two-click in-content confirm when ENABLING: the save revokes every
      // outstanding credential so certs come back with the managed marker.
      if (m.enabled && !con.mgSavedEnabled && !con.mgConfirm) {
        con.mgConfirm = true;
        con.mgMsgOk = false;
        con.mgMsg = "Enabling management reissues credentials: everyone at " + con.domain +
          " signs in again and comes back managed. Click again to confirm.";
        renderConsole();
        return;
      }
      con.mgConfirm = false;
      var deviceDays = parseInt(m.deviceDays, 10);
      var accessHours = parseInt(m.accessHours, 10);
      postJSON("/wsapi/tenant/management", {
        csrf: csrf,
        domain: con.domain,
        enabled: m.enabled,
        per_audience: m.per_audience,
        audiences: m.audiences,
        scopes: m.scopes.length ? m.scopes : null,
        device_cert_ttl: isNaN(deviceDays) ? null : deviceDays * 86400,
        access_cert_ttl: isNaN(accessHours) ? null : accessHours * 3600,
      }).then(function (res) {
        if (!res.ok || !res.body.success) {
          con.mgMsgOk = false;
          con.mgMsg = (res.body && res.body.reason) || "could not save";
          renderConsole();
          return;
        }
        con.mgSavedEnabled = m.enabled;
        con.mgMsgOk = true;
        con.mgMsg = m.enabled ? "Saved. Everyone signs in again with a managed identity." : "Saved.";
        renderConsole();
      });
    });
  }

  // --- Settings tab --------------------------------------------------------

  function settingsTabHtml() {
    return '<div class="card" style="margin-bottom:14px">' +
        '<div class="cardtitle" style="margin-bottom:0">Sign everyone out</div>' +
        '<p class="settext">Revokes every outstanding credential for ' + esc(con.domain) +
          " right now. Every user and agent is signed out and must sign in again. " +
          "Works whether or not managed identities are on.</p>" +
        '<div class="fieldrow" style="gap:12px">' +
          '<button class="btn-danger" id="revoke-all">' +
            (con.revokeConfirm ? "Confirm — revoke all credentials" : "Sign everyone out now") + "</button>" +
          '<span class="msg ' + (con.revokeOk ? "ok" : "warn") + '">' + esc(con.revokeMsg) + "</span>" +
        "</div>" +
      "</div>" +
      '<div class="card dangerzone">' +
        '<div class="cardtitle red">Delete this domain</div>' +
        '<p class="settext">Removes ' + esc(con.domain) + ", its users and its administrators from browserid.me, " +
          "so it can be onboarded fresh. Credentials already issued stop working once you remove or replace " +
          "the DNS record. This cannot be undone.</p>" +
        '<div class="fieldrow">' +
          '<input class="inp" id="del-confirm" placeholder="type ' + esc(con.domain) + ' to confirm"' +
            ' style="flex:1;min-width:220px" autocapitalize="off" autocorrect="off" spellcheck="false" />' +
          '<button class="btn-danger" id="del-btn">Delete domain</button>' +
        "</div>" +
        '<div class="err" id="del-err" style="margin-top:6px;min-height:14px">' + esc(con.delErr) + "</div>" +
      "</div>";
  }

  function wireSettingsTab() {
    document.getElementById("revoke-all").addEventListener("click", function () {
      if (!con.revokeConfirm) {
        con.revokeConfirm = true;
        con.revokeOk = false;
        con.revokeMsg = "Every user and agent at " + con.domain +
          " is signed out immediately. Click again to confirm.";
        renderConsole();
        return;
      }
      con.revokeConfirm = false;
      postJSON("/wsapi/tenant/revoke_all", { csrf: csrf, domain: con.domain }).then(function (res) {
        if (!res.ok || !res.body.success) {
          con.revokeOk = false;
          con.revokeMsg = (res.body && res.body.reason) || "could not revoke";
        } else {
          var n = res.body.revoked || 0;
          con.revokeOk = true;
          con.revokeMsg = "Revoked " + n + " credential" + (n === 1 ? "" : "s") + " — everyone signs in again.";
        }
        renderConsole();
      });
    });
    document.getElementById("del-btn").addEventListener("click", function () {
      var typed = document.getElementById("del-confirm").value.trim().toLowerCase();
      if (typed !== con.domain) {
        setErr("del-err", "Type the domain exactly to confirm.");
        return;
      }
      postJSON("/wsapi/tenant/delete", { csrf: csrf, domain: con.domain, confirm: typed }).then(function (res) {
        if (!res.ok || !res.body.success) {
          setErr("del-err", (res.body && res.body.reason) || "could not delete");
          return;
        }
        var el = document.getElementById("del-err");
        if (el) { el.className = "err ok"; el.textContent = "Deleted. Returning to your domains…"; }
        setTimeout(function () { location.href = "/domains"; }, 800);
      });
    });
  }

  function wireTab() {
    switch (con.tab) {
      case "users": wireUsersTab(); break;
      case "admins": wireAdminsTab(); break;
      case "policy": wirePolicyTab(); break;
      case "settings": wireSettingsTab(); break;
    }
  }

  function setErr(id, text) {
    var el = document.getElementById(id);
    if (el) { el.className = "err"; el.textContent = text; }
  }
})();
