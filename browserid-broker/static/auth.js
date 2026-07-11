// Fallback-IdP interactive auth page (apgv). Opened by the mediator's dialog
// (top-level popup) when silent provisioning found no valid email cookie.
// Proves control of the email via a one-time SMTP code, sets the medium-lived
// email cookie, then completes authentication — the dialog then silently
// re-provisions a fresh short cert against the cookie.
(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };
  var msg = $("msg");
  var currentEmail = null;

  function setMsg(text, cls) { msg.textContent = text || ""; msg.className = cls || "muted"; }

  navigator.id.beginAuthentication(function (email) {
    currentEmail = email;
    $("email").textContent = email || "(unknown)";
    if (!email) {
      setMsg("No email supplied.", "err");
      return;
    }
    // Already verified in this browser? Complete immediately.
    fetch("/whoami", { credentials: "include" })
      .then(function (r) { return r.json(); })
      .then(function (w) {
        if (w && w.authenticated && w.email === email.toLowerCase()) {
          setMsg("Already verified — returning…", "ok");
          navigator.id.completeAuthentication();
        }
        // else: leave the send-code UI visible.
      })
      .catch(function () {});
  });

  $("send").onclick = function () {
    if (!currentEmail) return;
    $("send").disabled = true;
    setMsg("Sending…");
    fetch("/auth/send", {
      method: "POST", credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: currentEmail }),
    })
      .then(function (r) { return r.json().then(function (b) { return { ok: r.ok, b: b }; }); })
      .then(function (res) {
        if (!res.ok || !res.b.success) throw new Error(res.b.reason || "failed to send");
        $("send-step").style.display = "none";
        $("code-step").style.display = "block";
        setMsg("Code sent — check your email.", "ok");
        $("code").focus();
      })
      .catch(function (e) { $("send").disabled = false; setMsg(String(e.message || e), "err"); });
  };

  $("verify").onclick = function () {
    var code = $("code").value.trim();
    if (!code) return;
    $("verify").disabled = true;
    setMsg("Verifying…");
    fetch("/auth/verify", {
      method: "POST", credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: currentEmail, code: code }),
    })
      .then(function (r) { return r.json().then(function (b) { return { ok: r.ok, b: b }; }); })
      .then(function (res) {
        if (!res.ok || !res.b.success) throw new Error(res.b.reason || "verification failed");
        setMsg("Verified — returning…", "ok");
        navigator.id.completeAuthentication();
      })
      .catch(function (e) { $("verify").disabled = false; setMsg(String(e.message || e), "err"); });
  };
})();
