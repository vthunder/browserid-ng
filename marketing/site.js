// Shared behaviors across every marketing page: theme toggle, auth-origin
// link rewriting (config.js decides where the broker lives), and copy buttons.
// Page-specific behavior (the hero animation, the live guestbook wall, the MCP
// setup tabs) stays inline on the page that uses it.
(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };

  // ---- theme toggle (stored choice wins; light is the default) ----
  var tt = $("themeToggle");
  if (tt) {
    tt.addEventListener("click", function () {
      var next = document.documentElement.getAttribute("data-theme") === "light" ? "dark" : "light";
      document.documentElement.setAttribute("data-theme", next);
      try { localStorage.setItem("browserid:theme", next); } catch (e) {}
    });
  }

  // ---- auth-origin links (config.js decides where the broker lives) ----
  var authOrigin = (window.BROWSERID && window.BROWSERID.authOrigin) || "";
  window.__authOrigin = authOrigin;
  document.querySelectorAll("[data-auth-href]").forEach(function (a) {
    a.setAttribute("href", authOrigin + a.getAttribute("data-auth-href"));
  });

  // ---- copy buttons ----
  document.querySelectorAll(".copy-btn[data-copy]").forEach(function (b) {
    b.addEventListener("click", function () {
      var el = $(b.dataset.copy);
      navigator.clipboard.writeText(el.textContent.trim()).then(function () {
        b.textContent = "Copied ✓";
        setTimeout(function () { b.textContent = "Copy"; }, 2200);
      });
      if (window.posthog && window.posthog.capture) {
        window.posthog.capture("prompt_copy", { which: b.dataset.copy });
      }
    });
  });
})();
