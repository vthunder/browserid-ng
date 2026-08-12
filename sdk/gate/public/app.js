// The admin console client. External file (no inline scripts → no CSP hash
// churn). Talks to the same-origin /admin API; all writes carry the CSRF token
// the server derived from the session (double-submit via the x-csrf-token
// header, also present in the readable gate_csrf cookie).

const $ = (id) => document.getElementById(id);
let STATE = { broker: null, origin: null, csrf: null, admin: null };

// --- API helpers ------------------------------------------------------------

async function api(method, path, body) {
  const headers = {};
  if (body !== undefined) headers["content-type"] = "application/json";
  if (method !== "GET" && STATE.csrf) headers["x-csrf-token"] = STATE.csrf;
  const res = await fetch(path, {
    method,
    headers,
    credentials: "same-origin",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let data = null;
  try { data = await res.json(); } catch { /* empty */ }
  if (!res.ok) throw new Error((data && data.error_description) || `HTTP ${res.status}`);
  return data;
}

// --- BrowserID login --------------------------------------------------------

let bidLoaded = null;
function loadBrowserID(broker) {
  if (window.navigator && window.navigator.id) return Promise.resolve();
  if (bidLoaded) return bidLoaded;
  bidLoaded = new Promise((resolve, reject) => {
    const s = document.createElement("script");
    s.src = `${broker.replace(/\/+$/, "")}/include.js`;
    s.async = true;
    s.setAttribute("data-browserid-url", broker.replace(/\/+$/, ""));
    s.onload = () => resolve();
    s.onerror = () => reject(new Error("could not load the BrowserID dialog"));
    document.head.appendChild(s);
  });
  return bidLoaded;
}

async function signIn() {
  const err = $("signin-error");
  err.hidden = true;
  try {
    await loadBrowserID(STATE.broker);
    window.navigator.id.watch({
      onlogin: async (presentation) => {
        try {
          const out = await api("POST", "/admin/login", { presentation });
          STATE.csrf = out.csrf;
          STATE.admin = out.admin;
          await render();
        } catch (e) {
          err.textContent = e.message;
          err.hidden = false;
        }
      },
      onlogout: () => {},
    });
    window.navigator.id.request({ siteName: "MCP Gateway" });
  } catch (e) {
    err.textContent = e.message;
    err.hidden = false;
  }
}

// --- rendering --------------------------------------------------------------

async function render() {
  const boot = await api("GET", "/admin/bootstrap");
  STATE.broker = boot.broker;
  STATE.origin = boot.origin;

  if (!boot.signedIn) {
    $("signed-in").hidden = true;
    $("whoami").hidden = true;
    $("signed-out").hidden = false;
    return;
  }

  // Signed in — get a fresh csrf + the mount list.
  const who = await api("GET", "/admin/whoami");
  STATE.csrf = who.csrf;
  STATE.admin = who.admin;
  $("mount-prefix").textContent = `${(STATE.origin || who.host || "").replace(/\/+$/, "")}/`;
  $("admin-email").textContent = who.admin;
  $("whoami").hidden = false;
  $("signed-out").hidden = true;
  $("signed-in").hidden = false;
  await refreshMounts();
}

async function refreshMounts() {
  const { mounts } = await api("GET", "/admin/mounts");
  const ul = $("mounts");
  ul.innerHTML = "";
  $("empty").hidden = mounts.length > 0;
  for (const m of mounts) ul.appendChild(mountRow(m));
}

function mountRow(m) {
  const li = document.createElement("li");
  li.className = "mount" + (m.running ? "" : " stopped");

  const head = el("div", "mount-head");
  head.appendChild(el("span", "mount-name", m.name));
  head.appendChild(el("span", "badge " + (m.running ? "ok" : "off"), m.running ? "running" : "stopped"));
  li.appendChild(head);

  const urlRow = el("div", "url-row");
  const code = el("code", "url", m.url);
  const copy = button("Copy", "ghost small", async () => {
    try { await navigator.clipboard.writeText(m.url); copy.textContent = "Copied"; setTimeout(() => (copy.textContent = "Copy"), 1200); }
    catch { /* clipboard unavailable */ }
  });
  urlRow.appendChild(code);
  urlRow.appendChild(copy);
  li.appendChild(urlRow);

  const meta = el("div", "mount-meta");
  meta.appendChild(el("span", "", `${m.allowCount} allowed`));
  meta.appendChild(el("span", "", `${m.toolCount} tools`));
  meta.appendChild(el("span", "cmd", m.command.join(" ")));
  li.appendChild(meta);

  const actions = el("div", "mount-actions");
  actions.appendChild(button(m.enabled ? "Disable" : "Enable", "ghost small", async () => {
    await guarded(() => api("PATCH", `/admin/mounts/${encodeURIComponent(m.id)}`, { enabled: !m.enabled }));
    await refreshMounts();
  }));

  // In-content remove confirm (never window.confirm).
  const removeBtn = button("Remove", "danger small", () => {
    actions.querySelectorAll(".confirm").forEach((n) => n.remove());
    const confirm = el("span", "confirm");
    confirm.appendChild(el("span", "confirm-text", "Remove?"));
    confirm.appendChild(button("Yes, remove", "danger small", async () => {
      await guarded(() => api("DELETE", `/admin/mounts/${encodeURIComponent(m.id)}`));
      await refreshMounts();
    }));
    confirm.appendChild(button("Keep", "ghost small", () => confirm.remove()));
    actions.appendChild(confirm);
  });
  actions.appendChild(removeBtn);
  li.appendChild(actions);
  return li;
}

// --- add dialog -------------------------------------------------------------

function openAdd() {
  $("add-error").hidden = true;
  for (const id of ["f-name", "f-mount", "f-command", "f-allow"]) $(id).value = "";
  $("add-dialog").hidden = false;
  $("f-name").focus();
}
function closeAdd() { $("add-dialog").hidden = true; }

async function saveAdd() {
  const err = $("add-error");
  err.hidden = true;
  const name = $("f-name").value.trim();
  const mount = $("f-mount").value.trim();
  const command = splitList($("f-command").value, /\s+/);
  const allow = splitList($("f-allow").value, /[\s,]+/);
  try {
    await api("POST", "/admin/mounts", { name, mount, command, allow });
    closeAdd();
    await refreshMounts();
  } catch (e) {
    err.textContent = e.message;
    err.hidden = false;
  }
}

// --- utilities --------------------------------------------------------------

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
}
function button(label, cls, onclick) {
  const b = el("button", cls, label);
  b.addEventListener("click", onclick);
  return b;
}
function splitList(s, re) { return String(s || "").split(re).filter(Boolean); }
async function guarded(fn) {
  try { await fn(); } catch (e) { console.error(e); showToast(e.message); }
}
function showToast(msg) {
  const t = el("div", "toast", msg);
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 3500);
}

// --- wire up ----------------------------------------------------------------

window.addEventListener("DOMContentLoaded", () => {
  $("signin").addEventListener("click", signIn);
  $("logout").addEventListener("click", async () => {
    try { await api("POST", "/admin/logout"); } catch { /* ignore */ }
    STATE.csrf = null;
    await render();
  });
  $("add-open").addEventListener("click", openAdd);
  $("add-cancel").addEventListener("click", closeAdd);
  $("add-save").addEventListener("click", saveAdd);
  render().catch((e) => {
    const err = $("signin-error");
    if (err) { err.textContent = e.message; err.hidden = false; }
    $("signed-out").hidden = false;
  });
});
