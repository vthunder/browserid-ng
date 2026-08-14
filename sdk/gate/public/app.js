// The admin console client (design: docs/plans/2026-08-12-gate-admin-ui-design-brief.md
// + the reviewed high-fidelity handoff). External file (no inline scripts → CSP-safe).
//
// Three tabs over one server-owned state blob (GET /admin/state):
//   Servers — the published mounts (URL, command, tools, who reaches it)
//   People  — the address book (grants nothing by itself)
//   Roles   — the single source of truth for access (per-server, per-tool)
// Every write is STAGED: saved to config, applied on the next manual restart.
// The header's staged pill + popover surface the pending diff.

const $ = (id) => document.getElementById(id);

const STATE = {
  signedIn: false,
  admin: null,
  csrf: null,
  origin: null,
  broker: null,
  mounts: [],
  people: [],
  roles: [],
  pending: [],
  // UI-only state
  view: "servers",
  expanded: null, // server row accordion (single-open)
  roleExpanded: null, // role card accordion (single-open)
  confirming: null, // mount id with the inline remove-confirm showing
  copiedId: null,
  stagedOpen: false,
  prevPending: null, // last-seen staged count (auto-open on 0→1)
  signinError: null, // { attempted } | { message }
  drafts: { personName: "", personEmail: "", roleName: "" },
  theme: "light",
};

// --- theme ------------------------------------------------------------------

function applyTheme(t) {
  STATE.theme = t;
  document.documentElement.setAttribute("data-theme", t);
  $("theme-btn").textContent = t === "dark" ? "☾" : "☀";
}
function initTheme() {
  let t = null;
  try { t = localStorage.getItem("gate-admin-theme"); } catch { /* private mode */ }
  if (!t) t = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  applyTheme(t);
}

// --- API --------------------------------------------------------------------

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
  if (!res.ok) {
    const e = new Error((data && data.error_description) || `HTTP ${res.status}`);
    e.data = data;
    e.status = res.status;
    throw e;
  }
  return data;
}

/** Pull the whole console state; flips the staged popover open on 0→1. */
async function refresh() {
  const s = await api("GET", "/admin/state");
  STATE.signedIn = true;
  STATE.admin = s.admin;
  STATE.csrf = s.csrf;
  STATE.origin = s.origin;
  STATE.broker = s.broker;
  STATE.mounts = s.mounts;
  STATE.people = s.people;
  STATE.roles = s.roles;
  STATE.pending = s.pending;
  if (STATE.prevPending === 0 && s.pending.length > 0) STATE.stagedOpen = true;
  STATE.prevPending = s.pending.length;
  if (STATE.expanded && !s.mounts.some((m) => m.id === STATE.expanded)) STATE.expanded = null;
  if (STATE.roleExpanded && !s.roles.some((r) => r.id === STATE.roleExpanded)) STATE.roleExpanded = null;
}

/** Run a mutation, re-pull state, re-render; surface failures as a toast. */
async function mutate(fn) {
  try {
    await fn();
    await refresh();
  } catch (e) {
    if (e.status === 401) {
      // Session expired — back to the sign-in card.
      STATE.signedIn = false;
      STATE.csrf = null;
      render();
      return;
    }
    showToast(e.message);
    try { await refresh(); } catch { /* keep the last state */ }
  }
  render();
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
  STATE.signinError = null;
  render();
  try {
    await loadBrowserID(STATE.broker);
    window.navigator.id.watch({
      onlogin: async (presentation) => {
        try {
          await api("POST", "/admin/login", { presentation });
          await refresh();
        } catch (e) {
          STATE.signinError = e.data?.attempted ? { attempted: e.data.attempted } : { message: e.message };
        }
        render();
      },
      onlogout: () => {},
    });
    window.navigator.id.request({ siteName: "MCP Gateway" });
  } catch (e) {
    STATE.signinError = { message: e.message };
    render();
  }
}

async function signOut() {
  try { await api("POST", "/admin/logout"); } catch { /* ignore */ }
  STATE.signedIn = false;
  STATE.csrf = null;
  STATE.admin = null;
  STATE.signinError = null;
  STATE.prevPending = null;
  STATE.stagedOpen = false;
  render();
}

// --- derived data -----------------------------------------------------------

/** UI staged tag for a mount row: null | 'add' | 'edit' | 'remove'. */
const stagedOf = (m) => (m.pending === "new" ? "add" : m.pending === "changed" ? "edit" : m.pending === "removed" ? "remove" : null);
const STAGED_LABELS = { add: "staged: new", edit: "staged: edited", remove: "staged: removal" };

/** Mounts that survive the next restart (everything but staged removals). */
const keptMounts = () => STATE.mounts.filter((m) => m.pending !== "removed");

/** Roles that reach a mount: built-in, or ≥1 tool granted there. */
const rolesOn = (mountId) => STATE.roles.filter((r) => r.builtin || r.grants.some((g) => g.mountId === mountId && g.on.length));

/** Human summary of a role's grant on one mount ('*' = every tool). */
function grantCount(role, mount) {
  const total = mount.tools ? mount.tools.length : null;
  if (role.builtin) return total ? `all ${total} tools` : "all tools";
  const g = role.grants.find((x) => x.mountId === mount.id);
  const n = g ? g.on.length : 0;
  if (g && g.on.includes("*")) return total ? `all ${total} tools` : "all tools";
  return total ? `${n} of ${total} tools` : `${n} tools`;
}

// --- rendering --------------------------------------------------------------

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
function showToast(msg) {
  const t = el("div", "toast", msg);
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 3500);
}

let copyTimer = null;
async function copyUrl(url, id) {
  try { await navigator.clipboard.writeText(url); } catch { /* clipboard unavailable */ }
  STATE.copiedId = id;
  clearTimeout(copyTimer);
  copyTimer = setTimeout(() => { STATE.copiedId = null; render(); }, 1600);
  render();
}

function render() {
  renderHeader();
  const out = $("signed-out");
  const content = $("content");
  if (!STATE.signedIn) {
    out.hidden = false;
    content.hidden = true;
    renderSignedOut(out);
    return;
  }
  out.hidden = true;
  content.hidden = false;
  content.textContent = "";
  if (STATE.view === "servers") renderServers(content);
  else if (STATE.view === "people") renderPeople(content);
  else renderRoles(content);
}

// --- header -----------------------------------------------------------------

function renderHeader() {
  const tabs = $("tabs");
  const anchor = $("staged-anchor");
  const email = $("admin-email");
  const signout = $("signout");
  tabs.hidden = anchor.hidden = email.hidden = signout.hidden = !STATE.signedIn;
  if (!STATE.signedIn) return;

  tabs.textContent = "";
  for (const t of [["Servers", "servers"], ["People", "people"], ["Roles", "roles"]]) {
    tabs.appendChild(button(t[0], "tab" + (STATE.view === t[1] ? " active" : ""), () => {
      STATE.view = t[1];
      STATE.stagedOpen = false;
      render();
    }));
  }

  email.textContent = STATE.admin || "";

  anchor.textContent = "";
  const n = STATE.pending.length;
  const pill = el("button", "staged-pill " + (n ? "has" : "clean"));
  pill.appendChild(el("i", "dot"));
  pill.appendChild(document.createTextNode(n ? `${n} staged` : "in sync"));
  if (n) {
    pill.appendChild(el("span", "staged-caret", STATE.stagedOpen ? "▲" : "▼"));
    pill.addEventListener("click", () => { STATE.stagedOpen = !STATE.stagedOpen; render(); });
  } else {
    pill.disabled = true;
  }
  anchor.appendChild(pill);

  if (n && STATE.stagedOpen) {
    const pop = el("div", "staged-pop");
    pop.appendChild(el("div", "staged-pop-title", "Staged — restart to apply"));
    pop.appendChild(el("p", "staged-pop-sub", "saved to config · the running gateway hasn't changed"));
    const list = el("div", "staged-list");
    for (const ch of STATE.pending) {
      const item = el("div", "staged-item");
      item.appendChild(el("span", "staged-sign " + (ch.sign === "+" ? "add" : ch.sign === "−" ? "del" : "edit"), ch.sign));
      item.appendChild(el("span", null, ch.label));
      item.appendChild(el("span", "staged-desc", ch.desc));
      list.appendChild(item);
    }
    pop.appendChild(list);
    pop.appendChild(el("div", "staged-apply", "To apply, restart the gateway."));
    anchor.appendChild(pop);
  }
}

// --- sign-in ----------------------------------------------------------------

function renderSignedOut(root) {
  root.textContent = "";
  const wrap = el("div", "signin-wrap");
  const card = el("div", "signin-card");
  card.appendChild(el("div", "signin-accent"));
  card.appendChild(el("div", "kicker", "Admin console"));
  card.appendChild(el("h1", null, "Manage your gateway"));
  card.appendChild(el("p", "signin-body", "This gateway publishes local MCP servers at URLs your agents can reach — you decide who connects, by email."));
  card.appendChild(button("Sign in with BrowserID", "btn-signin", signIn));
  if (STATE.signinError) {
    const box = el("div", "signin-err");
    if (STATE.signinError.attempted) {
      box.appendChild(el("b", null, "That identity can't manage this gateway."));
      box.appendChild(el("br"));
      box.appendChild(document.createTextNode("You signed in as "));
      box.appendChild(el("code", null, STATE.signinError.attempted));
      box.appendChild(document.createTextNode(", but this gateway belongs to a different user. Try again with the admin identity."));
    } else {
      box.appendChild(el("b", null, "Sign-in failed."));
      box.appendChild(el("br"));
      box.appendChild(document.createTextNode(STATE.signinError.message));
    }
    card.appendChild(box);
  }
  card.appendChild(el("p", "signin-foot", "Only the gateway's admin — the one identity set at launch — can get in. No passwords, no API keys."));
  wrap.appendChild(card);
  root.appendChild(wrap);
}

// --- servers tab ------------------------------------------------------------

function renderServers(root) {
  const head = el("div", "page-head");
  head.appendChild(el("h1", null, "MCP servers"));
  const running = STATE.mounts.filter((m) => m.running).length;
  head.appendChild(el("span", "page-sum", STATE.mounts.length ? `${running} running · ${STATE.mounts.length} configured` : ""));
  head.appendChild(el("span", "spacer"));
  head.appendChild(button("+ Add an MCP", "btn-gold", () => openDialog(null)));
  root.appendChild(head);
  root.appendChild(el("p", "page-sub", "Each server below is published at a URL. Copy it into your agent — or hand it to someone whose role grants them tools here."));

  if (!STATE.mounts.length) {
    const empty = el("div", "empty-panel");
    empty.appendChild(el("div", "empty-title", "No MCP servers yet"));
    empty.appendChild(el("p", "empty-body", "Adding one takes a name, a URL path, and the command that runs it. The gateway publishes it at a shareable URL — reachable only by people whose role grants access."));
    empty.appendChild(button("+ Add an MCP", "btn-gold big", () => openDialog(null)));
    root.appendChild(empty);
    return;
  }

  const panel = el("div", "list-panel");
  for (const m of STATE.mounts) panel.appendChild(serverRow(m));
  root.appendChild(panel);
}

function serverRow(m) {
  const staged = stagedOf(m);
  const removing = staged === "remove";
  const dot = removing ? "removed" : staged === "add" ? "addstaged" : !m.enabled ? "disabled" : "running";
  const statusLabel = removing ? "removal staged" : staged === "add" ? "not started yet" : !m.enabled ? "disabled" : "running";
  const expanded = STATE.expanded === m.id;

  const wrap = el("div", "m-wrap" + (removing || !m.enabled ? " dim" : ""));
  const headRow = el("div", "m-head");
  headRow.addEventListener("click", () => { STATE.expanded = expanded ? null : m.id; render(); });
  const dotEl = el("i", "dot8 " + dot);
  dotEl.title = statusLabel;
  headRow.appendChild(dotEl);
  headRow.appendChild(el("span", "m-name", m.name));
  headRow.appendChild(el("span", "m-path", `/${m.mount}`));
  if (staged) headRow.appendChild(el("span", "m-staged", STAGED_LABELS[staged]));
  else if (!m.enabled) headRow.appendChild(el("span", "m-quiet", statusLabel));
  headRow.appendChild(el("span", "spacer"));
  const rowCopy = button(STATE.copiedId === m.id ? "Copied ✓" : "Copy URL", "btn-copy" + (STATE.copiedId === m.id ? " copied" : ""), (e) => {
    e.stopPropagation();
    copyUrl(m.url, m.id);
  });
  headRow.appendChild(rowCopy);
  headRow.appendChild(el("span", "chev", expanded ? "▾" : "▸"));
  wrap.appendChild(headRow);

  if (expanded) wrap.appendChild(serverBody(m, staged, removing));
  return wrap;
}

function serverBody(m, staged, removing) {
  const body = el("div", "m-body");

  // URL well
  const well = el("div", "url-well");
  const code = el("code");
  const base = (STATE.origin || "").replace(/\/+$/, "");
  code.appendChild(el("span", "url-dim", `${base}/`));
  code.appendChild(el("span", "url-path", m.mount));
  code.appendChild(el("span", "url-dim", "/mcp"));
  well.appendChild(code);
  well.appendChild(button(STATE.copiedId === m.id ? "Copied ✓" : "Copy", "btn-copy" + (STATE.copiedId === m.id ? " copied" : ""), () => copyUrl(m.url, m.id)));
  body.appendChild(well);

  // Command
  const cmdSec = el("div");
  cmdSec.appendChild(el("div", "sec-label", "Command"));
  const cmd = el("code", "cmd-well");
  cmd.appendChild(el("span", "url-dim", "$"));
  cmd.appendChild(document.createTextNode(" " + m.command.join(" ")));
  cmdSec.appendChild(cmd);
  body.appendChild(cmdSec);

  // Tools
  const toolSec = el("div");
  toolSec.appendChild(el("div", "sec-label", "Tools"));
  if (m.tools) {
    const pills = el("div", "tool-pills");
    for (const t of m.tools) pills.appendChild(el("span", "tool-pill", t));
    toolSec.appendChild(pills);
  } else {
    toolSec.appendChild(el("div", "tools-unknown", "Not started yet — the gateway will query this server's tools after you restart."));
  }
  body.appendChild(toolSec);

  // Access
  const accSec = el("div");
  const labRow = el("div", "sec-label-row");
  labRow.appendChild(el("span", "sec-label", "Access"));
  labRow.appendChild(button("manage in Roles →", "link-cyan", () => { STATE.view = "roles"; render(); }));
  accSec.appendChild(labRow);
  const reaching = rolesOn(m.id);
  if (reaching.length) {
    const grid = el("div", "access-grid");
    for (const r of reaching) {
      grid.appendChild(el("span", "access-role" + (r.builtin ? " builtin" : ""), r.name));
      grid.appendChild(el("span", "access-emails", r.members.length ? r.members.join(", ") : "nobody yet"));
      grid.appendChild(el("span", "access-count", grantCount(r, m)));
    }
    accSec.appendChild(grid);
  } else {
    accSec.appendChild(el("span", "access-none", "only you — no role grants tools here yet"));
  }
  body.appendChild(accSec);

  // Inline remove confirm
  if (STATE.confirming === m.id) {
    const box = el("div", "rm-confirm");
    const text = el("span", "rm-confirm-text");
    text.appendChild(document.createTextNode("Remove "));
    text.appendChild(el("b", null, m.name));
    text.appendChild(document.createTextNode("? It keeps running until you restart — removal is staged like any other change."));
    box.appendChild(text);
    box.appendChild(button("Stage removal", "btn-red", () => {
      STATE.confirming = null;
      mutate(() => api("DELETE", `/admin/mounts/${encodeURIComponent(m.id)}`));
    }));
    box.appendChild(button("Cancel", "btn-plain", () => { STATE.confirming = null; render(); }));
    body.appendChild(box);
  }

  // Actions
  const actions = el("div", "row-actions");
  if (!removing) {
    actions.appendChild(button("Edit", "btn-mini", () => openDialog(m)));
    actions.appendChild(button(m.enabled ? "Disable" : "Enable", "btn-mini", () =>
      mutate(() => api("PATCH", `/admin/mounts/${encodeURIComponent(m.id)}`, { enabled: !m.enabled }))));
    actions.appendChild(button("Remove", "btn-mini-red", () => { STATE.confirming = m.id; render(); }));
  } else {
    actions.appendChild(button("Undo remove", "btn-mini strong", () =>
      mutate(() => api("POST", `/admin/mounts/${encodeURIComponent(m.id)}/restore`))));
  }
  body.appendChild(actions);
  return body;
}

// --- add/edit dialog --------------------------------------------------------

function openDialog(m) {
  const root = $("modal-root");
  root.textContent = "";
  const editId = m ? m.id : null;

  const backdrop = el("div", "modal-backdrop");
  backdrop.addEventListener("click", (e) => { if (e.target === backdrop) close(); });
  const card = el("div", "modal-card");
  card.setAttribute("role", "dialog");
  card.setAttribute("aria-modal", "true");
  card.appendChild(el("h2", null, editId ? "Edit MCP server" : "Add an MCP server"));
  card.appendChild(el("p", "modal-sub", "Tell the gateway what to run and where to publish it."));

  const fields = el("div", "fields");
  const mkField = (labText, input) => {
    const lab = el("label", "f-label");
    lab.appendChild(el("span", "lab", labText));
    lab.appendChild(input);
    return lab;
  };
  const fName = el("input", "f-input");
  fName.placeholder = "Dan's Notes";
  fName.value = m ? m.name : "";
  fields.appendChild(mkField("Name", fName));

  const fPath = el("input", "f-input mono");
  fPath.placeholder = "notes";
  fPath.value = m ? m.mount : "";
  const pathLab = mkField("Mount path", fPath);
  const preview = el("span", "path-preview");
  const base = (STATE.origin || "").replace(/\/+$/, "");
  preview.appendChild(el("span", null, `will publish at  ${base}/`));
  const previewPath = el("span", "url-path", m ? m.mount : "path");
  preview.appendChild(previewPath);
  preview.appendChild(el("span", null, "/mcp"));
  pathLab.appendChild(preview);
  const inlineErr = el("span", "f-inline-err");
  inlineErr.hidden = true;
  pathLab.appendChild(inlineErr);
  fields.appendChild(pathLab);

  const fCmd = el("input", "f-input mono-sm");
  fCmd.placeholder = "npx -y @modelcontextprotocol/server-filesystem ~/notes";
  fCmd.value = m ? m.command.join(" ") : "";
  fields.appendChild(mkField("Command", fCmd));
  card.appendChild(fields);

  const err = el("p", "f-err");
  err.hidden = true;
  card.appendChild(err);

  const slugOk = (s) => /^[a-z0-9][a-z0-9-]*$/.test(s);
  const dup = (s) => keptMounts().some((x) => x.mount === s && x.id !== editId);
  const updatePath = () => {
    fPath.value = fPath.value.toLowerCase();
    const slug = fPath.value.trim();
    previewPath.textContent = slug || "path";
    const bad = !!slug && (!slugOk(slug) || dup(slug));
    inlineErr.hidden = !bad;
    if (bad) inlineErr.textContent = dup(slug) ? "That mount path is already taken." : "Lowercase letters, digits and dashes only.";
    err.hidden = true;
  };
  fPath.addEventListener("input", updatePath);
  fName.addEventListener("input", () => { err.hidden = true; });
  fCmd.addEventListener("input", () => { err.hidden = true; });

  const validate = () => {
    if (!fName.value.trim()) return "Give it a name.";
    const slug = fPath.value.trim();
    if (!slug) return "Mount path is required.";
    if (!slugOk(slug)) return "Mount path must be lowercase letters, digits and dashes.";
    if (dup(slug)) return "That mount path is already taken.";
    if (!fCmd.value.trim()) return "Command is required.";
    return "";
  };

  const close = () => { root.textContent = ""; };
  const actions = el("div", "modal-actions");
  actions.appendChild(button("Cancel", "btn-cancel", close));
  actions.appendChild(button(editId ? "Save — applies on restart" : "Save — publishes on restart", "btn-save", async () => {
    const msg = validate();
    if (msg) { err.textContent = msg; err.hidden = false; return; }
    const def = { name: fName.value.trim(), mount: fPath.value.trim(), command: fCmd.value.trim() };
    try {
      if (editId) {
        await api("PATCH", `/admin/mounts/${encodeURIComponent(editId)}`, def);
      } else {
        const row = await api("POST", "/admin/mounts", def);
        STATE.expanded = row.id; // auto-expand the new server's row
      }
      close();
      await refresh();
      render();
    } catch (e) {
      err.textContent = e.message;
      err.hidden = false;
    }
  }));
  card.appendChild(actions);
  backdrop.appendChild(card);
  root.appendChild(backdrop);
  fName.focus();
}

// --- people tab -------------------------------------------------------------

function renderPeople(root) {
  const head = el("div", "page-head");
  head.appendChild(el("h1", null, "People"));
  head.appendChild(el("span", "page-sum", `${STATE.people.length} people`));
  root.appendChild(head);
  root.appendChild(el("p", "page-sub", "Your address book. Being here grants nothing — access comes from the roles a person is in."));

  const panel = el("div", "list-panel");
  const avatarTints = ["gold", "cyan", "green"];
  const kept = keptMounts();

  STATE.people.forEach((p, i) => {
    const row = el("div", "p-row");
    row.appendChild(el("span", "avatar " + avatarTints[i % 3], p.name.slice(0, 2)));

    const main = el("span", "p-main");
    const nameLine = el("span", "p-name");
    nameLine.appendChild(document.createTextNode(p.name + " "));
    nameLine.appendChild(el("span", "p-email", p.email));
    main.appendChild(nameLine);
    let summary;
    if (p.admin) {
      summary = "full access to everything — implicit, not a role";
    } else {
      const inRoles = STATE.roles.filter((r) => r.members.includes(p.email));
      const reach = new Set(
        inRoles.flatMap((r) => (r.builtin ? kept.map((m) => m.id) : r.grants.filter((g) => g.on.length).map((g) => g.mountId)))
      );
      const n = [...reach].filter((id) => kept.some((m) => m.id === id)).length;
      summary = `can reach ${n} ${n === 1 ? "server" : "servers"}`;
    }
    main.appendChild(el("span", "p-sum", summary));
    row.appendChild(main);

    if (p.admin) {
      const badge = el("span", "badge-admin", "admin");
      badge.title = "The admin identity always has full access — it isn't a role";
      row.appendChild(badge);
    } else {
      const chips = el("span", "chips");
      for (const r of STATE.roles) {
        const on = r.members.includes(p.email);
        const chip = el("button", "chip " + (on ? (r.builtin ? "on-gold" : "on-cyan") : "off"));
        chip.appendChild(el("span", "check", on ? "✓" : ""));
        chip.appendChild(document.createTextNode(r.name));
        chip.title = `${on ? "Remove from" : "Add to"} ${r.name} — staged, applies on restart`;
        chip.addEventListener("click", () => {
          const members = on ? r.members.filter((e) => e !== p.email) : [...r.members, p.email];
          mutate(() => api("PATCH", `/admin/roles/${encodeURIComponent(r.id)}`, { members }));
        });
        chips.appendChild(chip);
      }
      row.appendChild(chips);

      const x = el("button", "x-btn", "×");
      x.setAttribute("aria-label", "Remove person");
      x.title = "Remove from address book and all roles";
      x.addEventListener("click", () => mutate(() => api("DELETE", `/admin/people/${encodeURIComponent(p.email)}`)));
      row.appendChild(x);
    }
    panel.appendChild(row);
  });

  const addRow = el("div", "add-row");
  const nameIn = el("input", "input w130");
  nameIn.placeholder = "Name";
  nameIn.value = STATE.drafts.personName;
  nameIn.addEventListener("input", () => { STATE.drafts.personName = nameIn.value; });
  const emailIn = el("input", "input mono grow");
  emailIn.placeholder = "email@example.com";
  emailIn.value = STATE.drafts.personEmail;
  emailIn.addEventListener("input", () => { STATE.drafts.personEmail = emailIn.value; });
  addRow.appendChild(nameIn);
  addRow.appendChild(emailIn);
  addRow.appendChild(button("Add person", "btn-cyan", () => {
    const email = emailIn.value.trim();
    if (!email || !email.includes("@")) return;
    STATE.drafts.personName = "";
    STATE.drafts.personEmail = "";
    mutate(() => api("POST", "/admin/people", { name: nameIn.value.trim(), email }));
  }));
  panel.appendChild(addRow);
  root.appendChild(panel);

  root.appendChild(el("p", "foot-note", "The admin identity (set at launch) always has full access — it never appears in a role."));
}

// --- roles tab --------------------------------------------------------------

function renderRoles(root) {
  const head = el("div", "page-head");
  head.appendChild(el("h1", null, "Roles"));
  head.appendChild(el("span", "page-sum", `${STATE.roles.length} roles`));
  root.appendChild(head);
  root.appendChild(el("p", "page-sub wide", "Roles are the editor: a role grants tools — per server, per tool. What people can actually use comes from the access grants YOU SIGN below — each person's grant is a record signed with your browserid, revocable any time from your account page."));
  renderGrantsPanel(root);

  const list = el("div", "roles-list");
  for (const r of STATE.roles) list.appendChild(roleCard(r));

  const create = el("div", "new-role-panel");
  const nameIn = el("input", "input grow");
  nameIn.placeholder = "New role name — e.g. Housemates";
  nameIn.value = STATE.drafts.roleName;
  nameIn.addEventListener("input", () => { STATE.drafts.roleName = nameIn.value; });
  create.appendChild(nameIn);
  create.appendChild(button("Create role", "btn-cyan", () => {
    const name = nameIn.value.trim();
    if (!name) return;
    STATE.drafts.roleName = "";
    mutate(async () => {
      const role = await api("POST", "/admin/roles", { name });
      STATE.roleExpanded = role.id; // auto-expand the new role
    });
  }));
  list.appendChild(create);
  root.appendChild(list);
}

// --- signed grants (spec §6.5): the enforcement source -----------------------
// Roles compile to flat per-(person, server) grants; the admin signs them at
// the broker's consent card. Until signed, an edit grants nothing.

async function refreshGrants() {
  try { STATE.grants = await api("GET", "/admin/grants"); } catch { STATE.grants = null; }
}

function renderGrantsPanel(root) {
  const g = STATE.grants;
  const panel = el("div", "new-role-panel");
  panel.style.marginBottom = "16px";
  if (!g) {
    panel.appendChild(el("span", "page-sum", "Loading grant status…"));
    refreshGrants().then(render);
    root.appendChild(panel);
    return;
  }
  const pending = g.pending?.length || 0;
  const stale = g.stale?.length || 0;
  const signedN = g.signed?.length || 0;
  const st = g.signState;

  if (st?.status === "pending") {
    panel.appendChild(el("span", "page-sum", "Waiting for your signature at the broker… "));
    const a = document.createElement("a");
    a.href = st.consentUri;
    a.target = "_blank";
    a.textContent = "open the consent card";
    panel.appendChild(a);
    if (!grantsPollTimer) {
      grantsPollTimer = setInterval(async () => {
        await refreshGrants();
        const now = STATE.grants?.signState;
        if (now?.status !== "pending") { clearInterval(grantsPollTimer); grantsPollTimer = null; }
        render();
      }, 2000);
    }
  } else if (pending || stale) {
    panel.appendChild(el("span", "page-sum",
      `${pending} grant${pending === 1 ? "" : "s"} awaiting your signature` +
      (stale ? ` · ${stale} to remove` : "") + " — "));
    panel.appendChild(button("Sign at browserid", "btn-cyan", () => {
      mutate(async () => {
        const out = await api("POST", "/admin/grants/sign");
        await refreshGrants();
        if (out?.consentUri || STATE.grants?.signState?.consentUri) {
          window.open(out?.consentUri || STATE.grants.signState.consentUri, "_blank");
        }
      });
    }));
  } else {
    panel.appendChild(el("span", "page-sum",
      `${signedN} signed grant${signedN === 1 ? "" : "s"} in force — everything you configured is signed.`));
    if (st?.status === "error") panel.appendChild(el("span", "err", ` Last signing failed: ${st.error}`));
  }
  root.appendChild(panel);
}

let grantsPollTimer = null;

function roleCard(r) {
  const expanded = STATE.roleExpanded === r.id;
  const card = el("div", "role-card" + (r.builtin ? " builtin" : ""));

  const kept = keptMounts();
  const grantSummary = r.builtin
    ? "every tool on every server"
    : r.grants
        .filter((g) => g.on.length)
        .map((g) => {
          const m = STATE.mounts.find((x) => x.id === g.mountId);
          const path = m ? m.mount : g.mountId;
          return g.on.includes("*") ? `all tools on /${path}` : `${g.on.length} tools on /${path}`;
        })
        .join(" · ") || "nothing granted yet";

  const headBtn = el("button", "role-head");
  headBtn.addEventListener("click", () => { STATE.roleExpanded = expanded ? null : r.id; render(); });
  headBtn.appendChild(el("span", "avatar " + (r.builtin ? "gold" : "cyan"), r.name.slice(0, 2)));
  const main = el("span", "role-main");
  const nameLine = el("span", "role-name");
  nameLine.appendChild(document.createTextNode(r.name + " "));
  if (r.builtin) nameLine.appendChild(el("span", "badge-builtin", "built-in"));
  main.appendChild(nameLine);
  main.appendChild(el("span", "role-sum", `${r.members.length} ${r.members.length === 1 ? "person" : "people"} · ${grantSummary}`));
  headBtn.appendChild(main);
  headBtn.appendChild(el("span", "role-chev", expanded ? "▾" : "▸"));
  card.appendChild(headBtn);

  if (!expanded) return card;
  const body = el("div", "role-body");

  // Members (read-only here; edited in People)
  const memSec = el("div");
  const memLab = el("div", "sec-label-row");
  memLab.appendChild(el("span", "sec-label", "Members"));
  memLab.appendChild(button("manage in People →", "link-cyan", () => { STATE.view = "people"; render(); }));
  memSec.appendChild(memLab);
  memSec.appendChild(el("span", "member-list", r.members.length ? r.members.join(", ") : "nobody yet"));
  body.appendChild(memSec);

  if (r.builtin) {
    const note = el("div", "builtin-note");
    note.appendChild(el("b", null, "Every tool, every server"));
    note.appendChild(document.createTextNode(" — including servers you add later. Use it sparingly; a normal role is safer."));
    body.appendChild(note);
  } else {
    for (const m of kept) body.appendChild(grantSection(r, m));
  }

  const foot = el("div", "role-foot");
  foot.appendChild(el("p", null, "Changes to roles apply on the next restart."));
  if (!r.builtin) {
    foot.appendChild(button("Delete role", "btn-mini-red", () =>
      mutate(() => api("DELETE", `/admin/roles/${encodeURIComponent(r.id)}`))));
  }
  body.appendChild(foot);
  card.appendChild(body);
  return card;
}

function grantSection(r, m) {
  const sec = el("div");
  const g = r.grants.find((x) => x.mountId === m.id) || { on: [] };
  const starred = g.on.includes("*");
  const onCount = starred && m.tools ? m.tools.length : g.on.length;
  const summary = m.tools
    ? onCount
      ? `${onCount} of ${m.tools.length} tools`
      : "nothing granted"
    : "not started yet";
  const lab = el("div", "sec-label");
  lab.appendChild(document.createTextNode(m.name + " "));
  lab.appendChild(el("span", "grant-label-sub", `— ${summary}`));
  sec.appendChild(lab);

  if (!m.tools) {
    sec.appendChild(el("div", "grant-unknown", "Tools unknown until restart — nothing to grant yet. This row fills in once the server has started."));
    return sec;
  }

  const grid = el("div", "grant-grid");
  for (const t of m.tools) {
    const on = starred || g.on.includes(t);
    const lbl = el("label", "grant-tool");
    const box = document.createElement("input");
    box.type = "checkbox";
    box.checked = on;
    box.addEventListener("change", () => {
      // Compute the next grants list for THIS role: expand '*' first, then toggle.
      const current = starred ? [...m.tools] : [...g.on];
      const next = on ? current.filter((x) => x !== t) : [...current, t];
      const grants = r.grants.filter((x) => x.mountId !== m.id);
      if (next.length) grants.push({ mountId: m.id, on: next });
      mutate(() => api("PATCH", `/admin/roles/${encodeURIComponent(r.id)}`, { grants }));
    });
    lbl.appendChild(box);
    lbl.appendChild(el("span", on ? "on" : "off", t));
    grid.appendChild(lbl);
  }
  sec.appendChild(grid);
  return sec;
}

// --- boot -------------------------------------------------------------------

async function boot() {
  initTheme();
  $("theme-btn").addEventListener("click", () => {
    const t = STATE.theme === "dark" ? "light" : "dark";
    try { localStorage.setItem("gate-admin-theme", t); } catch { /* private mode */ }
    applyTheme(t);
  });
  $("signout").addEventListener("click", signOut);

  // Close the staged popover on any click outside its anchor.
  document.addEventListener("click", (e) => {
    if (!STATE.stagedOpen) return;
    const anchor = $("staged-anchor");
    if (anchor && !anchor.contains(e.target)) {
      STATE.stagedOpen = false;
      render();
    }
  }, true);

  const bootData = await api("GET", "/admin/bootstrap");
  STATE.broker = bootData.broker;
  STATE.origin = bootData.origin;
  if (bootData.signedIn) await refresh();
  render();
}

window.addEventListener("DOMContentLoaded", () => {
  boot().catch((e) => {
    showToast(e.message);
    render();
  });
});
