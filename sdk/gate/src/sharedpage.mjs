// The member landing page (Dan's day-one kit, 2026-08-15): the admin shares
// ONE url — the gateway's — and anyone it was shared with signs in at
// /shared to see every server they can use, with per-agent connect
// instructions. Session + entitlements come from the same identity-first
// machinery as connecting (/connect/login, gate_user cookie); the page
// itself is static HTML that fetches /shared/servers.

export function sharedPage() {
  return `<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Servers shared with you</title>
<style>
body{font:15px/1.6 -apple-system,system-ui,sans-serif;max-width:640px;margin:6vh auto 10vh;padding:0 24px;color:#1a1a1a}
h1{font-size:22px;margin:0 0 4px}
.sub{color:#6b6b74;margin:0 0 24px}
.card{border:1px solid rgba(0,0,0,.1);border-radius:14px;padding:18px 20px;margin-bottom:16px}
.card h2{font-size:17px;margin:0 0 2px}
.chips{margin:6px 0 12px}
.chip{display:inline-block;font:12px ui-monospace,monospace;background:#f2f3f5;border-radius:6px;padding:2px 8px;margin:2px 4px 2px 0}
.url{display:flex;gap:8px;align-items:center;margin-bottom:12px}
.url code{flex:1;font:13px ui-monospace,monospace;background:#f7f7f8;border:1px solid rgba(0,0,0,.08);border-radius:8px;padding:8px 10px;overflow-wrap:anywhere}
button{font:600 13px system-ui;padding:8px 14px;border-radius:8px;border:0;background:#17171a;color:#fff;cursor:pointer}
.tabs{display:flex;gap:6px;margin-bottom:8px}
.tab{font:12.5px system-ui;padding:5px 10px;border-radius:7px;border:1px solid rgba(0,0,0,.12);background:none;color:#1a1a1a;cursor:pointer}
.tab.active{background:#17171a;color:#fff;border-color:#17171a}
.howto{font-size:13.5px;color:#3a3a40;background:#faf9f7;border-radius:8px;padding:10px 12px}
.howto code{font:12.5px ui-monospace,monospace;background:#f0efec;border-radius:5px;padding:1px 5px;overflow-wrap:anywhere}
.foot{font-size:13px;color:#6b6b74;margin-top:24px}
.empty{border:1px dashed rgba(0,0,0,.2);border-radius:14px;padding:28px;text-align:center;color:#6b6b74}
a{color:inherit}
</style>
<h1>Servers shared with you</h1>
<p class="sub" id="who">Loading…</p>
<div id="list"></div>
<p class="foot">Signed in as the wrong address? <a href="/connect/login?next=%2Fshared&switch=1">Use a different account</a>.
Every call you make is attributed to you and revocable — by you or the person who shared — at any time.</p>
<script>
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const HOWTO = {
  "Claude (web/desktop)": (u, slug) =>
    'Open <b>Settings → Connectors → Add custom connector</b>, paste the URL above, and finish the sign-in it opens. The tools appear in your chats.',
  "Claude Code": (u, slug) =>
    'Run <code>claude mcp add --transport http ' + esc(slug) + ' ' + esc(u) + '</code>, then approve the sign-in link it prints.',
  "Cursor / other": (u, slug) =>
    'Add to your MCP config: <code>{"mcpServers":{"' + esc(slug) + '":{"url":"' + esc(u) + '"}}}</code> — any client speaking streamable HTTP + OAuth works.',
};
async function main() {
  const r = await fetch("/shared/servers", { credentials: "same-origin" });
  if (r.status === 401) { location.assign("/connect/login?next=%2Fshared"); return; }
  const j = await r.json();
  document.getElementById("who").textContent = "Shared with " + j.email + " on this gateway.";
  const list = document.getElementById("list");
  if (!j.servers.length) {
    list.innerHTML = '<div class="empty">Nothing is shared with ' + esc(j.email) +
      ' here yet. Ask the person who sent you this link to share a server with that address.</div>';
    return;
  }
  for (const s of j.servers) {
    const card = document.createElement("div");
    card.className = "card";
    const tabs = Object.keys(HOWTO);
    card.innerHTML = '<h2>' + esc(s.name) + '</h2>' +
      '<div class="chips">' + s.tools.map((t) => '<span class="chip">' + esc(t) + '</span>').join("") + '</div>' +
      '<div class="url"><code>' + esc(s.url) + '</code><button data-copy="' + esc(s.url) + '">Copy</button></div>' +
      '<div class="tabs">' + tabs.map((t, i) => '<button class="tab' + (i === 0 ? " active" : "") + '" data-t="' + esc(t) + '">' + esc(t) + '</button>').join("") + '</div>' +
      '<div class="howto"></div>';
    const show = (t) => {
      card.querySelector(".howto").innerHTML = HOWTO[t](s.url, s.slug);
      for (const b of card.querySelectorAll(".tab")) b.classList.toggle("active", b.dataset.t === t);
    };
    card.addEventListener("click", (ev) => {
      const b = ev.target.closest("button");
      if (!b) return;
      if (b.dataset.copy) { navigator.clipboard?.writeText(b.dataset.copy); b.textContent = "Copied"; setTimeout(() => { b.textContent = "Copy"; }, 1400); }
      if (b.dataset.t) show(b.dataset.t);
    });
    show(tabs[0]);
    list.appendChild(card);
  }
}
main().catch((e) => { document.getElementById("who").textContent = "Error: " + e.message; });
</script>`;
}
