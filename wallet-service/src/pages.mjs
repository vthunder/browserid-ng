// HTML for the two human-facing pages: the OAuth authorize page (browserid
// sign-in + connect approval) and a minimal landing page. The authorize page
// re-reads the OAuth params from location.search client-side; the server
// re-validates everything at /oauth/approve, so the page carries no
// authorization state of its own.
import { BROKER, WALLET_ORIGIN } from "./config.mjs";

const esc = (s) =>
  String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const STYLE = `<style>
  body{font:16px/1.6 system-ui;max-width:30rem;margin:4rem auto;padding:0 1rem;color:#1a1a1a}
  @media(prefers-color-scheme:dark){body{background:#111;color:#eee}}
  button{font:inherit;padding:.6rem 1.2rem;border-radius:8px;border:1px solid #8886;cursor:pointer}
  button.primary{background:#2563eb;color:#fff;border-color:#2563eb}
  code{background:#8882;padding:.1em .4em;border-radius:4px}
  .muted{color:#888;font-size:.85em}
  .card{border:1px solid #8884;border-radius:12px;padding:1.5rem;margin:1.5rem 0}
</style>`;

/** GET /authorize — sign in with browserid, then approve the connection. */
export function authorizePage({ clientName }) {
  return `<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Connect to your browserid wallet</title>${STYLE}
<h1>browserid wallet</h1>
<div class=card>
  <p><strong>${esc(clientName || "An application")}</strong> is asking to connect to your hosted
  agent wallet. If you approve, it can drive your wallet's agent identity:
  request approvals from you, and sign in at sites <em>you</em> grant warrants for.</p>
  <p id=state>checking session…</p>
  <button id=login class=primary hidden>Sign in with browserid</button>
  <button id=approve class=primary hidden>Connect</button>
  <button id=deny hidden>Cancel</button>
  <p class=muted>Signed-in identity: <code id=who>–</code></p>
</div>
<p class=muted>Approvals for anything your agent later does still happen at ${esc(BROKER)} —
connecting here only links this app to your wallet.</p>
<script src="${esc(BROKER)}/include.js"></script>
<script>
const $ = (id) => document.getElementById(id);
const params = Object.fromEntries(new URLSearchParams(location.search));
let email = null;
function render() {
  $('who').textContent = email || '–';
  $('login').hidden = !!email;
  $('approve').hidden = $('deny').hidden = !email;
  $('state').textContent = email ? 'Approve connecting this app to your wallet?' : 'Sign in to continue.';
}
async function refresh() {
  const me = await (await fetch('/oauth/me')).json();
  email = me.email || null;
  render();
}
navigator.id.watch({
  loggedInUser: null,
  onlogin: async (presentation) => {
    $('state').textContent = 'verifying…';
    const r = await fetch('/oauth/login', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ presentation }),
    });
    if (!r.ok) { $('state').textContent = 'sign-in failed: ' + (await r.json()).reason; return; }
    await refresh();
  },
  onlogout: () => {},
});
$('login').onclick = () => navigator.id.request({ siteName: 'browserid wallet' });
$('approve').onclick = async () => {
  $('state').textContent = 'connecting…';
  const r = await fetch('/oauth/approve', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify(params),
  });
  const body = await r.json();
  if (!r.ok) { $('state').textContent = 'failed: ' + (body.error || 'unknown error'); return; }
  location.href = body.redirect;
};
$('deny').onclick = () => { $('state').textContent = 'Cancelled. You can close this tab.'; $('approve').hidden = $('deny').hidden = true; };
refresh();
</script>`;
}

/** GET / — what this host is. */
export function landingPage() {
  return `<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>browserid hosted wallet</title>${STYLE}
<h1>browserid hosted wallet</h1>
<p>A <a href="https://modelcontextprotocol.io">remote MCP server</a> that gives agents
which can't run code — claude.ai web and mobile — their own
<a href="${esc(BROKER)}">browserid</a> identity.</p>
<div class=card>
  <p><strong>Add it to claude.ai:</strong> Settings → Connectors → Add custom connector, URL:</p>
  <p><code>${esc(WALLET_ORIGIN)}/mcp</code></p>
  <p>Then ask your agent to provision a browserid identity and sign the guestbook.</p>
</div>
<p class=muted>Your agent's key is custodied here (sign-only, encrypted at rest, audited).
Prefer the key on your own machine? Use the local wallet:
<code>npx -y @browserid-ng/wallet</code>. Grants and revocation always live at ${esc(BROKER)}.</p>`;
}
