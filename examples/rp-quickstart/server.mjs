// The 5-minute relying-party: passwordless human sign-in with browserid-ng
// (device-cert model).
//
// The whole integration is the /api/login handler below: take the access
// presentation the browser produced (browserid.login()), verify it against
// YOUR origin, and start a session. No passwords, no registration, no client
// secret.
//
// Config (env):
//   PORT         listen port (default 8080)
//   RP_ORIGIN    your public origin, the audience you pin (default http://localhost:PORT)
//   BROKER       broker origin serving include.js + the dialog (default https://browserid.me)
//   VERIFIER_URL /verify-access URL (default the broker's). Point at your own to self-verify.
//   SESSION_SECRET  HMAC key for the session cookie (default: dev-only constant)

import { createServer } from "node:http";
import { createHmac, timingSafeEqual } from "node:crypto";
import { createVerifier } from "@browserid-ng/verify";

const PORT = Number(process.env.PORT || 8080);
const RP_ORIGIN = process.env.RP_ORIGIN || `http://localhost:${PORT}`;
const BROKER = process.env.BROKER || "https://browserid.me";
const SECRET = process.env.SESSION_SECRET || "dev-only-not-secret";
const verifier = createVerifier({ verifierUrl: process.env.VERIFIER_URL || `${BROKER}/verify-access` });

// --- tiny signed-cookie session (HMAC; no dependency) ----------------------
const b64 = (s) => Buffer.from(s).toString("base64url");
const unb64 = (s) => Buffer.from(s, "base64url").toString();
function sign(payloadObj) {
  const p = b64(JSON.stringify(payloadObj));
  const sig = createHmac("sha256", SECRET).update(p).digest("base64url");
  return `${p}.${sig}`;
}
function verifyCookie(token) {
  if (!token || !token.includes(".")) return null;
  const [p, sig] = token.split(".");
  const expect = createHmac("sha256", SECRET).update(p).digest("base64url");
  if (sig.length !== expect.length || !timingSafeEqual(Buffer.from(sig), Buffer.from(expect))) return null;
  try {
    const obj = JSON.parse(unb64(p));
    if (obj.exp && obj.exp < Date.now() / 1000) return null;
    return obj;
  } catch {
    return null;
  }
}
const cookieOf = (req) =>
  Object.fromEntries((req.headers.cookie || "").split(";").map((c) => c.trim().split("=").map(decodeURIComponent)).filter((x) => x[0]));

// --- page ------------------------------------------------------------------
const PAGE = `<!doctype html><meta charset=utf-8><title>browserid-ng RP quickstart</title>
<style>body{font:16px/1.6 system-ui;max-width:34rem;margin:4rem auto;padding:0 1rem}
button{font:inherit;padding:.5rem 1rem;border-radius:8px;border:1px solid #8884;cursor:pointer}
code{background:#8882;padding:.1em .4em;border-radius:4px}</style>
<h1>browserid-ng quickstart</h1>
<p id=state>checking…</p>
<button id=login hidden>Sign in</button>
<button id=logout hidden>Sign out</button>
<script src="${BROKER}/include.js"></script>
<script>
const $=id=>document.getElementById(id), state=$('state');
async function refresh(){ const me=await (await fetch('/api/me')).json();
  if(me.email){ state.innerHTML='Signed in as <code>'+me.email+'</code>'; $('login').hidden=true; $('logout').hidden=false; }
  else { state.textContent='Not signed in.'; $('login').hidden=false; $('logout').hidden=true; } }
navigator.id.watch({
  loggedInUser: null,
  onlogin: async (presentation)=>{
    state.textContent='verifying…';
    const resp=await fetch('/api/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({presentation})});
    if(!resp.ok){ const e=await resp.json(); state.textContent='sign-in failed: '+e.reason; return; }
    refresh();
  },
  onlogout: ()=>{}
});
$('login').onclick=()=>navigator.id.request({siteName:'RP Quickstart'});
$('logout').onclick=async()=>{ await fetch('/api/logout',{method:'POST'}); navigator.id.logout&&navigator.id.logout(); refresh(); };
refresh();
</script>`;

// --- server ----------------------------------------------------------------
function json(res, code, obj, headers = {}) {
  res.writeHead(code, { "content-type": "application/json", ...headers });
  res.end(JSON.stringify(obj));
}
function readBody(req) {
  return new Promise((resolve) => { let d = ""; req.on("data", (c) => (d += c)); req.on("end", () => resolve(d)); });
}

const server = createServer(async (req, res) => {
  if (req.method === "GET" && req.url === "/") {
    res.writeHead(200, { "content-type": "text/html" });
    return res.end(PAGE);
  }

  // THE INTEGRATION: verify the browser's presentation against your origin.
  if (req.method === "POST" && req.url === "/api/login") {
    let presentation;
    try { ({ presentation } = JSON.parse(await readBody(req))); } catch {}
    const r = await verifier.verify(presentation, RP_ORIGIN); // agents rejected by default
    if (!r.ok) return json(res, 401, { reason: r.reason });
    const session = sign({ email: r.email, exp: Math.floor(Date.now() / 1000) + 86400 });
    return json(res, 200, { email: r.email }, {
      "set-cookie": `sid=${session}; HttpOnly; SameSite=Lax; Path=/; Max-Age=86400`,
    });
  }

  if (req.method === "GET" && req.url === "/api/me") {
    const s = verifyCookie(cookieOf(req).sid);
    return json(res, 200, s ? { email: s.email } : {});
  }
  if (req.method === "POST" && req.url === "/api/logout") {
    return json(res, 200, { ok: true }, { "set-cookie": "sid=; HttpOnly; Path=/; Max-Age=0" });
  }
  json(res, 404, { reason: "not found" });
});

if (import.meta.url === `file://${process.argv[1]}`) {
  server.listen(PORT, () => console.error(`RP quickstart on ${RP_ORIGIN} (broker ${BROKER})`));
}
export { server, sign, verifyCookie };
