// PROD smoke against browserid.me: session-path device-cert flow.
// admin-create @example.com account -> authenticate -> /device/issue ->
// /access/mint -> warrant (config key) + assertion -> /verify-access.
import { webcrypto as crypto } from 'node:crypto';
const BASE = 'https://browserid.me';
const ADMIN = process.env.ADMIN_TOKEN;
const email = `smoke-dc-${Date.now()}@example.com`;
const pass = 'smoke-passw0rd!';

const b64uj = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const HDR = b64uj({ alg: 'EdDSA', typ: 'JWT' });
const nowS = () => Math.floor(Date.now() / 1000);
const rnd = () => [...crypto.getRandomValues(new Uint8Array(16))].map(b=>b.toString(16).padStart(2,'0')).join('');
async function gen() { const kp = await crypto.subtle.generateKey({name:'Ed25519'},false,['sign','verify']);
  return { priv: kp.privateKey, x: (await crypto.subtle.exportKey('jwk', kp.publicKey)).x }; }
async function jws(priv, claims) { const p = b64uj(claims);
  const sig = Buffer.from(await crypto.subtle.sign({name:'Ed25519'}, priv, new TextEncoder().encode(`${HDR}.${p}`))).toString('base64url');
  return `${HDR}.${p}.${sig}`; }

let cookie = '';
async function req(method, path, body, extra={}) {
  const r = await fetch(BASE+path, { method, headers: { 'content-type':'application/json', accept:'application/json', ...(cookie?{cookie}:{}) , ...extra }, body: body?JSON.stringify(body):undefined });
  const setc = r.headers.getSetCookie?.() || [];
  for (const c of setc) if (c.startsWith('browserid_session=')) cookie = c.split(';')[0];
  return { status: r.status, data: await r.json().catch(()=>({})) };
}
let failed = false;
const must = (n, ok, d='') => { console.log(`${ok?'✓':'✗'} ${n}${d?' — '+d:''}`); if(!ok) failed=true; };

// 1. seed account + session
let r = await req('POST','/admin/create_account',{ email, pass },{ 'x-admin-token': ADMIN });
must('admin create_account', r.status===200, JSON.stringify(r.data).slice(0,80));
r = await req('POST','/wsapi/authenticate_user',{ email, pass, ephemeral:false });
must('authenticate', r.status===200 && !!cookie);
const ctx = (await req('GET','/wsapi/session_context')).data;
must('session ctx', ctx.authenticated===true, `domain=${ctx.domain}`);

// 2. device issue
const device = await gen(), config = await gen();
r = await req('POST','/device/issue',{ csrf: ctx.csrf_token, email, device_pubkey: device.x, config_pubkey: config.x });
must('/device/issue', r.status===200 && !!r.data.device_cert && !!r.data.config_cert);
const dec = (j)=>JSON.parse(Buffer.from(j.split('.')[1],'base64url').toString());
const cc = dec(r.data.config_cert);
must('config cert has +* glob', (cc.identities||[]).some(i=>i.includes('+*')), JSON.stringify(cc.identities));

// 3. mint — the access request copies the device cert's broker-assigned holder
const access = await gen();
const holder = dec(r.data.device_cert).holder;
must('device cert has holder', typeof holder==='string' && holder.length>0, holder);
const areq = await jws(device.priv, { typ:'browserid-access-request-v1', iat:nowS(), exp:nowS()+600, jti:rnd(), domain: ctx.domain, identity: email, holder, 'access-key':{ algorithm:'Ed25519', publicKey: access.x } });
const mint = await req('POST','/access/mint',{ device_cert: r.data.device_cert, access_request: areq });
must('/access/mint', mint.status===200 && !!mint.data.access_cert, mint.data.reason||'');
must('access cert copied holder', dec(mint.data.access_cert||'e30.e30.').holder===holder, dec(mint.data.access_cert||'e30.e30.').holder);

// 4. warrant + assertion + verify — login warrant grants the holder's namespace
const audience = 'https://rp.example.com';
const loginMatcher = holder.includes('.') ? holder.slice(0, holder.indexOf('.'))+'.*' : holder;
const warrant = await jws(config.priv, { typ:'browserid-warrant-v1', iat:nowS(), exp:nowS()+90*86400, identifier: email, holder: loginMatcher, audience, scopes:['login'] });
const assertion = await jws(access.priv, { exp:nowS()+300, aud:audience });
const pres = `${mint.data.access_cert}~${assertion}~${warrant}~${r.data.config_cert}`;
const v = await req('POST','/verify-access',{ presentation: pres, audience });
must('/verify-access okay', v.data.status==='okay' && v.data.email===email, JSON.stringify(v.data));

console.log(failed ? '\nPROD SMOKE FAILED' : '\nPROD SMOKE OK');
process.exit(failed?1:0);
