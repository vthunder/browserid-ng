// Protocol ceremonies. The app replicates what dialog.js does on the
// browserid.me origin, from outside it:
//
//   bootstrap:  browser-grade session (interactive BrowserWindow login, or
//               password lane for tests) -> /device/issue -> device+config
//               certs under a browsers-namespace holder. One-time.
//   login:      self-signed login warrant (config key, per RP audience)
//               + /access/mint (device-cert-authed, no cookies)
//               + 300s assertion (access key)  -> 4-object presentation.
//
// Endpoint shapes per recon of dialog.js/device.rs and smoke-prod-dc.mjs.
const store = require('./store');
const { generateKey, jws, decodeJws, nowS, randHex } = require('./bidcrypto');

const BROKER = process.env.WALLET_BROKER || 'https://browserid.me';
const UA = 'BrowserID-Menubar-Wallet/0.1 (prototype)';

// ---------------------------------------------------------------------------
// Two fetch lanes:
//  - sessionFetch: carries the broker session. Interactive mode uses the
//    Electron BrowserWindow session (cookies live there); test mode uses a
//    plain in-memory cookie jar filled by authenticate_user.
//  - bareFetch: no cookies at all (/access/mint, /verify).
let electronSession = null; // set by bootstrapInteractive
let jarCookie = '';         // test lane

async function sessionFetch(path, opts = {}) {
  if (electronSession) {
    const res = await electronSession.fetch(BROKER + path, {
      ...opts,
      credentials: 'include',
      headers: { 'content-type': 'application/json', accept: 'application/json', ...opts.headers },
    });
    return { status: res.status, data: await res.json().catch(() => ({})) };
  }
  const res = await fetch(BROKER + path, {
    ...opts,
    headers: {
      'content-type': 'application/json', accept: 'application/json', 'user-agent': UA,
      ...(jarCookie ? { cookie: jarCookie } : {}), ...opts.headers,
    },
  });
  for (const c of res.headers.getSetCookie?.() || []) {
    if (c.startsWith('browserid_session=')) jarCookie = c.split(';')[0];
  }
  return { status: res.status, data: await res.json().catch(() => ({})) };
}

async function csrf() {
  const { data } = await sessionFetch('/wsapi/session_context');
  if (!data.csrf_token) throw new Error('no session_context csrf');
  return data;
}

// ---------------------------------------------------------------------------
// Primary-IdP hop: open the IdP's device-authorize page (fragment carries the
// pubkeys, per the dialog's contract), using the `return_url` delivery lane —
// on success the page navigates to return_url#device_cert=…&config_cert=…,
// which we intercept in Electron before it loads. The user authenticates
// first-party on the IdP page if their IdP session is cold.
function primaryHop({ deviceAuthUrl, email, devicePub, configPub, holder }) {
  const { BrowserWindow } = require('electron');
  const RETURN_URL = `${BROKER}/wallet-idp-return`; // never actually loaded
  return new Promise((resolve, reject) => {
    const win = new BrowserWindow({
      width: 480, height: 640, title: `Sign in to ${new URL(deviceAuthUrl).host}`,
      webPreferences: { partition: 'persist:browserid', nodeIntegration: false, contextIsolation: true },
    });
    const url = deviceAuthUrl +
      '#email=' + encodeURIComponent(email) +
      '&device_pubkey=' + encodeURIComponent(devicePub) +
      '&config_pubkey=' + encodeURIComponent(configPub) +
      (holder ? '&holder=' + encodeURIComponent(holder) : '') +
      // return_origin is a page precondition (postMessage lane target); the
      // return_url delivery lane is what we actually consume.
      '&return_origin=' + encodeURIComponent(new URL(BROKER).origin) +
      '&return_url=' + encodeURIComponent(RETURN_URL);

    const timeout = setTimeout(() => { win.close(); reject(new Error('IdP authorization timed out')); }, 3 * 60 * 1000);
    let settled = false;
    const finish = (fn, arg) => { if (!settled) { settled = true; clearTimeout(timeout); fn(arg); setImmediate(() => win.close()); } };

    const onNav = (event, navUrl) => {
      if (!navUrl.startsWith(RETURN_URL)) return;
      event.preventDefault();
      const frag = new URLSearchParams(navUrl.slice(navUrl.indexOf('#') + 1));
      if (frag.get('device_error')) return finish(reject, new Error(`IdP refused: ${frag.get('device_error')}`));
      const device_cert = frag.get('device_cert'), config_cert = frag.get('config_cert');
      if (!device_cert || !config_cert) return finish(reject, new Error('IdP return carried no certs'));
      finish(resolve, { device_cert, config_cert });
    };
    win.webContents.on('will-navigate', onNav);
    win.webContents.on('will-redirect', onNav);
    win.on('closed', () => { if (!settled) { settled = true; clearTimeout(timeout); reject(new Error('IdP window closed')); } });
    win.loadURL(url);
  });
}

// ---------------------------------------------------------------------------
// Bootstrap core: with an authenticated broker session in hand, issue the
// device + config pair and persist everything the steady state needs.
// Secondary (broker-vouched) identities issue at the broker's /device/issue;
// primary identities hop to their IdP's device-authorize page.
async function issueCredentials(email) {
  const ctx = await csrf();
  if (!ctx.authenticated) throw new Error('broker session not authenticated');

  const info = (await sessionFetch(`/wsapi/address_info?email=${encodeURIComponent(email)}`)).data;
  const bh = await sessionFetch('/wsapi/browser_holder');
  if (bh.status !== 200 || !bh.data.prefix) throw new Error(`browser_holder failed: ${bh.status}`);
  const holder = `${bh.data.prefix}.${randHex(5)}`; // prefix + 10 hex, like dialog.js:339

  const device = await generateKey();
  const config = await generateKey();

  let certs, issuer, mintUrl;
  if (info.type === 'primary') {
    if (!info.device_auth || !info.access_mint) throw new Error(`primary identity but no device_auth/access_mint in address_info`);
    certs = await primaryHop({
      deviceAuthUrl: info.device_auth, email,
      devicePub: device.x, configPub: config.x, holder,
    });
    issuer = info.issuer;
    mintUrl = info.access_mint;
  } else {
    const issue = await sessionFetch('/device/issue', {
      method: 'POST',
      body: JSON.stringify({
        csrf: ctx.csrf_token, email,
        device_pubkey: device.x, config_pubkey: config.x, holder,
      }),
    });
    if (issue.status !== 200 || !issue.data.device_cert) {
      throw new Error(`device/issue failed: ${issue.status} ${JSON.stringify(issue.data).slice(0, 200)}`);
    }
    certs = issue.data;
    issuer = ctx.domain;
    mintUrl = `${BROKER}/access/mint`;
  }

  const assignedHolder = decodeJws(certs.device_cert).holder;
  await store.set({
    identity: email,
    domain: issuer,       // access-request `domain` claim = the issuer
    mintUrl,
    holder: assignedHolder,
    holderPrefix: assignedHolder.split('.')[0],
    deviceKey: device.privJwk,
    deviceCert: certs.device_cert,
    configKey: config.privJwk,
    configCert: certs.config_cert,
    warrants: {},
    bootstrappedAt: nowS(),
  });
  return { email, holder: assignedHolder, issuer };
}

// Interactive bootstrap: open browserid.me in an Electron window, let the
// user sign in on the real site, then issue from that session.
async function startBootstrap({ notify, updateTray }) {
  const { BrowserWindow, session } = require('electron');
  const ses = session.fromPartition('persist:browserid');
  ses.setUserAgent(UA);
  electronSession = ses;

  const win = new BrowserWindow({
    width: 480, height: 640, title: 'Sign in to BrowserID',
    webPreferences: { partition: 'persist:browserid', nodeIntegration: false, contextIsolation: true },
  });
  // The account page may sign the user in via a window.open dialog —
  // allow child windows in the same session so that flow works in-app.
  win.webContents.setWindowOpenHandler(() => ({
    action: 'allow',
    overrideBrowserWindowOptions: { webPreferences: { partition: 'persist:browserid' } },
  }));
  win.loadURL(`${BROKER}/account`);

  // Poll the window's session until it is authenticated, then issue.
  const poll = setInterval(async () => {
    try {
      const { data } = await sessionFetch('/wsapi/session_context');
      if (!data.authenticated) return;
      clearInterval(poll);
      const emails = (await sessionFetch('/wsapi/list_emails')).data.emails || [];
      if (!emails.length) throw new Error('authenticated session has no emails');
      let email = emails[0];
      if (emails.length > 1) {
        const { dialog } = require('electron');
        const choices = emails.slice(0, 3);
        const { response } = await dialog.showMessageBox(win, {
          type: 'question',
          buttons: [...choices, 'Cancel'],
          cancelId: choices.length,
          message: 'Which identity should this wallet hold?',
        });
        if (response >= choices.length) throw new Error('user cancelled identity choice');
        email = choices[response];
      }
      const r = await issueCredentials(email);
      win.close();
      notify('BrowserID wallet', `Wallet bootstrapped as ${r.email}`);
      updateTray?.();
      startApprovalWatch({ notify });
    } catch (err) {
      clearInterval(poll);
      console.error('[wallet] bootstrap failed', err);
      notify('BrowserID wallet', `Bootstrap failed: ${err.message}`);
    }
  }, 1500);
  win.on('closed', () => clearInterval(poll));
}

// Test-lane bootstrap: direct password auth (no Electron window). Used by
// automated tests against a local broker; also the fallback if the user
// prefers typing credentials into the app.
async function bootstrapPassword({ email, pass }) {
  // No csrf: session_context only mints one once a session exists, and
  // authenticate_user itself is the session-minting call (smoke-prod-dc.mjs).
  const auth = await sessionFetch('/wsapi/authenticate_user', {
    method: 'POST',
    body: JSON.stringify({ email, pass, ephemeral: false }),
  });
  if (auth.status !== 200) throw new Error(`authenticate_user failed: ${auth.status} ${JSON.stringify(auth.data)}`);
  return issueCredentials(email);
}

// ---------------------------------------------------------------------------
// Login: build a presentation for an RP origin.
async function ensureWarrant(audience) {
  const s = store.state();
  const cached = (s.warrants || {})[audience];
  if (cached && decodeJws(cached).exp > nowS() + 3600) return cached;

  // Self-signed with the config (Authorization) key, exactly dialog.js:487-496.
  // Status allocation is best-effort session work; the prototype skips it
  // (v1 warrants carry no required status ref).
  const warrant = await jws(s.configKey, {
    typ: 'browserid-warrant-v1',
    iat: nowS(), exp: nowS() + 90 * 86400,
    grantor: s.identity, grantee: s.identity,
    holder: `${s.holderPrefix}.*`,
    audience, scopes: ['login'],
  });
  await store.set({ warrants: { ...(s.warrants || {}), [audience]: warrant } });
  return warrant;
}

async function mintAccess() {
  const s = store.state();
  const access = await generateKey();
  const areq = await jws(s.deviceKey, {
    typ: 'browserid-access-request-v1',
    iat: nowS(), exp: nowS() + 600, jti: randHex(16),
    domain: s.domain, identity: s.identity, holder: s.holder,
    'access-key': { algorithm: 'Ed25519', publicKey: access.x },
  });
  const mintUrl = s.mintUrl || `${BROKER}/access/mint`;
  const res = await fetch(mintUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json', 'user-agent': UA },
    body: JSON.stringify({ device_cert: s.deviceCert, access_request: areq }),
  });
  const mint = { status: res.status, data: await res.json().catch(() => ({})) };
  if (mint.status !== 200 || !mint.data.access_cert) {
    throw new Error(`access/mint failed: ${mint.status} ${mint.data.reason || JSON.stringify(mint.data).slice(0, 200)}`);
  }
  return { cert: mint.data.access_cert, privJwk: access.privJwk };
}

async function login({ origin, approveLogin }) {
  const s = store.state();
  if (!s.deviceCert) return { error: 'wallet not bootstrapped' };
  const ok = process.env.WALLET_AUTO_APPROVE === '1' || (await approveLogin({ origin, email: s.identity }));
  if (!ok) return { error: 'user cancelled' };

  const warrant = await ensureWarrant(origin);
  const access = await mintAccess();
  const assertion = await jws(access.privJwk, { exp: nowS() + 300, aud: origin });
  const presentation = `${access.cert}~${assertion}~${warrant}~${s.configCert}`;
  return { presentation, email: s.identity };
}

// ---------------------------------------------------------------------------
// Approval push: poll /wsapi/warrant_requests on the (interactive) broker
// session; native-notify on new pending requests. No external endpoint exists
// for this today (recon 2026-08-27) — this is the cookie-session workaround.
let approvalTimer = null;
const seenCodes = new Set();

// On app start: if the wallet is bootstrapped, re-attach the persisted
// Electron session so approval-watch works across restarts (the broker
// session cookie lives in the persist:browserid partition).
function resumeSession({ notify }) {
  if (!store.state().deviceCert) return;
  const { session } = require('electron');
  electronSession = session.fromPartition('persist:browserid');
  electronSession.setUserAgent(UA);
  startApprovalWatch({ notify });
}

function startApprovalWatch({ notify }) {
  if (approvalTimer || !electronSession) return;
  const { shell } = require('electron');
  approvalTimer = setInterval(async () => {
    try {
      const { status, data } = await sessionFetch('/wsapi/warrant_requests');
      if (status !== 200 || !data.requests) return;
      for (const req of data.requests) {
        if (seenCodes.has(req.code)) continue;
        seenCodes.add(req.code);
        const who = req.label || req.agent_email || 'An agent';
        const what = (req.grants || []).map((g) => `${g.scopes.join(',')} @ ${g.audience}`).join('; ');
        notify(`Approval requested: ${who}`, what || 'wants access', () =>
          shell.openExternal(`${BROKER}/consent/${encodeURIComponent(req.code)}`)
        );
      }
    } catch { /* session gone or offline — stay quiet */ }
  }, 60_000);
}

module.exports = { startBootstrap, bootstrapPassword, login, startApprovalWatch, resumeSession, BROKER };
if (process.env.WALLET_TEST === '1') module.exports.__testSessionFetch = sessionFetch;
