// Single-login bootstrap (bean gxi9). Email-FIRST, issuer-first — the
// wallet's loyalty order:
//
//   1. ask WHICH email (native window, before any network auth)
//   2. unauthenticated /wsapi/address_info decides the lane:
//      - primary:  ONE login at the IDENTITY'S OWN IdP (device-authorize
//        hop); then the wallet joins the broker registry silently via
//        auth_with_presentation — no broker password ever.
//      - secondary: the broker IS the IdP, so the /account login is the
//        single login; /device/issue from that session.
//   3. persist keys+certs (encrypted at rest) and start the registry-API
//      inbox watch.
//
// The prototype bootstrapped broker-first (two logins for primaries); this
// inverts it. The one-time issuer session below is the ONLY cookie-carrying
// code in the app.
const path = require('path');
const store = require('./store');
const broker = require('./broker');
const { generateKey, decodeJws, nowS, randHex } = require('./crypto');

// ---------------------------------------------------------------------------
// The one-time issuer session (secondary lane). Interactive mode uses the
// Electron BrowserWindow session; the test lane uses a plain cookie jar
// filled by authenticate_user.
let electronSession = null;
let jarCookie = '';

async function sessionFetch(path_, opts = {}) {
  if (electronSession) {
    const res = await electronSession.fetch(broker.BROKER + path_, {
      ...opts,
      credentials: 'include',
      headers: { 'content-type': 'application/json', accept: 'application/json', ...opts.headers },
    });
    return { status: res.status, data: await res.json().catch(() => ({})) };
  }
  const res = await fetch(broker.BROKER + path_, {
    ...opts,
    headers: {
      'content-type': 'application/json', accept: 'application/json', 'user-agent': broker.UA,
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
// Step 1: which email? A small native window, before any auth anywhere.
function askEmail() {
  const { BrowserWindow, ipcMain } = require('electron');
  return new Promise((resolve) => {
    const win = new BrowserWindow({
      width: 420, height: 300, title: 'Set up BrowserID Wallet', resizable: false,
      webPreferences: {
        preload: path.join(__dirname, 'bootstrap-preload.js'),
        nodeIntegration: false, contextIsolation: true,
      },
    });
    let settled = false;
    const finish = (v) => {
      if (settled) return;
      settled = true;
      ipcMain.removeHandler('wallet:bootstrap-email');
      resolve(v);
      if (!win.isDestroyed()) win.close();
    };
    ipcMain.handle('wallet:bootstrap-email', (_e, email) => finish((email || '').trim().toLowerCase() || null));
    win.on('closed', () => finish(null));
    win.loadFile(path.join(__dirname, 'bootstrap.html'));
  });
}

// ---------------------------------------------------------------------------
// Primary lane: the IdP's device-authorize page (fragment carries the
// pubkeys, per the dialog's contract), consumed over the `return_url`
// delivery lane — the page navigates to return_url#device_cert=…, which we
// intercept before it loads. The user authenticates first-party at their
// IdP if that session is cold. No holder is passed: cold bootstrap has no
// broker session to fetch a prefix from, so the IdP self-assigns one and
// the broker's join-side adoption/move machinery (rrve/i8a2) heals it into
// the account's `browsers` namespace.
function primaryHop({ deviceAuthUrl, email, devicePub, configPub }) {
  const { BrowserWindow } = require('electron');
  const RETURN_URL = `${broker.BROKER}/wallet-idp-return`; // never actually loaded
  return new Promise((resolve, reject) => {
    const win = new BrowserWindow({
      width: 480, height: 640, title: `Sign in to ${new URL(deviceAuthUrl).host}`,
      webPreferences: { partition: 'persist:browserid', nodeIntegration: false, contextIsolation: true },
    });
    const url = deviceAuthUrl +
      '#email=' + encodeURIComponent(email) +
      '&device_pubkey=' + encodeURIComponent(devicePub) +
      '&config_pubkey=' + encodeURIComponent(configPub) +
      // return_origin is a page precondition (postMessage lane target); the
      // return_url delivery lane is what we actually consume.
      '&return_origin=' + encodeURIComponent(broker.ORIGIN) +
      '&return_url=' + encodeURIComponent(RETURN_URL);

    const timeout = setTimeout(() => { win.close(); reject(new Error('IdP authorization timed out')); }, 3 * 60 * 1000);
    let settled = false;
    const finish = (fn, arg) => {
      if (!settled) { settled = true; clearTimeout(timeout); fn(arg); setImmediate(() => win.close()); }
    };
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

async function persist({ email, issuer, mintUrl, device, config, certs }) {
  const assignedHolder = decodeJws(certs.device_cert).holder;
  await store.set({
    identity: email,
    domain: issuer,   // access-request `domain` claim = the issuer
    mintUrl,
    holder: assignedHolder,
    holderPrefix: assignedHolder.split('.')[0],
    deviceKey: device.privJwk,
    deviceCert: certs.device_cert,
    configKey: config.privJwk,
    configCert: certs.config_cert,
    warrants: {},
    warrantRefs: {},
    bootstrappedAt: nowS(),
  });
}

// The silent broker-registry join (primary lane): a full presentation for
// the broker's OWN audience — strictly stronger than the password lane it
// replaces — links the identity into an account, records this device's
// config cert (labeled from our UA), and schedules holder healing.
// Best-effort: the wallet works without it; the account page just won't
// list this device until a later join succeeds.
async function joinBroker() {
  try {
    const presentation = await require('./login').buildBrokerPresentation();
    const r = await broker.bare('/wsapi/auth_with_presentation', {
      method: 'POST',
      body: { presentation, ephemeral: true },
    });
    if (r.status !== 200) {
      console.warn(`[wallet] broker join failed (non-fatal): ${r.status} ${JSON.stringify(r.data).slice(0, 150)}`);
    }
  } catch (e) {
    console.warn('[wallet] broker join failed (non-fatal):', e.message || e);
  }
}

async function bootstrapPrimary(email, info) {
  if (!info.device_auth || !info.access_mint) {
    throw new Error('this identity\'s IdP does not support device authorization');
  }
  const device = await generateKey();
  const config = await generateKey();
  const certs = await primaryHop({
    deviceAuthUrl: info.device_auth, email, devicePub: device.x, configPub: config.x,
  });
  await persist({ email, issuer: info.issuer, mintUrl: info.access_mint, device, config, certs });
  await joinBroker();
  return { email };
}

// Secondary lane: the broker is the issuer, so its /account login IS the
// single login. The account must hold the chosen email; /device/issue
// enforces it server-side and we fail early with a clear message.
async function bootstrapSecondary(email, { interactive }) {
  if (interactive) await interactiveIssuerLogin(email);
  const ctx = await csrf();
  if (!ctx.authenticated) throw new Error('issuer session not authenticated');
  const bh = await sessionFetch('/wsapi/browser_holder');
  if (bh.status !== 200 || !bh.data.prefix) throw new Error(`browser_holder failed: ${bh.status}`);
  const holder = `${bh.data.prefix}.${randHex(5)}`;
  const device = await generateKey();
  const config = await generateKey();
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
  await persist({
    email, issuer: ctx.domain, mintUrl: `${broker.BROKER}/access/mint`,
    device, config, certs: issue.data,
  });
  return { email };
}

function interactiveIssuerLogin(email) {
  const { BrowserWindow, session } = require('electron');
  const ses = session.fromPartition('persist:browserid');
  ses.setUserAgent(broker.UA);
  electronSession = ses;
  return new Promise((resolve, reject) => {
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
    win.loadURL(`${broker.BROKER}/account`);
    let settled = false;
    const finish = (fn, arg) => {
      if (settled) return;
      settled = true;
      clearInterval(poll);
      fn(arg);
      if (!win.isDestroyed()) win.close();
    };
    const poll = setInterval(async () => {
      try {
        const { data } = await sessionFetch('/wsapi/session_context');
        if (!data.authenticated) return;
        const emails = (await sessionFetch('/wsapi/list_emails')).data.emails || [];
        if (!emails.some((e) => String(e).toLowerCase() === email)) {
          return finish(reject, new Error(`the signed-in account does not hold ${email}`));
        }
        finish(resolve);
      } catch (err) {
        finish(reject, err);
      }
    }, 1500);
    win.on('closed', () => finish(reject, new Error('sign-in window closed')));
  });
}

// ---------------------------------------------------------------------------
// Entry points.
async function bootstrapForEmail(email, { interactive }) {
  const info = await broker.bare(`/wsapi/address_info?email=${encodeURIComponent(email)}`);
  if (info.status !== 200) throw new Error(`address_info failed: ${info.status}`);
  if (info.data.type === 'primary') {
    if (!interactive) throw new Error('primary identities need the interactive flow');
    return bootstrapPrimary(email, info.data);
  }
  return bootstrapSecondary(email, { interactive });
}

async function startBootstrap({ notify, updateTray }) {
  const email = await askEmail();
  if (!email) return;
  try {
    const r = await bootstrapForEmail(email, { interactive: true });
    notify('BrowserID Wallet', `Wallet ready as ${r.email}`);
    updateTray?.();
    require('./registry').startInboxWatch({ notify });
  } catch (err) {
    console.error('[wallet] bootstrap failed', err);
    notify('BrowserID Wallet', `Setup failed: ${err.message}`);
  }
}

// Test lane (WALLET_TEST=1): password auth against a local broker — the
// secondary path with a plain cookie jar, no windows.
async function bootstrapPassword({ email, pass }) {
  const auth = await sessionFetch('/wsapi/authenticate_user', {
    method: 'POST',
    body: JSON.stringify({ email, pass, ephemeral: false }),
  });
  if (auth.status !== 200) throw new Error(`authenticate_user failed: ${auth.status} ${JSON.stringify(auth.data)}`);
  return bootstrapForEmail(email.trim().toLowerCase(), { interactive: false });
}

module.exports = { startBootstrap, bootstrapPassword };
