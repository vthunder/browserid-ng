// Single-login bootstrap (bean gxi9, converged per d0xb). Email-FIRST,
// issuer-first — and ONE flow (fallback-idp-api-v1 §1):
//
//   1. ask WHICH email (native window, before any network auth)
//   2. resolve the ISSUER: the identity domain's own IdP if it runs one,
//      otherwise the wallet's configured fallback IdP — which presents
//      exactly as a primary (same discovery keys, same ceremony page)
//   3. run the issuer's device-authorization ceremony (fragment carries the
//      pubkeys; the user authenticates FIRST-PARTY on the issuer's page)
//   4. persist keys+certs (encrypted at rest), then REGISTER the pair at
//      the wallet's registry over the token lane (§4: /api/v1/token +
//      /api/v1/devices/register) and start the registry-API inbox watch.
//
// No credential ever crosses a native API and no cookie ever reaches this
// app — the ceremony page owns human auth (this deleted the prototype's
// only cookie-carrying code). The wallet never assumes the issuer and the
// registry talk to each other, even when they are the same host.
const path = require('path');
const store = require('./store');
const broker = require('./broker');
const { generateKey, decodeJws, nowS } = require('./crypto');

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
// Step 2: issuer resolution. The primary branch still leans on the broker's
// /wsapi/address_info as its discovery convenience (client-side core §3
// DNSSEC discovery is future work); the fallback branch reads the configured
// fallback's OWN support document — the same two keys any primary advertises
// (fallback-idp-api-v1 §2), so step 3 is one code path.
async function resolveIssuer(email) {
  const info = await broker.bare(`/wsapi/address_info?email=${encodeURIComponent(email)}`);
  if (info.status !== 200) throw new Error(`address_info failed: ${info.status}`);
  if (info.data.type === 'primary') {
    if (!info.data.device_auth || !info.data.access_mint) {
      throw new Error('this identity\'s IdP does not support device authorization');
    }
    return {
      issuer: info.data.issuer,
      deviceAuthUrl: info.data.device_auth,
      mintUrl: info.data.access_mint,
    };
  }
  const doc = await broker.bare('/.well-known/browserid');
  if (doc.status !== 200) throw new Error(`fallback discovery failed: ${doc.status}`);
  const deviceAuth = doc.data['device-authorization'];
  const accessCert = doc.data['access-cert'];
  if (!deviceAuth || !accessCert) {
    throw new Error('the configured fallback IdP does not advertise device authorization');
  }
  return {
    issuer: new URL(broker.BROKER).host,
    deviceAuthUrl: new URL(deviceAuth, broker.BROKER).toString(),
    mintUrl: new URL(accessCert, broker.BROKER).toString(),
  };
}

// ---------------------------------------------------------------------------
// Step 3: the issuer's device-authorize page (fragment carries the pubkeys,
// per the ceremony contract), consumed over the `return_url` delivery lane —
// the page navigates to return_url#device_cert=…, which we intercept before
// it loads. The user authenticates first-party at their issuer if that
// session is cold. No holder is passed: the issuer self-assigns a fresh one
// (fallback-idp-api-v1 §3.2) and the registry's adoption/move machinery
// heals it into the account's `browsers` namespace at registration.
//
// `testPassword` (WALLET_TEST lane): the REAL page in a hidden window, with
// the password typed by injection — the test stands in for the human, never
// for the flow.
function primaryHop({ deviceAuthUrl, email, devicePub, configPub, testPassword }) {
  const { BrowserWindow, session } = require('electron');
  // The ceremony partition is the WALLET's surface: its product-token UA is
  // what the issuer's UA-label hook sees, so the resulting device row reads
  // "BrowserID-Wallet", not "Chrome on macOS".
  session.fromPartition('persist:browserid').setUserAgent(broker.UA);
  const RETURN_URL = `${broker.BROKER}/wallet-idp-return`; // never actually loaded
  return new Promise((resolve, reject) => {
    const win = new BrowserWindow({
      width: 480, height: 640, title: `Sign in to ${new URL(deviceAuthUrl).host}`,
      show: !testPassword,
      webPreferences: { partition: 'persist:browserid', nodeIntegration: false, contextIsolation: true },
    });
    const url = deviceAuthUrl +
      '#email=' + encodeURIComponent(email) +
      '&device_pubkey=' + encodeURIComponent(devicePub) +
      '&config_pubkey=' + encodeURIComponent(configPub) +
      // return_origin is the page's postMessage target precondition and the
      // origin its return_url must match (9it0); the return_url delivery
      // lane is what we actually consume.
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
    if (testPassword) {
      win.webContents.on('did-finish-load', () => {
        win.webContents.executeJavaScript(`(function retry(n) {
          var c = document.getElementById('confirm-form');
          if (c && !c.classList.contains('hidden')) { c.requestSubmit(); return; }
          var f = document.getElementById('login-form');
          if (f && !f.classList.contains('hidden')) {
            document.getElementById('password').value = ${JSON.stringify(testPassword)};
            f.requestSubmit();
            return;
          }
          if (n > 0) setTimeout(function () { retry(n - 1); }, 200);
        })(50);`).catch(() => {});
      });
    }
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

// Step 4: registration is the WALLET's act (fallback-idp-api-v1 §4): a token
// exchange with the new certs, then devices/register records the verified
// pair — the token lane replaces the prototype's cookie session join.
// Best-effort: the wallet works unregistered; the account page just won't
// list this device until a later call succeeds (the token machinery runs
// again on the inbox watch anyway).
async function registerAtRegistry() {
  try {
    const s = store.state();
    await require('./registry').apiCall('POST', '/api/v1/devices/register', {
      device_cert: s.deviceCert,
      config_cert: s.configCert,
    });
  } catch (e) {
    console.warn('[wallet] device registration failed (non-fatal):', e.message || e);
  }
}

// ---------------------------------------------------------------------------
// Entry points.
async function bootstrapForEmail(email, { testPassword } = {}) {
  const { issuer, deviceAuthUrl, mintUrl } = await resolveIssuer(email);
  const device = await generateKey();
  const config = await generateKey();
  const certs = await primaryHop({
    deviceAuthUrl, email, devicePub: device.x, configPub: config.x, testPassword,
  });
  await persist({ email, issuer, mintUrl, device, config, certs });
  await registerAtRegistry();
  return { email };
}

async function startBootstrap({ notify, updateTray }) {
  const email = await askEmail();
  if (!email) return;
  try {
    const r = await bootstrapForEmail(email);
    notify('BrowserID Wallet', `Wallet ready as ${r.email}`);
    updateTray?.();
    require('./registry').startInboxWatch({ notify });
  } catch (err) {
    console.error('[wallet] bootstrap failed', err);
    notify('BrowserID Wallet', `Setup failed: ${err.message}`);
  }
}

// Test lane (WALLET_TEST=1): same flow, hidden window, injected password.
async function bootstrapPassword({ email, pass }) {
  return bootstrapForEmail(email.trim().toLowerCase(), { testPassword: pass });
}

module.exports = { startBootstrap, bootstrapPassword };
