// The wallet HOSTS the broker's consent page (bean jo0m): one UI for every
// request shape, the wallet supplying what the page's keystore and cookie
// session would — signing by the config key, registry calls under the
// wallet's session — through consent-preload.js. Nothing native is
// rebuilt; the page detects the bridge and uses it at its three seams.
const path = require('path');
const broker = require('./broker');
const store = require('./store');
const registry = require('./registry');
const { signJws } = require('./crypto');

// Live consent windows by webContents id; IPC from anything else is refused.
const live = new Map();
let handlersInstalled = false;

function senderWindow(event) {
  const entry = live.get(event.sender.id);
  if (!entry) throw new Error('not a consent window');
  // The page must still be the broker's consent page (no navigation away).
  const url = event.senderFrame?.url || event.sender.getURL();
  if (!url.startsWith(`${broker.ORIGIN}/consent`)) throw new Error('consent bridge: wrong page');
  return entry;
}

function installHandlers() {
  if (handlersInstalled) return;
  handlersInstalled = true;
  const { ipcMain } = require('electron');
  ipcMain.handle('wallet:consent-info', (event) => {
    senderWindow(event);
    const s = store.state();
    return { identity: s.identity, configCert: s.configCert };
  });
  ipcMain.handle('wallet:consent-sign', async (event, header, claims) => {
    senderWindow(event);
    if (typeof header !== 'string' || !claims || typeof claims !== 'object') throw new Error('bad sign request');
    // Only warrants / admission records: never a general-purpose signer.
    if (!/^browserid-warrant-v[12]$/.test(claims.typ || '')) throw new Error('consent bridge signs warrants only');
    return signJws(store.state().configKey, header, claims);
  });
  ipcMain.handle('wallet:consent-registry', async (event, method, p, body) => {
    senderWindow(event);
    if (typeof p !== 'string' || !p.startsWith('/api/v1/')) throw new Error('consent bridge: registry paths only');
    try {
      return await registry.apiCall(method, p, body);
    } catch (e) {
      // Surface the API's error shape so the page's handling stays the same.
      const err = new Error(e.message || String(e));
      throw Object.assign(err, { status: e.status, reason: e.reason });
    }
  });
  ipcMain.handle('wallet:consent-done', (event, outcome) => {
    const entry = senderWindow(event);
    entry.finish(outcome || 'closed');
  });
}

/// Open `/consent/<code>` (or the inbox when no code) in a wallet window.
/// Resolves with the page's outcome ('approved' | 'denied' | 'closed').
/// `testAction` (WALLET_TEST only) drives the page: click approve or deny
/// on the deep-linked card as soon as its button arms.
function hostConsent({ code, testAction } = {}) {
  const { BrowserWindow } = require('electron');
  installHandlers();
  return new Promise((resolve) => {
    const win = new BrowserWindow({
      width: 520, height: 720, title: 'Approve a request',
      show: !testAction,
      webPreferences: {
        partition: 'persist:browserid',
        preload: path.join(__dirname, 'consent-preload.js'),
        nodeIntegration: false, contextIsolation: true, sandbox: true,
      },
    });
    let settled = false;
    const finish = (outcome) => {
      if (settled) return;
      settled = true;
      live.delete(win.webContents.id);
      resolve(outcome);
      // Let the page show its final status for a moment when a human is watching.
      setTimeout(() => { if (!win.isDestroyed()) win.close(); }, testAction ? 0 : 1500);
    };
    live.set(win.webContents.id, { finish });
    win.on('closed', () => finish('closed'));
    if (testAction) {
      win.webContents.on('did-finish-load', () => {
        win.webContents.executeJavaScript(`(function retry(n) {
          var sel = ${JSON.stringify(testAction === 'deny' ? 'button.deny' : 'button.approve')};
          var card = document.getElementById(${JSON.stringify('req-' + (code || ''))}) || document;
          var b = card.querySelector(sel + ':not([disabled])');
          if (b) { b.click(); return; }
          if (n > 0) setTimeout(function () { retry(n - 1); }, 200);
        })(100);`).catch(() => {});
      });
      // A test run must not hang on a page that never finishes.
      setTimeout(() => finish('timeout'), 30_000);
    }
    win.loadURL(`${broker.BROKER}/consent${code ? '/' + encodeURIComponent(code) : ''}`);
  });
}

module.exports = { hostConsent };
