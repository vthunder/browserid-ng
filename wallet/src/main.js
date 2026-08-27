// BrowserID Wallet — Electron main process. Menubar app that holds the
// device keys (encrypted at rest under the OS keychain), runs the login
// ceremony for the browser extension, and watches the approvals inbox over
// the registry API.
//
// Packaged as a real .app with LSUIElement=1 (see package.json `build`), so
// LaunchServices grants the menubar slot — the macOS 26 invisible-tray trap
// only bites terminal-spawned processes (dev: `npm run tray`).
const { app, Tray, Menu, Notification, nativeImage, dialog } = require('electron');
const path = require('path');
const { startServer } = require('./server');
const store = require('./store');

let tray = null;

function trayIcon() {
  // Monochrome template PNG — an empty image collapses to a zero-width,
  // invisible tray item on current macOS.
  const img = nativeImage.createFromPath(path.join(__dirname, '..', 'assets', 'trayTemplate.png'));
  img.setTemplateImage(true);
  return img;
}

function updateTray(state) {
  if (!tray) return;
  tray.setTitle(state.identity ? '' : ' id…');
  tray.setContextMenu(Menu.buildFromTemplate([
    { label: state.identity ? `Signed in: ${state.identity}` : 'Not set up', enabled: false },
    {
      label: store.encryptedAtRest() ? 'Keys encrypted at rest (keychain)' : '⚠ Keys NOT encrypted at rest',
      enabled: false,
    },
    { type: 'separator' },
    {
      label: state.identity ? 'Set up a different identity…' : 'Set up wallet…',
      click: () => require('./bootstrap').startBootstrap({ notify, updateTray: () => updateTray(store.state()) }),
    },
    { type: 'separator' },
    { label: 'Quit', click: () => app.quit() },
  ]));
}

function notify(title, body, onClick) {
  const n = new Notification({ title, body });
  if (onClick) n.on('click', onClick);
  n.show();
}

// Native approval prompt for login requests coming from the extension.
async function approveLogin({ origin, email }) {
  const { response } = await dialog.showMessageBox({
    type: 'question',
    buttons: ['Sign in', 'Cancel'],
    defaultId: 0,
    cancelId: 1,
    message: `Sign in to ${origin}?`,
    detail: `The site at ${origin} is requesting a BrowserID login${email ? ` as ${email}` : ''}.`,
  });
  return response === 0;
}

if (process.env.ELECTRON_USER_DATA) app.setPath('userData', process.env.ELECTRON_USER_DATA);

const log = (...a) => {
  console.log('[wallet]', ...a);
  try { require('fs').appendFileSync('/tmp/browserid-wallet.log', a.join(' ') + '\n'); } catch {}
};
process.on('uncaughtException', (e) => log('UNCAUGHT', e.stack || e));
process.on('unhandledRejection', (e) => log('UNHANDLED', (e && e.stack) || e));

app.whenReady().then(async () => {
  try {
    if (app.dock) app.dock.hide(); // menubar-only
    // Without an application menu there are no Edit roles, so Cmd+V/C/X are
    // dead in every window (e.g. pasting a password in the sign-in window).
    Menu.setApplicationMenu(Menu.buildFromTemplate([
      { role: 'appMenu' }, { role: 'editMenu' }, { role: 'windowMenu' },
    ]));
    const icon = trayIcon();
    tray = new Tray(icon);
    tray.setToolTip('BrowserID Wallet');
    log(`tray created (icon ${icon.isEmpty() ? 'EMPTY' : icon.getSize().width + 'px'})`);
    await store.init(app.getPath('userData'));
    updateTray(store.state());
    const port = await startServer({ approveLogin, notify, onStateChange: () => updateTray(store.state()) });
    log(`localhost server on 127.0.0.1:${port}`);

    if (store.state().deviceCert) {
      // Approvals ride the registry API (token + proof) — no borrowed
      // session, so this works across restarts for every identity type.
      require('./registry').startInboxWatch({ notify });
    } else if (process.env.WALLET_TEST !== '1') {
      // The tray can be suppressed (menu-bar managers), so don't depend on
      // it: open setup when the wallet has no identity yet.
      log('not set up — opening bootstrap window');
      require('./bootstrap').startBootstrap({ notify, updateTray: () => updateTray(store.state()) });
    }
  } catch (err) {
    log('startup failed:', err.stack || err);
  }
});

app.on('window-all-closed', (e) => e.preventDefault?.());
