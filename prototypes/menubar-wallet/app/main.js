// BrowserID menubar wallet — Electron main process.
// Tray app that holds the device key/certs and answers login requests
// routed from the browser extension via a localhost server.
const { app, Tray, Menu, Notification, nativeImage, dialog, shell } = require('electron');
const path = require('path');
const { startServer } = require('./server');
const store = require('./store');

let tray = null;

function trayIcon() {
  // 16x16 template image drawn as a simple "id" glyph placeholder.
  // Prototype: use an empty image + title text so we need no asset pipeline.
  return nativeImage.createEmpty();
}

function updateTray(state) {
  if (!tray) return;
  tray.setTitle(state.paired ? ' id✓' : ' id…');
  tray.setContextMenu(Menu.buildFromTemplate([
    { label: state.identity ? `Signed in: ${state.identity}` : 'Not bootstrapped', enabled: false },
    { type: 'separator' },
    {
      label: 'Bootstrap with browserid.me…',
      click: () => require('./ceremony').startBootstrap({ notify, updateTray: () => updateTray(store.state()) }),
    },
    { label: 'Copy extension pairing info', click: () => {} },
    { type: 'separator' },
    { label: 'Quit', click: () => app.quit() },
  ]));
}

function notify(title, body, onClick) {
  const n = new Notification({ title, body });
  if (onClick) n.on('click', onClick);
  n.show();
}

// Native approval prompt used for login requests coming from the extension.
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
  try { require('fs').appendFileSync('/tmp/wallet-app-trace.log', a.join(' ') + '\n'); } catch {}
};

process.on('uncaughtException', (e) => log('UNCAUGHT', e.stack || e));
process.on('unhandledRejection', (e) => log('UNHANDLED', (e && e.stack) || e));

log('main.js loaded, awaiting ready');
app.whenReady().then(async () => {
  log('ready');
  try {
    if (app.dock) app.dock.hide(); // menubar-only
    tray = new Tray(trayIcon());
    tray.setToolTip('BrowserID wallet');
    log('tray created');
    await store.init(app.getPath('userData'));
    updateTray(store.state());
    const port = await startServer({ approveLogin, notify, onStateChange: () => updateTray(store.state()) });
    log(`localhost server on 127.0.0.1:${port}`);
    require('./ceremony').resumeSession({ notify });
  } catch (err) {
    log('startup failed:', err.stack || err);
  }
});

app.on('window-all-closed', (e) => e.preventDefault?.());
