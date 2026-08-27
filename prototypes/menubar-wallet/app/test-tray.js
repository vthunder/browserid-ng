// Tray placement experiment: try several configurations, sample bounds over
// time. A real menubar slot has height ~24; height 0 means no slot.
const { app, Tray, BrowserWindow, nativeImage } = require('electron');
const path = require('path');
const fs = require('fs');
const MODE = process.env.TRAY_MODE || 'plain';
const out = (s) => { fs.appendFileSync('/tmp/tray-test.log', `[${MODE}] ${s}\n`); };

function makeTray() {
  const img = nativeImage.createFromPath(path.join(__dirname, 'trayTemplate.png'));
  img.setTemplateImage(true);
  const tray = new Tray(img);
  tray.setTitle(' id');
  return tray;
}

let tray;
app.whenReady().then(async () => {
  const wait = (ms) => new Promise((r) => setTimeout(r, ms));

  if (MODE === 'plain') {
    tray = makeTray();
  } else if (MODE === 'delayed') {
    await wait(3000);
    tray = makeTray();
  } else if (MODE === 'accessory-explicit') {
    app.setActivationPolicy('accessory');
    await wait(500);
    tray = makeTray();
  } else if (MODE === 'regular-policy') {
    app.setActivationPolicy('regular');
    await wait(500);
    tray = makeTray();
  } else if (MODE === 'window-first') {
    const w = new BrowserWindow({ width: 200, height: 200, show: true });
    w.loadURL('about:blank');
    await wait(1500);
    tray = makeTray();
  } else if (MODE === 'recreate') {
    tray = makeTray();
    await wait(1000);
    tray.destroy();
    tray = makeTray();
  }

  // Sample bounds for up to 8s — placement might be async.
  for (let i = 0; i < 8; i++) {
    await wait(1000);
    const b = tray.getBounds();
    out(`t+${i + 1}s bounds ${JSON.stringify(b)}`);
    if (b.height > 0) break;
  }
  app.quit();
});
