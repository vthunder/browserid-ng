// Tray placement experiment: try several configurations, report bounds for
// each. A real menubar slot has height ~24 and y at the top; height 0 means
// macOS gave the item no slot.
const { app, Tray, nativeImage } = require('electron');
const path = require('path');
const fs = require('fs');
const MODE = process.env.TRAY_MODE || 'dock-hidden-icon';
const out = (s) => fs.appendFileSync('/tmp/tray-test.log', `[${MODE}] ${s}\n`);

app.whenReady().then(() => {
  if (MODE.startsWith('dock-hidden') && app.dock) app.dock.hide();

  let tray;
  if (MODE.endsWith('title')) {
    tray = new Tray(nativeImage.createEmpty());
    tray.setTitle('WALLET');
  } else {
    const img = nativeImage.createFromPath(path.join(__dirname, 'trayTemplate.png'));
    img.setTemplateImage(true);
    tray = new Tray(img);
    tray.setTitle(' id');
  }
  setTimeout(() => {
    out(`bounds ${JSON.stringify(tray.getBounds())}`);
    app.quit();
  }, 1500);
});
