#!/bin/sh
# Dev launcher that still gets a visible tray on macOS 26: LaunchServices
# (`open`) grants menubar slots; terminal-spawned Electron gets an invisible
# zero-height status item. Packaged builds (`npm run pack`) don't need this —
# the .app is LSUIElement and launches normally.
#
# `open` detaches stdio, so console output lands in /tmp/browserid-wallet.log.
# For dev-with-console (no tray), `npm start` still works.
cd "$(dirname "$0")/.." || exit 1
exec open -n ./node_modules/electron/dist/Electron.app --args "$(pwd)"
