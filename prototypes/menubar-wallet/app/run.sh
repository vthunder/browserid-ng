#!/bin/sh
# Launch the wallet via LaunchServices (`open`), NOT directly from a shell:
# on macOS 26 the status bar only grants menubar slots to LaunchServices-
# launched processes — terminal-spawned Electron gets an invisible tray
# (zero-height status-item window; verified with a native AppKit probe too).
#
# `open` detaches stdio, so console output lands in /tmp/wallet-app-trace.log.
# For dev-with-console (no tray), `npx electron .` still works.
cd "$(dirname "$0")" || exit 1
exec open -n ./node_modules/electron/dist/Electron.app --args "$(pwd)"
