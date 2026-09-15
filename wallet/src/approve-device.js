// Approve a new device from this one (registry-api-v1 §5.2.8, bean puo8):
// the inbox watch notices an open approval on the account and opens a
// small native window asking for the code the new device shows; the code
// goes back over this wallet's registry session. Deny is one click.
const path = require('path');
const registry = require('./registry');

const live = new Map(); // webContents id → { approval, finish }
let handlersInstalled = false;

function installHandlers() {
  if (handlersInstalled) return;
  handlersInstalled = true;
  const { ipcMain } = require('electron');
  const entry = (event) => {
    const e = live.get(event.sender.id);
    if (!e) throw new Error('not an approve-device window');
    return e;
  };
  ipcMain.handle('wallet:approve-device-info', (event) => {
    const { approval } = entry(event);
    return { label: approval.label || null, expires_at: approval.expires_at };
  });
  ipcMain.handle('wallet:approve-device', async (event, code) => {
    const e = entry(event);
    try {
      await approveDevice(e.approval.id, String(code || ''));
      e.finish('approved');
      return { ok: true };
    } catch (err) {
      const reason = err.reason || '';
      const message = reason === 'code_mismatch' ? 'That is not the code the new device shows.'
        : reason === 'approver_unproven' ? 'This wallet must sign in to an identity before it can approve other devices.'
        : reason === 'approval_disabled' ? 'Your account settings do not allow adding devices by approval.'
        : err.status === 404 ? 'That request is no longer open.'
        : (err.message || 'That did not work.');
      return { ok: false, message };
    }
  });
  ipcMain.handle('wallet:approve-device-deny', async (event) => {
    const e = entry(event);
    try { await denyDevice(e.approval.id); } catch (err) { console.warn('[wallet] deny failed:', err.message || err); }
    e.finish('denied');
    return { ok: true };
  });
}

async function listApprovals() {
  const data = await registry.apiCall('GET', '/api/v1/approvals');
  return data.approvals || [];
}
async function approveDevice(id, code) {
  return registry.apiCall('POST', '/api/v1/approvals/approve', { id, code });
}
async function denyDevice(id) {
  return registry.apiCall('POST', '/api/v1/approvals/deny', { id });
}

/// Show the window for one open approval; resolves 'approved' | 'denied' | 'closed'.
function askApproval(approval, { testCode } = {}) {
  const { BrowserWindow } = require('electron');
  installHandlers();
  return new Promise((resolve) => {
    const win = new BrowserWindow({
      width: 420, height: 320, title: 'Approve a new device', resizable: false,
      show: !testCode,
      webPreferences: {
        preload: path.join(__dirname, 'approve-device-preload.js'),
        nodeIntegration: false, contextIsolation: true, sandbox: true,
      },
    });
    let settled = false;
    const finish = (outcome) => {
      if (settled) return;
      settled = true;
      live.delete(win.webContents.id);
      resolve(outcome);
      setTimeout(() => { if (!win.isDestroyed()) win.close(); }, testCode ? 0 : 1200);
    };
    live.set(win.webContents.id, { approval, finish });
    win.on('closed', () => finish('closed'));
    if (testCode) {
      win.webContents.on('did-finish-load', () => {
        win.webContents.executeJavaScript(`(function () {
          document.getElementById('code').value = ${JSON.stringify(testCode)};
          document.getElementById('f').requestSubmit();
        })();`).catch(() => {});
      });
      setTimeout(() => finish('timeout'), 30_000);
    }
    win.loadFile(path.join(__dirname, 'approve-device.html'));
  });
}

module.exports = { listApprovals, approveDevice, denyDevice, askApproval };
