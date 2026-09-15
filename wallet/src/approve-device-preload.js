// Bridge for the local approve-device window only (bean puo8): the code the
// person typed goes to the main process, which answers the approval over
// the wallet's registry session.
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('walletBridge', {
  info: () => ipcRenderer.invoke('wallet:approve-device-info'),
  approve: (code) => ipcRenderer.invoke('wallet:approve-device', code),
  deny: () => ipcRenderer.invoke('wallet:approve-device-deny'),
});
