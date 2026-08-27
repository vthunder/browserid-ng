// Bridge for the local bootstrap page only: exposes exactly one call.
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('walletBridge', {
  submitEmail: (email) => ipcRenderer.invoke('wallet:bootstrap-email', email),
});
