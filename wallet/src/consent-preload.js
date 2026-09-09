// Bridge for the consent page when the WALLET hosts it (bean jo0m): the
// page signs with the wallet's config key and talks to the registry over
// the wallet's own session — keys never enter the page. Exposed only to
// windows consent.js opens; main-side handlers re-check the sender.
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('browseridWallet', {
  // { identity, configCert }
  info: () => ipcRenderer.invoke('wallet:consent-info'),
  // A JWS over (header b64url, claims) by the config key — the page hands
  // over exactly what it would have signed with a keystore key.
  signWarrant: (header, claims) => ipcRenderer.invoke('wallet:consent-sign', header, claims),
  // registry-api-v1 call under the wallet's session (method, path, body).
  registryCall: (method, path, body) => ipcRenderer.invoke('wallet:consent-registry', method, path, body),
  // The page is finished ('approved' | 'denied' | 'closed'): the wallet closes the window.
  done: (outcome) => ipcRenderer.invoke('wallet:consent-done', outcome),
});
