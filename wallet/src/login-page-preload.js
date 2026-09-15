// The mediator inside the wallet's own windows (bean e98a / d26p): pages
// the wallet opens — the registry login page first — get a `navigator.id`
// answered by this wallet, so "prove your identities" works with no
// browser extension in the loop. The isolated preload exposes one bridge;
// a main-world shim installed at document start puts it under
// navigator.id with the include.js contract (request(kind, args) → a
// promise of the kind's artefact), as an accessor so the page's own
// include.js cannot displace it.
const { contextBridge, ipcRenderer, webFrame } = require('electron');

contextBridge.exposeInMainWorld('__browseridWalletMediator', {
  request: (kind, args) => ipcRenderer.invoke('wallet:mediator-request', kind, args),
});

const SHIM = `(() => {
  if (navigator.id && navigator.id.__menubarWallet) return;
  let observers = { login: null, logout: null, ready: null };
  const api = {
    __menubarWallet: true, _shimmed: true, version: 'wallet-window',
    watch(opts) {
      opts = opts || {};
      observers = { login: opts.onlogin || null, logout: opts.onlogout || null, ready: opts.onready || null };
      if (observers.ready) setTimeout(() => observers.ready(), 0);
    },
    request(kindOrOpts, args) {
      const kind = typeof kindOrOpts === 'string' ? kindOrOpts : 'login';
      const a = (typeof kindOrOpts === 'string' ? args : kindOrOpts) || {};
      return window.__browseridWalletMediator.request(kind, a).then((result) => {
        if (result && result.error) throw result;
        if (kind === 'login' && result && result.presentation && observers.login) {
          try { observers.login(result.presentation, result); } catch (e) {}
        }
        return result;
      });
    },
    logout() { if (observers.logout) observers.logout(); },
    get(callback, opts) { api.watch({ onlogin: (p) => callback(p), onlogout: () => {} }); api.request(opts || {}); },
  };
  const target = Navigator.prototype.hasOwnProperty('id') ? Navigator.prototype : navigator;
  Object.defineProperty(target, 'id', { configurable: false, enumerable: true, get: () => api, set: () => {} });
})();`;

try { webFrame.executeJavaScript(SHIM); } catch (e) { /* a page without a main world */ }
