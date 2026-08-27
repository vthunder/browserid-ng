// Page-world shim: provides navigator.id so RP pages route logins to the
// native menubar wallet instead of the browserid.me dialog popup.
//
// API contract matches include.js (the broker's shim): watch() registers
// {onlogin, onlogout, onready}; request() triggers a login; onlogin receives
// (presentationString, responseObject). Installed as an accessor with a
// swallowing setter so a later include.js `navigator.id = {...}` assignment
// can never displace it (safe in both sloppy and strict mode).
(() => {
  if (navigator.id && navigator.id.__menubarWallet) return;

  let observers = { login: null, logout: null, ready: null };
  const pending = new Map();
  let seq = 0;

  window.addEventListener('message', (ev) => {
    if (ev.source !== window || !ev.data || ev.data.__bidWallet !== 'response') return;
    const resolve = pending.get(ev.data.id);
    if (!resolve) return;
    pending.delete(ev.data.id);
    resolve(ev.data.result);
  });

  function callWallet(cmd, payload) {
    return new Promise((resolve) => {
      const id = ++seq;
      pending.set(id, resolve);
      window.postMessage({ __bidWallet: 'request', id, cmd, payload }, '*');
    });
  }

  const idApi = {
    __menubarWallet: true,
    _shimmed: true,
    watch(opts) {
      opts = opts || {};
      if (typeof opts.onlogin !== 'function') throw new Error('onlogin is required');
      observers = { login: opts.onlogin, logout: opts.onlogout || null, ready: opts.onready || null };
      if (observers.ready) setTimeout(() => observers.ready(), 0);
    },
    request() {
      if (!observers.login) throw new Error('navigator.id.watch must be called before navigator.id.request');
      callWallet('login', { origin: location.origin }).then((result) => {
        if (result && result.presentation) {
          observers.login(result.presentation, { presentation: result.presentation, email: result.email });
        } else if (result && result.error) {
          console.warn('[menubar-wallet] login failed:', result.error);
        }
      });
    },
    logout() { if (observers.logout) observers.logout(); },
    get(callback, opts) { // legacy stateless shim, minimal
      idApi.watch({ onlogin: (p) => callback(p), onlogout: () => {} });
      idApi.request(opts || {});
    },
  };

  Object.defineProperty(Navigator.prototype.hasOwnProperty('id') ? Navigator.prototype : navigator, 'id', {
    configurable: false,
    get: () => idApi,
    set: () => { /* swallow include.js's own shim install */ },
  });
})();
