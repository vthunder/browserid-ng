// Broker HTTP lane with no cookies — the wallet's steady state never uses
// ambient auth: /access/mint is device-cert-authed, the registry API is
// token+proof-authed, and the one-time bootstrap session lives in
// bootstrap.js only.
const BROKER = (process.env.WALLET_BROKER || 'https://browserid.me').replace(/\/$/, '');
const ORIGIN = new URL(BROKER).origin;
const UA = 'BrowserID-Wallet/0.2';

async function bare(path, opts = {}) {
  const res = await fetch(BROKER + path, {
    ...opts,
    body: opts.body !== undefined && typeof opts.body !== 'string'
      ? JSON.stringify(opts.body) : opts.body,
    headers: {
      'content-type': 'application/json',
      accept: 'application/json',
      'user-agent': UA,
      ...opts.headers,
    },
  });
  return { status: res.status, data: await res.json().catch(() => ({})) };
}

module.exports = { BROKER, ORIGIN, UA, bare };
