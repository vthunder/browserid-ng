// Localhost bridge the browser extension talks to.
// Trust model (carried from the prototype, hardening tracked on the bean):
// 127.0.0.1 bind + first-connect pairing approved natively in the app;
// subsequent requests must carry the issued token.
const http = require('http');
const crypto = require('crypto');
const store = require('./store');

const PORT = 8873; // fixed so the extension needs no discovery

function json(res, code, body) {
  res.writeHead(code, {
    'content-type': 'application/json',
    // The extension's service worker fetches from its own origin; allow it.
    'access-control-allow-origin': '*',
    'access-control-allow-headers': 'content-type, x-wallet-token',
  });
  res.end(JSON.stringify(body));
}

async function readBody(req) {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  return chunks.length ? JSON.parse(Buffer.concat(chunks).toString()) : {};
}

function startServer({ approveLogin, notify, onStateChange }) {
  return new Promise((resolve) => {
    const server = http.createServer(async (req, res) => {
      if (req.method === 'OPTIONS') return json(res, 204, {});
      const url = new URL(req.url, 'http://127.0.0.1');
      try {
        if (url.pathname === '/pair' && req.method === 'POST') {
          // First contact from the extension: ask the human natively.
          const ok = process.env.WALLET_AUTO_APPROVE === '1'
            || (await approveLogin({ origin: 'a browser extension (pairing request)', email: null }));
          if (!ok) return json(res, 403, { error: 'pairing rejected' });
          const token = crypto.randomBytes(24).toString('base64url');
          await store.setPairToken(token);
          onStateChange?.();
          return json(res, 200, { token });
        }

        // Everything below requires the pairing token.
        const token = req.headers['x-wallet-token'];
        if (!token || token !== store.state().pairToken) {
          return json(res, 401, { error: 'not paired' });
        }

        if (url.pathname === '/status' && req.method === 'GET') {
          const s = store.state();
          return json(res, 200, {
            paired: true,
            identity: s.identity || null,
            bootstrapped: !!s.deviceCert,
            encrypted_at_rest: store.encryptedAtRest(),
          });
        }

        if (url.pathname === '/login' && req.method === 'POST') {
          // { origin } -> presentation for that RP origin, after native approval.
          const { origin } = await readBody(req);
          if (!origin) return json(res, 400, { error: 'origin required' });
          const result = await require('./login').login({ origin, approveLogin, notify });
          return json(res, result.error ? 400 : 200, result);
        }

        // --- Test-only lanes (WALLET_TEST=1, e2e against a local broker) ---
        if (process.env.WALLET_TEST === '1' && req.method === 'POST') {
          if (url.pathname === '/test/bootstrap') {
            const { email, pass } = await readBody(req);
            const r = await require('./bootstrap').bootstrapPassword({ email, pass });
            onStateChange?.();
            return json(res, 200, r);
          }
          if (url.pathname === '/test/inbox') {
            // Drives the registry-API token lane end to end.
            return json(res, 200, await require('./registry').listRequests());
          }
          if (url.pathname === '/test/state') {
            const { pairToken: _p, deviceKey: _d, configKey: _c, ...rest } = store.state();
            return json(res, 200, rest); // never the keys, even in tests
          }
        }

        return json(res, 404, { error: 'unknown endpoint' });
      } catch (err) {
        console.error('[wallet] request failed', err);
        return json(res, 500, { error: String(err.message || err) });
      }
    });
    // Fail LOUDLY if another wallet instance holds the port — silently
    // deferring to a stale process is how test runs end up talking to the
    // wrong app.
    server.on('error', (err) => {
      console.error(`[wallet] localhost bridge failed to bind :${PORT}:`, err.message);
      process.exit(1);
    });
    server.listen(PORT, '127.0.0.1', () => resolve(PORT));
  });
}

module.exports = { startServer, PORT };
