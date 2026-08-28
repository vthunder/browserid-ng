// Localhost bridge the browser extension talks to.
// Trust model: 127.0.0.1 bind + first-connect pairing approved natively in
// the app; subsequent requests must carry the issued token, from the same
// browser origin that paired. Browser callers are restricted to an origin
// allowlist (below); native local processes send no Origin and are gated by
// the native pairing/login dialogs, which name them as unidentified.
const http = require('http');
const crypto = require('crypto');
const store = require('./store');

const PORT = 8873; // fixed so the extension needs no discovery

// Browser origins allowed to talk to the bridge: the MV3 extension's service
// worker, plus loopback pages for the e2e harness. Everything else — i.e.
// any web page the user happens to visit — is refused outright, before the
// pairing dialog can fire. CORS headers reflect the specific caller, never *.
const ALLOWED_ORIGIN = /^(chrome-extension:\/\/[a-p]{32}|https?:\/\/(127\.0\.0\.1|localhost)(:\d+)?)$/;

function json(req, res, code, body) {
  const headers = { 'content-type': 'application/json', vary: 'origin' };
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGIN.test(origin)) {
    headers['access-control-allow-origin'] = origin;
    headers['access-control-allow-headers'] = 'content-type, x-wallet-token';
  }
  res.writeHead(code, headers);
  res.end(JSON.stringify(body));
}

// Human-readable caller line for the native dialogs. A browser attaches the
// Origin header itself (a page can't forge it); a native process sends none.
function describeCaller(origin) {
  if (!origin) return 'a local process on this machine (no browser origin)';
  if (origin.startsWith('chrome-extension://')) return `a browser extension (${origin})`;
  return `a page at ${origin}`;
}

async function readBody(req) {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  return chunks.length ? JSON.parse(Buffer.concat(chunks).toString()) : {};
}

function startServer({ approveLogin, approvePair, notify, onStateChange }) {
  return new Promise((resolve) => {
    const server = http.createServer(async (req, res) => {
      const origin = req.headers.origin || null;
      // A browser caller outside the allowlist is refused before anything
      // else — no pairing dialog, no CORS headers to read the answer with.
      if (origin && !ALLOWED_ORIGIN.test(origin)) {
        return json(req, res, 403, { error: 'origin not allowed' });
      }
      if (req.method === 'OPTIONS') return json(req, res, 204, {});
      const url = new URL(req.url, 'http://127.0.0.1');
      try {
        if (url.pathname === '/pair' && req.method === 'POST') {
          // First contact: ask the human natively, naming the caller.
          const ok = process.env.WALLET_AUTO_APPROVE === '1'
            || (await approvePair({ caller: describeCaller(origin) }));
          if (!ok) return json(req, res, 403, { error: 'pairing rejected' });
          const token = crypto.randomBytes(24).toString('base64url');
          // Bind the token to the origin it was issued to, so a token minted
          // for one browser caller is useless from another.
          await store.set({ pairToken: token, pairOrigin: origin });
          onStateChange?.();
          return json(req, res, 200, { token });
        }

        // Everything below requires the pairing token, presented from the
        // same origin it was paired under.
        const token = req.headers['x-wallet-token'];
        if (!token || token !== store.state().pairToken
          || origin !== (store.state().pairOrigin || null)) {
          return json(req, res, 401, { error: 'not paired' });
        }

        if (url.pathname === '/status' && req.method === 'GET') {
          const s = store.state();
          return json(req, res, 200, {
            paired: true,
            identity: s.identity || null,
            bootstrapped: !!s.deviceCert,
            encrypted_at_rest: store.encryptedAtRest(),
          });
        }

        if (url.pathname === '/login' && req.method === 'POST') {
          // { origin } -> presentation for that RP origin, after native
          // approval. The RP origin in the body is caller-claimed; the
          // caller line shown to the human comes from the Origin header.
          const { origin: rpOrigin, acceptedFallbacks } = await readBody(req);
          if (!rpOrigin) return json(req, res, 400, { error: 'origin required' });
          const result = await require('./login').login({
            origin: rpOrigin, caller: describeCaller(origin), approveLogin, notify,
            acceptedFallbacks,
          });
          return json(req, res, result.error ? 400 : 200, result);
        }

        // --- Test-only lanes (WALLET_TEST=1, e2e against a local broker) ---
        if (process.env.WALLET_TEST === '1' && req.method === 'POST') {
          if (url.pathname === '/test/bootstrap') {
            const { email, pass } = await readBody(req);
            const r = await require('./bootstrap').bootstrapPassword({ email, pass });
            onStateChange?.();
            return json(req, res, 200, r);
          }
          if (url.pathname === '/test/inbox') {
            // Drives the registry-API token lane end to end.
            return json(req, res, 200, await require('./registry').listRequests());
          }
          if (url.pathname === '/test/label') {
            // Drives the §5.4 friendly-label heal, returns the resulting view.
            const registry = require('./registry');
            await registry.ensureDeviceLabel();
            const view = await registry.apiCall('GET', '/api/v1/holders');
            const holder = store.state().holder;
            const mine = [
              ...(view.namespaces || []).flatMap((n) => n.holders || []),
              ...(view.holders_without_namespace || []),
            ].find((h) => h.holder_id === holder);
            return json(req, res, 200, { holder, label: mine?.label ?? null });
          }
          if (url.pathname === '/test/state') {
            const { pairToken: _p, deviceKey: _d, configKey: _c, ...rest } = store.state();
            return json(req, res, 200, rest); // never the keys, even in tests
          }
        }

        return json(req, res, 404, { error: 'unknown endpoint' });
      } catch (err) {
        console.error('[wallet] request failed', err);
        return json(req, res, 500, { error: String(err.message || err) });
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
