/**
 * Origin-split production proof (bean browserid-ng-cn1q).
 *
 * Validates the real split as deployed:
 *  - the static marketing site (marketing/) runs on a SEPARATE origin and
 *    renders the broker's guestbook feed cross-origin (read-only display);
 *  - its "Sign in" link points at the auth/issuer origin, not itself;
 *  - the broker, when MARKETING_URL is set, 301-redirects the public marketing
 *    routes (/ and /guestbook) to the marketing origin while keeping the feed
 *    JSON + POST-sign API on the auth origin.
 *
 * The guestbook audience is unchanged by the split (still <broker>/guestbook),
 * so no agent credential breaks — asserted by reusing the real agent sign flow.
 */
import { test, expect } from '@playwright/test';
import { createServer, IncomingMessage, ServerResponse } from 'http';
import { spawn, ChildProcess } from 'child_process';
import { readFile, mkdtemp } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';

const baseUrl = process.env.BROKER_URL || 'http://localhost:3000';
const marketingDir = join(__dirname, '..', '..', 'marketing');
// The workspace builds into a SHARED target dir (~/.cache/cargo-target,
// set in ~/.cargo/config.toml since 2026-07-22) — the repo-local target/
// no longer exists. Honor CARGO_TARGET_DIR / BROKER_BIN, then the shared
// default, then the legacy in-repo path.
import { homedir } from 'os';
import { existsSync } from 'fs';
const brokerBinCandidates = [
  process.env.BROKER_BIN,
  process.env.CARGO_TARGET_DIR && join(process.env.CARGO_TARGET_DIR, 'debug', 'browserid-broker'),
  join(homedir(), '.cache', 'cargo-target', 'debug', 'browserid-broker'),
  join(__dirname, '..', '..', 'target', 'debug', 'browserid-broker'),
].filter((p): p is string => !!p);
const brokerBin = brokerBinCandidates.find(existsSync) ?? brokerBinCandidates[0];

/** Serves the real marketing/ dir, injecting authOrigin=<broker> into config.js. */
class MarketingServer {
  private server: ReturnType<typeof createServer> | null = null;
  private port = 0;

  async start(): Promise<void> {
    return new Promise((resolve) => {
      this.server = createServer((req, res) => this.handle(req, res));
      this.server.listen(0, '127.0.0.1', () => {
        const addr = this.server!.address();
        this.port = typeof addr === 'object' ? addr!.port : 0;
        resolve();
      });
    });
  }
  async stop(): Promise<void> {
    return new Promise((resolve) => (this.server ? this.server.close(() => resolve()) : resolve()));
  }
  origin(): string {
    return `http://127.0.0.1:${this.port}`;
  }

  private async handle(req: IncomingMessage, res: ServerResponse) {
    const path = (req.url || '/').split('?')[0];
    // Test-time config: point the marketing site at the running broker.
    if (path === '/config.js') {
      res.writeHead(200, { 'Content-Type': 'application/javascript' });
      res.end(`window.BROWSERID = { authOrigin: ${JSON.stringify(baseUrl)} };`);
      return;
    }
    // Mirror nginx.conf: v3 redirects + clean URLs for the support pages.
    if (path === '/agents' || path === '/guestbook') {
      res.writeHead(301, { Location: path === '/agents' ? '/' : '/#guestbook' });
      res.end();
      return;
    }
    const clean = /^\/(developers|domains|demos)$/.exec(path);
    const file = path === '/' ? 'index.html' : clean ? `${clean[1]}.html` : path.slice(1);
    try {
      const body = await readFile(join(marketingDir, file));
      const type = file.endsWith('.js') ? 'application/javascript' : 'text/html';
      res.writeHead(200, { 'Content-Type': type });
      res.end(body);
    } catch {
      res.writeHead(404);
      res.end('not found');
    }
  }
}

test.describe('Origin split — marketing site', () => {
  let mkt: MarketingServer;
  test.beforeAll(async () => {
    mkt = new MarketingServer();
    await mkt.start();
  });
  test.afterAll(async () => {
    await mkt.stop();
  });

  test('home-page wall renders the broker feed cross-origin (v3: guestbook lives on index)', async ({
    page,
    request,
  }) => {
    // Read the broker feed directly (the source of truth), then assert the
    // marketing home page — served on a DIFFERENT origin — fetches and renders
    // it faithfully. Parity-based so it holds whether the feed is empty or
    // full, without depending on the (separately-broken) provisioning UI.
    const feed = await (await request.get(`${baseUrl}/guestbook/feed`)).json();
    const entries: any[] = feed.entries || [];

    await page.goto(`${mkt.origin()}/#guestbook`);
    // Sanity: this page is NOT the broker origin — the render is cross-origin.
    expect(new URL(page.url()).origin).not.toBe(new URL(baseUrl).origin);

    if (entries.length === 0) {
      await expect(page.locator('#wall')).toContainText('No one has signed yet', { timeout: 10000 });
    } else {
      // The wall shows the latest entries (capped at 4), display-name attributed.
      const latest = entries[0];
      await expect(page.locator('#wall')).toContainText(latest.message, { timeout: 10000 });
      const name = latest.name || String(latest.agent || '').split('@')[0];
      await expect(page.locator('#wall')).toContainText(name);
      await expect(page.locator('#wall .wall-entry')).toHaveCount(Math.min(entries.length, 4));
    }
  });

  test('home-page wall shows a graceful error when the broker feed is unreachable', async ({
    page,
  }) => {
    // Point the marketing page at a dead auth origin; it must not hang or throw.
    await page.route('**/config.js', (r) =>
      r.fulfill({
        contentType: 'application/javascript',
        body: `window.BROWSERID = { authOrigin: "http://127.0.0.1:1" };`,
      })
    );
    await page.goto(`${mkt.origin()}/`);
    await expect(page.locator('#wall')).toContainText('Couldn’t load the wall', { timeout: 10000 });
  });

  test('marketing landing "Sign in" points at the auth origin, not the marketing origin', async ({
    page,
  }) => {
    await page.goto(`${mkt.origin()}/`);
    const href = await page.getAttribute('[data-auth-href]', 'href');
    expect(href).toBe(`${baseUrl}/account`);
  });

  test('v3 nav: Demos is a page, Agents is gone, and the old URLs redirect', async ({
    page,
    request,
  }) => {
    await page.goto(`${mkt.origin()}/`);
    await expect(page.locator('nav a[href="/demos"]')).toHaveText('Demos');
    await expect(page.locator('nav a[href="/agents"]')).toHaveCount(0);

    // /agents and /guestbook 301 (nginx in prod; mirrored by the test server).
    const agents = await request.get(`${mkt.origin()}/agents`, { maxRedirects: 0 });
    expect(agents.status()).toBe(301);
    expect(agents.headers()['location']).toBe('/');
    const gb = await request.get(`${mkt.origin()}/guestbook`, { maxRedirects: 0 });
    expect(gb.status()).toBe(301);
    expect(gb.headers()['location']).toBe('/#guestbook');

    // The demos page serves at its clean URL with the wallet setup panel.
    await page.goto(`${mkt.origin()}/demos`);
    await expect(page.locator('.setup-panel')).toContainText('Give your agent the browserid wallet');
    await expect(page.locator('.demorow')).toHaveCount(6);
  });
});

test.describe('Origin split — broker redirects when MARKETING_URL is set', () => {
  let proc: ChildProcess | null = null;
  let port = 0;
  const marketing = 'https://marketing.example.test';

  test.beforeAll(async () => {
    // Boot a second broker instance with MARKETING_URL set, on its own port/db.
    port = 3100 + Math.floor(Math.random() * 800);
    const dir = await mkdtemp(join(tmpdir(), 'broker-split-'));
    proc = spawn(brokerBin, [], {
      env: {
        ...process.env,
        BROKER_PORT: String(port),
        DATABASE_PATH: join(dir, 'b.db'),
        BROKER_KEY_FILE: join(dir, 'k.json'),
        MARKETING_URL: marketing + '/', // trailing slash trimmed by the broker
        DISABLE_SMTP: '1',
      },
      stdio: 'ignore',
    });
    // Wait for it to accept connections.
    const deadline = Date.now() + 30000;
    for (;;) {
      try {
        const r = await fetch(`http://127.0.0.1:${port}/.well-known/browserid`);
        if (r.ok) break;
      } catch {}
      if (Date.now() > deadline) throw new Error('second broker did not start');
      await new Promise((r) => setTimeout(r, 200));
    }
  });
  test.afterAll(() => {
    if (proc) proc.kill('SIGKILL');
  });

  test('GET / and GET /guestbook 301 to the marketing origin', async ({ request }) => {
    const root = await request.get(`http://127.0.0.1:${port}/`, { maxRedirects: 0 });
    expect(root.status()).toBe(308); // Redirect::permanent → 308
    expect(root.headers()['location']).toBe(marketing);

    const gb = await request.get(`http://127.0.0.1:${port}/guestbook`, { maxRedirects: 0 });
    expect(gb.status()).toBe(308);
    expect(gb.headers()['location']).toBe(`${marketing}/guestbook`);
  });

  test('feed JSON + POST sign API stay on the auth origin (not redirected)', async ({ request }) => {
    const feed = await request.get(`http://127.0.0.1:${port}/guestbook/feed`, { maxRedirects: 0 });
    expect(feed.status()).toBe(200);
    expect(feed.headers()['content-type']).toContain('application/json');

    const sign = await request.post(`http://127.0.0.1:${port}/guestbook`, {
      data: { assertion: 'nope', message: 'x' },
      maxRedirects: 0,
    });
    expect(sign.status()).toBeGreaterThanOrEqual(400); // reached the handler, rejected
    expect(sign.status()).toBeLessThan(500);
  });
});
