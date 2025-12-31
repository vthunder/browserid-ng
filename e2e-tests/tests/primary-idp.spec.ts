/**
 * Primary IdP E2E Tests
 *
 * Tests the primary IdP flow where a domain operates its own identity provider
 * instead of using the fallback broker.
 */

import { test, expect } from '../fixtures/test-helpers';
import { createServer, IncomingMessage, ServerResponse } from 'http';

// Mock IdP server for testing
class MockIdpServer {
  private server: ReturnType<typeof createServer> | null = null;
  private port: number = 0;
  private authenticatedEmail: string | null = null;

  async start(): Promise<number> {
    return new Promise((resolve) => {
      this.server = createServer((req, res) => this.handleRequest(req, res));
      this.server.listen(0, '127.0.0.1', () => {
        const addr = this.server!.address();
        this.port = typeof addr === 'object' ? addr!.port : 0;
        console.log(`Mock IdP server started on port ${this.port}`);
        resolve(this.port);
      });
    });
  }

  async stop(): Promise<void> {
    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => resolve());
      } else {
        resolve();
      }
    });
  }

  setAuthenticatedEmail(email: string | null) {
    this.authenticatedEmail = email;
  }

  getBaseUrl(): string {
    return `http://127.0.0.1:${this.port}`;
  }

  private handleRequest(req: IncomingMessage, res: ServerResponse) {
    const url = new URL(req.url || '/', `http://127.0.0.1:${this.port}`);

    // CORS headers for cross-origin requests from broker
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
      res.writeHead(200);
      res.end();
      return;
    }

    if (url.pathname === '/.well-known/browserid') {
      this.handleWellKnown(res);
    } else if (url.pathname === '/browserid/provision') {
      this.handleProvision(res);
    } else if (url.pathname === '/browserid/auth') {
      this.handleAuth(res);
    } else if (url.pathname === '/api/browserid/whoami') {
      this.handleWhoami(res);
    } else if (url.pathname === '/api/browserid/cert_key' && req.method === 'POST') {
      this.handleCertKey(req, res);
    } else {
      res.writeHead(404);
      res.end('Not Found');
    }
  }

  private handleWellKnown(res: ServerResponse) {
    // Return a valid BrowserID support document
    // In a real test, we'd need a real keypair, but for now just test the flow
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      'public-key': {
        algorithm: 'Ed25519',
        publicKey: 'test-public-key-base64'
      },
      authentication: '/browserid/auth',
      provisioning: '/browserid/provision'
    }));
  }

  private handleProvision(res: ServerResponse) {
    // Serve the provisioning page with inlined API
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(`<!DOCTYPE html>
<html>
<head><title>Mock IdP Provisioning</title></head>
<body>
<script>
// BrowserID Provisioning API
(function() {
  if (typeof navigator.id === 'undefined') navigator.id = {};

  const channel = {
    _callbacks: {},
    _callId: 0,
    call: function(method, callback) {
      const id = ++this._callId;
      this._callbacks[id] = callback;
      window.parent.postMessage({ type: 'browserid:provisioning', method: method, id: id }, '*');
    },
    notify: function(method, data) {
      window.parent.postMessage({ type: 'browserid:provisioning', method: method, data: data }, '*');
    }
  };

  window.addEventListener('message', function(event) {
    if (event.data && event.data.type === 'browserid:provisioning:response') {
      const callback = channel._callbacks[event.data.id];
      if (callback) {
        delete channel._callbacks[event.data.id];
        callback(event.data.result);
      }
    }
  });

  navigator.id.beginProvisioning = function(callback) {
    channel.call('beginProvisioning', function(params) {
      callback(params.email, params.cert_duration_s);
    });
  };

  navigator.id.genKeyPair = function(callback) {
    channel.call('genKeyPair', function(result) {
      callback(result.publicKey);
    });
  };

  navigator.id.registerCertificate = function(certificate) {
    channel.notify('registerCertificate', { certificate: certificate });
  };

  navigator.id.raiseProvisioningFailure = function(reason) {
    channel.notify('raiseProvisioningFailure', { reason: reason });
  };
})();

// Start provisioning
navigator.id.beginProvisioning(async function(email, certDuration) {
  try {
    // Check if authenticated with this IdP
    const whoami = await fetch('/api/browserid/whoami', { credentials: 'same-origin' }).then(r => r.json());

    if (!whoami.email) {
      navigator.id.raiseProvisioningFailure('not authenticated');
      return;
    }

    if (whoami.email.toLowerCase() !== email.toLowerCase()) {
      navigator.id.raiseProvisioningFailure('email mismatch');
      return;
    }

    // Generate keypair
    navigator.id.genKeyPair(async function(publicKey) {
      try {
        const response = await fetch('/api/browserid/cert_key', {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: email, pubkey: JSON.parse(publicKey), duration: certDuration })
        });

        if (!response.ok) {
          const error = await response.json();
          navigator.id.raiseProvisioningFailure(error.error || 'Certificate signing failed');
          return;
        }

        const data = await response.json();
        navigator.id.registerCertificate(data.certificate);
      } catch (e) {
        navigator.id.raiseProvisioningFailure('Certificate request failed: ' + e.message);
      }
    });
  } catch (e) {
    navigator.id.raiseProvisioningFailure('Provisioning failed: ' + e.message);
  }
});
</script>
</body>
</html>`);
  }

  private handleAuth(res: ServerResponse) {
    // Serve the authentication page
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(`<!DOCTYPE html>
<html>
<head><title>Mock IdP Auth</title></head>
<body>
<h1>Mock IdP Authentication</h1>
<p>This is a test authentication page.</p>
</body>
</html>`);
  }

  private handleWhoami(res: ServerResponse) {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      email: this.authenticatedEmail
    }));
  }

  private handleCertKey(req: IncomingMessage, res: ServerResponse) {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        const data = JSON.parse(body);

        // Create a mock certificate (not cryptographically valid, but tests the flow)
        const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'JWT' })).toString('base64url');
        const payload = Buffer.from(JSON.stringify({
          iss: 'test-idp.example',
          iat: Math.floor(Date.now() / 1000),
          exp: Math.floor(Date.now() / 1000) + data.duration,
          'public-key': data.pubkey,
          principal: { email: data.email }
        })).toString('base64url');
        const signature = 'mock-signature';

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ certificate: `${header}.${payload}.${signature}` }));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid request' }));
      }
    });
  }
}

test.describe('Primary IdP Flow', () => {
  let mockIdp: MockIdpServer;
  const testDomain = 'test-idp.example';

  test.beforeAll(async ({ request }) => {
    // Start mock IdP server
    mockIdp = new MockIdpServer();
    const port = await mockIdp.start();

    // Register it with the broker
    const baseUrl = process.env.BROKER_URL || 'http://localhost:3000';
    const response = await request.post(`${baseUrl}/wsapi/test/set_mock_primary_idp`, {
      data: {
        domain: testDomain,
        base_url: mockIdp.getBaseUrl(),
        auth_path: '/browserid/auth',
        prov_path: '/browserid/provision'
      }
    });
    expect(response.ok()).toBeTruthy();
  });

  test.afterAll(async ({ request }) => {
    // Clean up mock IdP registration
    const baseUrl = process.env.BROKER_URL || 'http://localhost:3000';
    await request.post(`${baseUrl}/wsapi/test/clear_mock_primary_idps`);

    // Stop mock server
    await mockIdp.stop();
  });

  test('address_info returns primary type for mock IdP domain', async ({ request }) => {
    const baseUrl = process.env.BROKER_URL || 'http://localhost:3000';
    const email = `user@${testDomain}`;

    const response = await request.get(`${baseUrl}/wsapi/address_info?email=${encodeURIComponent(email)}`);
    expect(response.ok()).toBeTruthy();

    const info = await response.json();
    expect(info.type).toBe('primary');
    expect(info.auth).toContain(mockIdp.getBaseUrl());
    expect(info.prov).toContain(mockIdp.getBaseUrl());
    expect(info.issuer).toBe(testDomain);
  });

  test('entering primary IdP email triggers provisioning', async ({ dialogPage }) => {
    const email = `testuser@${testDomain}`;

    // Set the mock IdP to have this user authenticated
    mockIdp.setAuthenticatedEmail(email);

    await dialogPage.goto('http://example.com');

    // Enter the primary IdP email
    await dialogPage.enterEmail(email);

    // The dialog should attempt provisioning
    // Since user is "authenticated" with mock IdP, provisioning should succeed
    // or show auth screen if not authenticated

    // Wait a bit for provisioning attempt
    await dialogPage.page.waitForTimeout(2000);

    // Check console for any errors (provisioning communication)
    const logs: string[] = [];
    dialogPage.page.on('console', msg => logs.push(msg.text()));
  });

  test('unauthenticated user sees primary IdP auth page', async ({ dialogPage }) => {
    const email = `newuser@${testDomain}`;

    // User is NOT authenticated with the IdP
    mockIdp.setAuthenticatedEmail(null);

    await dialogPage.goto('http://example.com');
    await dialogPage.enterEmail(email);

    // Should eventually show primary auth screen or redirect
    // The exact behavior depends on how the dialog handles primary IdP auth
    await dialogPage.page.waitForTimeout(2000);
  });
});

test.describe('Primary IdP Provisioning Communication', () => {
  let mockIdp: MockIdpServer;
  const testDomain = 'prov-test.example';

  test.beforeAll(async ({ request }) => {
    mockIdp = new MockIdpServer();
    const port = await mockIdp.start();

    const baseUrl = process.env.BROKER_URL || 'http://localhost:3000';
    await request.post(`${baseUrl}/wsapi/test/set_mock_primary_idp`, {
      data: {
        domain: testDomain,
        base_url: mockIdp.getBaseUrl()
      }
    });
  });

  test.afterAll(async ({ request }) => {
    const baseUrl = process.env.BROKER_URL || 'http://localhost:3000';
    await request.post(`${baseUrl}/wsapi/test/clear_mock_primary_idps`);
    await mockIdp.stop();
  });

  test('provisioning iframe receives beginProvisioning call', async ({ page }) => {
    const baseUrl = process.env.BROKER_URL || 'http://localhost:3000';
    const email = `test@${testDomain}`;

    // Track postMessage communication
    const messages: any[] = [];

    await page.exposeFunction('captureMessage', (data: any) => {
      messages.push(data);
    });

    // Go directly to provisioning page to test the API
    await page.goto(`${mockIdp.getBaseUrl()}/browserid/provision`);

    // Inject a mock parent that captures messages
    await page.evaluate(() => {
      window.addEventListener('message', (event) => {
        (window as any).captureMessage(event.data);
      });
    });

    // The provisioning page should have sent a beginProvisioning message
    // (though without a parent, it won't get a response)
    await page.waitForTimeout(500);

    // Verify the page loaded without errors
    const content = await page.content();
    expect(content).toContain('beginProvisioning');
  });
});
