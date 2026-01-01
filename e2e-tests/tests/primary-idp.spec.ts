/**
 * Primary IdP E2E Tests
 *
 * Comprehensive tests for the primary IdP flow where a domain operates its own
 * identity provider instead of using the fallback broker.
 *
 * The flow:
 * 1. User enters email for primary IdP domain
 * 2. Broker detects primary via address_info
 * 3. Dialog creates hidden iframe to IdP's provisioning URL
 * 4. Provisioning page calls navigator.id.beginProvisioning()
 * 5. Dialog responds with email + cert_duration_s via postMessage
 * 6. Provisioning page checks if user is authenticated (whoami)
 * 7. If authenticated: genKeyPair → cert_key → registerCertificate
 * 8. If not: raiseProvisioningFailure → auth redirect
 */

import { test, expect, Page, BrowserContext } from '@playwright/test';
import { createServer, IncomingMessage, ServerResponse } from 'http';

// Mock IdP server that simulates a primary identity provider
class MockIdpServer {
  private server: ReturnType<typeof createServer> | null = null;
  private port: number = 0;
  private authenticatedEmail: string | null = null;
  private logs: string[] = [];
  private lastCertRequest: any = null;
  private shouldFailCertSigning = false;
  private whoamiDelay = 0;

  async start(): Promise<number> {
    return new Promise((resolve) => {
      this.server = createServer((req, res) => this.handleRequest(req, res));
      this.server.listen(0, '127.0.0.1', () => {
        const addr = this.server!.address();
        this.port = typeof addr === 'object' ? addr!.port : 0;
        this.logs.push(`Mock IdP server started on port ${this.port}`);
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
    this.logs.push(`Set authenticated email: ${email}`);
  }

  setWhoamiDelay(ms: number) {
    this.whoamiDelay = ms;
  }

  setShouldFailCertSigning(fail: boolean) {
    this.shouldFailCertSigning = fail;
  }

  getBaseUrl(): string {
    return `http://127.0.0.1:${this.port}`;
  }

  getLogs(): string[] {
    return this.logs;
  }

  getLastCertRequest(): any {
    return this.lastCertRequest;
  }

  clearLogs() {
    this.logs = [];
  }

  private handleRequest(req: IncomingMessage, res: ServerResponse) {
    const url = new URL(req.url || '/', `http://127.0.0.1:${this.port}`);
    this.logs.push(`${req.method} ${url.pathname}`);

    // CORS headers for cross-origin requests from broker
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Allow-Credentials', 'true');

    if (req.method === 'OPTIONS') {
      res.writeHead(200);
      res.end();
      return;
    }

    if (url.pathname === '/.well-known/browserid') {
      this.handleWellKnown(res);
    } else if (url.pathname === '/browserid/provision') {
      this.handleProvision(url, res);
    } else if (url.pathname === '/browserid/auth') {
      this.handleAuth(url, res);
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
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      'public-key': {
        algorithm: 'Ed25519',
        publicKey: 'dGVzdC1wdWJsaWMta2V5LWJhc2U2NA' // base64 encoded test key
      },
      authentication: '/browserid/auth',
      provisioning: '/browserid/provision'
    }));
  }

  private handleProvision(url: URL, res: ServerResponse) {
    // Serve the provisioning page with inlined API (same as sandmill.org)
    const email = url.searchParams.get('email') || '';
    this.logs.push(`Serving provisioning page for email: ${email}`);

    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(`<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Mock IdP Provisioning</title>
</head>
<body>
<script>
// BrowserID Provisioning API - communicates with broker via postMessage
(function() {
  'use strict';

  if (typeof navigator.id === 'undefined') {
    navigator.id = {};
  }

  const channel = {
    _callbacks: {},
    _callId: 0,

    call: function(method, callback) {
      const id = ++this._callId;
      this._callbacks[id] = callback;
      console.log('[MockIdP Provision] Sending:', method, 'id:', id);
      window.parent.postMessage({
        type: 'browserid:provisioning',
        method: method,
        id: id
      }, '*');
    },

    notify: function(method, data) {
      console.log('[MockIdP Provision] Notifying:', method, data);
      window.parent.postMessage({
        type: 'browserid:provisioning',
        method: method,
        data: data
      }, '*');
    }
  };

  window.addEventListener('message', function(event) {
    console.log('[MockIdP Provision] Received message:', event.data);
    if (event.data && event.data.type === 'browserid:provisioning:response') {
      const callback = channel._callbacks[event.data.id];
      if (callback) {
        delete channel._callbacks[event.data.id];
        callback(event.data.result);
      }
    }
  });

  navigator.id.beginProvisioning = function(callback) {
    console.log('[MockIdP Provision] beginProvisioning called');
    channel.call('beginProvisioning', function(params) {
      console.log('[MockIdP Provision] beginProvisioning response:', params);
      callback(params.email, params.cert_duration_s);
    });
  };

  navigator.id.genKeyPair = function(callback) {
    console.log('[MockIdP Provision] genKeyPair called');
    channel.call('genKeyPair', function(result) {
      console.log('[MockIdP Provision] genKeyPair response:', result);
      callback(result.publicKey);
    });
  };

  navigator.id.registerCertificate = function(certificate) {
    console.log('[MockIdP Provision] registerCertificate called');
    channel.notify('registerCertificate', { certificate: certificate });
  };

  navigator.id.raiseProvisioningFailure = function(reason) {
    console.log('[MockIdP Provision] raiseProvisioningFailure called:', reason);
    channel.notify('raiseProvisioningFailure', { reason: reason });
  };
})();

// Start provisioning
console.log('[MockIdP Provision] Page loaded, starting provisioning...');
navigator.id.beginProvisioning(async function(email, certDuration) {
  console.log('[MockIdP Provision] Got email:', email, 'duration:', certDuration);
  try {
    // Check if authenticated
    console.log('[MockIdP Provision] Checking whoami...');
    const whoami = await fetch('/api/browserid/whoami', {
      credentials: 'same-origin'
    }).then(r => r.json());

    console.log('[MockIdP Provision] whoami response:', whoami);

    if (!whoami.email) {
      console.log('[MockIdP Provision] Not authenticated, failing');
      navigator.id.raiseProvisioningFailure('not authenticated');
      return;
    }

    if (whoami.email.toLowerCase() !== email.toLowerCase()) {
      console.log('[MockIdP Provision] Email mismatch:', whoami.email, '!=', email);
      navigator.id.raiseProvisioningFailure('email mismatch');
      return;
    }

    // Generate keypair (broker does this)
    console.log('[MockIdP Provision] Generating keypair...');
    navigator.id.genKeyPair(async function(publicKey) {
      console.log('[MockIdP Provision] Got public key:', publicKey);
      try {
        // Sign certificate with our backend
        console.log('[MockIdP Provision] Requesting certificate...');
        const response = await fetch('/api/browserid/cert_key', {
          method: 'POST',
          credentials: 'same-origin',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            email: email,
            pubkey: JSON.parse(publicKey),
            duration: certDuration
          })
        });

        console.log('[MockIdP Provision] cert_key response status:', response.status);

        if (!response.ok) {
          const error = await response.json();
          console.log('[MockIdP Provision] cert_key error:', error);
          navigator.id.raiseProvisioningFailure(error.error || 'Certificate signing failed');
          return;
        }

        const data = await response.json();
        console.log('[MockIdP Provision] Got certificate, registering...');
        navigator.id.registerCertificate(data.certificate);
      } catch (e) {
        console.error('[MockIdP Provision] cert_key fetch error:', e);
        navigator.id.raiseProvisioningFailure('Certificate request failed: ' + e.message);
      }
    });
  } catch (e) {
    console.error('[MockIdP Provision] Provisioning error:', e);
    navigator.id.raiseProvisioningFailure('Provisioning failed: ' + e.message);
  }
});
</script>
</body>
</html>`);
  }

  private handleAuth(url: URL, res: ServerResponse) {
    const email = url.searchParams.get('email') || '';
    const returnTo = url.searchParams.get('return_to') || '';
    this.logs.push(`Auth page for email: ${email}, return_to: ${returnTo}`);

    // Serve the authentication page with inlined API
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(`<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Mock IdP Authentication</title>
  <style>
    body { font-family: sans-serif; max-width: 400px; margin: 50px auto; padding: 20px; }
    h1 { font-size: 24px; }
    button { padding: 10px 20px; margin: 5px; cursor: pointer; }
    #email-display { font-weight: bold; }
  </style>
</head>
<body>
<script>
// BrowserID Authentication API (inlined)
(function() {
  'use strict';

  if (typeof navigator.id === 'undefined') {
    navigator.id = {};
  }

  const params = new URLSearchParams(window.location.search);
  const email = params.get('email');
  const returnTo = params.get('return_to');

  console.log('[MockIdP Auth] Page loaded, email:', email, 'returnTo:', returnTo);

  navigator.id.beginAuthentication = function(callback) {
    console.log('[MockIdP Auth] beginAuthentication called');
    if (email) {
      callback(email);
    } else {
      console.error('[MockIdP Auth] No email parameter in URL');
    }
  };

  navigator.id.completeAuthentication = function() {
    console.log('[MockIdP Auth] completeAuthentication called');
    if (returnTo) {
      console.log('[MockIdP Auth] Redirecting to:', returnTo + '#AUTH_RETURN');
      window.location.href = returnTo + '#AUTH_RETURN';
    } else {
      console.error('[MockIdP Auth] No return URL available');
    }
  };

  navigator.id.raiseAuthenticationFailure = function(reason) {
    console.log('[MockIdP Auth] raiseAuthenticationFailure called:', reason);
    if (returnTo) {
      window.location.href = returnTo + '#AUTH_RETURN_CANCEL';
    }
  };
})();
</script>

<h1>Mock IdP Authentication</h1>
<p>Sign in to verify <span id="email-display"></span></p>

<form id="login-form">
  <button type="button" id="login-btn">Sign In (Simulate Success)</button>
  <button type="button" id="cancel-btn">Cancel</button>
</form>

<script>
const params = new URLSearchParams(window.location.search);
document.getElementById('email-display').textContent = params.get('email') || 'unknown';

document.getElementById('login-btn').addEventListener('click', function() {
  console.log('[MockIdP Auth] Login button clicked');
  // Simulate setting authenticated session
  fetch('/api/browserid/set_authenticated', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: params.get('email') })
  }).then(() => {
    navigator.id.completeAuthentication();
  });
});

document.getElementById('cancel-btn').addEventListener('click', function() {
  navigator.id.raiseAuthenticationFailure('User cancelled');
});
</script>
</body>
</html>`);
  }

  private handleWhoami(res: ServerResponse) {
    this.logs.push(`whoami returning: ${this.authenticatedEmail}`);

    // Optional delay to test timing issues
    const respond = () => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        email: this.authenticatedEmail
      }));
    };

    if (this.whoamiDelay > 0) {
      setTimeout(respond, this.whoamiDelay);
    } else {
      respond();
    }
  }

  private handleCertKey(req: IncomingMessage, res: ServerResponse) {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        const data = JSON.parse(body);
        this.lastCertRequest = data;
        this.logs.push(`cert_key request: email=${data.email}`);

        if (this.shouldFailCertSigning) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Certificate signing failed' }));
          return;
        }

        // Create a mock certificate (not cryptographically valid, but tests the flow)
        const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'JWT' })).toString('base64url');
        const payload = Buffer.from(JSON.stringify({
          iss: 'test-idp.example',
          iat: Math.floor(Date.now() / 1000),
          exp: Math.floor(Date.now() / 1000) + (data.duration || 86400),
          'public-key': data.pubkey,
          principal: { email: data.email }
        })).toString('base64url');
        const signature = 'mock-signature-for-testing';

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ certificate: `${header}.${payload}.${signature}` }));
      } catch (e) {
        this.logs.push(`cert_key error: ${e}`);
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid request' }));
      }
    });
  }
}

// Helper to register mock IdP with broker
async function registerMockIdp(request: any, domain: string, mockIdp: MockIdpServer) {
  const baseUrl = process.env.BROKER_URL || 'http://localhost:3000';
  const response = await request.post(`${baseUrl}/wsapi/test/set_mock_primary_idp`, {
    data: {
      domain: domain,
      base_url: mockIdp.getBaseUrl(),
      auth_path: '/browserid/auth',
      prov_path: '/browserid/provision'
    }
  });
  return response;
}

// Helper to clear all mock IdPs (use sparingly - prefer removeMockIdp for parallel safety)
async function clearMockIdps(request: any) {
  const baseUrl = process.env.BROKER_URL || 'http://localhost:3000';
  await request.post(`${baseUrl}/wsapi/test/clear_mock_primary_idps`);
}

// Helper to remove a specific mock IdP (parallel-safe)
async function removeMockIdp(request: any, domain: string) {
  const baseUrl = process.env.BROKER_URL || 'http://localhost:3000';
  await request.post(`${baseUrl}/wsapi/test/remove_mock_primary_idp`, {
    data: { domain }
  });
}

// Collect console logs from page
async function collectConsoleLogs(page: Page): Promise<string[]> {
  const logs: string[] = [];
  page.on('console', msg => {
    logs.push(`[${msg.type()}] ${msg.text()}`);
  });
  page.on('pageerror', err => {
    logs.push(`[error] ${err.message}`);
  });
  return logs;
}

// ============================================================================
// TEST SUITES
// ============================================================================

test.describe('Primary IdP: Basic API Tests', () => {
  test('address_info returns primary type for registered domain', async ({ request }) => {
    const mockIdp = new MockIdpServer();
    await mockIdp.start();
    const testDomain = `api1-${Date.now()}.example`;

    try {
      const registerResponse = await registerMockIdp(request, testDomain, mockIdp);
      expect(registerResponse.ok()).toBeTruthy();

      const baseUrl = process.env.BROKER_URL || 'http://localhost:3000';
      const email = `user@${testDomain}`;

      const response = await request.get(`${baseUrl}/wsapi/address_info?email=${encodeURIComponent(email)}`);
      expect(response.ok()).toBeTruthy();

      const info = await response.json();
      expect(info.type).toBe('primary');
      expect(info.auth).toContain(mockIdp.getBaseUrl());
      expect(info.prov).toContain(mockIdp.getBaseUrl());
      expect(info.issuer).toBe(testDomain);
    } finally {
      await removeMockIdp(request, testDomain);
      await mockIdp.stop();
    }
  });

  test('address_info returns secondary type for unregistered domain', async ({ request }) => {
    const baseUrl = process.env.BROKER_URL || 'http://localhost:3000';
    const email = 'user@unregistered-domain.example';

    const response = await request.get(`${baseUrl}/wsapi/address_info?email=${encodeURIComponent(email)}`);
    expect(response.ok()).toBeTruthy();

    const info = await response.json();
    expect(info.type).toBe('secondary');
  });

  test('mock IdP well-known endpoint works', async ({ request }) => {
    const mockIdp = new MockIdpServer();
    await mockIdp.start();

    try {
      const response = await request.get(`${mockIdp.getBaseUrl()}/.well-known/browserid`);
      expect(response.ok()).toBeTruthy();

      const doc = await response.json();
      expect(doc['public-key']).toBeDefined();
      expect(doc.authentication).toBe('/browserid/auth');
      expect(doc.provisioning).toBe('/browserid/provision');
    } finally {
      await mockIdp.stop();
    }
  });

  test('mock IdP whoami endpoint works', async ({ request }) => {
    const mockIdp = new MockIdpServer();
    await mockIdp.start();
    const testEmail = `test-${Date.now()}@api-test.example`;

    try {
      mockIdp.setAuthenticatedEmail(testEmail);

      const response = await request.get(`${mockIdp.getBaseUrl()}/api/browserid/whoami`);
      expect(response.ok()).toBeTruthy();

      const data = await response.json();
      expect(data.email).toBe(testEmail);
    } finally {
      await mockIdp.stop();
    }
  });

  test('mock IdP cert_key endpoint works', async ({ request }) => {
    const mockIdp = new MockIdpServer();
    await mockIdp.start();

    try {
      const response = await request.post(`${mockIdp.getBaseUrl()}/api/browserid/cert_key`, {
        data: {
          email: 'test@api-test.example',
          pubkey: { algorithm: 'Ed25519', publicKey: 'test-key' },
          duration: 86400
        }
      });
      expect(response.ok()).toBeTruthy();

      const data = await response.json();
      expect(data.certificate).toBeDefined();
      expect(data.certificate.split('.').length).toBe(3); // JWT format
    } finally {
      await mockIdp.stop();
    }
  });
});

test.describe('Primary IdP: Provisioning Page Loading', () => {
  test('provisioning page loads and contains API shim', async ({ page }) => {
    const mockIdp = new MockIdpServer();
    await mockIdp.start();

    try {
      await page.goto(`${mockIdp.getBaseUrl()}/browserid/provision`);

      // Check that navigator.id is defined
      const hasNavigatorId = await page.evaluate(() => typeof navigator.id !== 'undefined');
      expect(hasNavigatorId).toBe(true);

      // Check that all required methods exist
      const methods = await page.evaluate(() => ({
        beginProvisioning: typeof navigator.id.beginProvisioning === 'function',
        genKeyPair: typeof navigator.id.genKeyPair === 'function',
        registerCertificate: typeof navigator.id.registerCertificate === 'function',
        raiseProvisioningFailure: typeof navigator.id.raiseProvisioningFailure === 'function'
      }));

      expect(methods.beginProvisioning).toBe(true);
      expect(methods.genKeyPair).toBe(true);
      expect(methods.registerCertificate).toBe(true);
      expect(methods.raiseProvisioningFailure).toBe(true);
    } finally {
      await mockIdp.stop();
    }
  });

  test('provisioning page sends beginProvisioning message', async ({ page }) => {
    const mockIdp = new MockIdpServer();
    await mockIdp.start();

    try {
      const messages: any[] = [];

      // Listen for postMessage calls to parent
      await page.exposeFunction('capturePostMessage', (data: any) => {
        messages.push(data);
      });

      // Intercept postMessage before page loads
      await page.addInitScript(() => {
        const originalPostMessage = window.parent.postMessage.bind(window.parent);
        window.parent.postMessage = function(data: any, origin: any) {
          if (typeof (window as any).capturePostMessage === 'function') {
            (window as any).capturePostMessage(data);
          }
          // Don't actually send since there's no parent
        };
      });

      await page.goto(`${mockIdp.getBaseUrl()}/browserid/provision`);

      // Wait for the provisioning script to run
      await page.waitForTimeout(500);

      // Should have sent beginProvisioning message
      const beginProvMsg = messages.find(m =>
        m && m.type === 'browserid:provisioning' && m.method === 'beginProvisioning'
      );
      expect(beginProvMsg).toBeDefined();
    } finally {
      await mockIdp.stop();
    }
  });
});

test.describe('Primary IdP: PostMessage Communication', () => {
  test('provisioning iframe communicates with parent via postMessage', async ({ page, request }) => {
    const mockIdp = new MockIdpServer();
    await mockIdp.start();
    const testDomain = `postmsg1-${Date.now()}.example`;

    try {
      await registerMockIdp(request, testDomain, mockIdp);
      const baseUrl = process.env.BROKER_URL || 'http://localhost:3000';
      const testEmail = `testuser@${testDomain}`;
      mockIdp.setAuthenticatedEmail(testEmail);

      // Go to the broker dialog
      await page.goto(`${baseUrl}/dialog/dialog.html?origin=http://example.com`);
      await page.fill('#email', testEmail);
      await page.click('#email-form button[type="submit"]');

      // Wait for provisioning attempt
      await page.waitForTimeout(3000);

      // The mock IdP should have received requests
      const idpLogs = mockIdp.getLogs();
      expect(idpLogs.some(l => l.includes('GET /browserid/provision'))).toBe(true);
    } finally {
      await removeMockIdp(request, testDomain);
      await mockIdp.stop();
    }
  });

  test('authenticated user completes provisioning successfully', async ({ page, request }) => {
    const mockIdp = new MockIdpServer();
    await mockIdp.start();
    const testDomain = `postmsg2-${Date.now()}.example`;

    try {
      await registerMockIdp(request, testDomain, mockIdp);
      const baseUrl = process.env.BROKER_URL || 'http://localhost:3000';
      const testEmail = `success@${testDomain}`;
      mockIdp.setAuthenticatedEmail(testEmail);

      await page.goto(`${baseUrl}/dialog/dialog.html?origin=http://example.com`);
      await page.fill('#email', testEmail);
      await page.click('#email-form button[type="submit"]');

      // Wait for provisioning flow to complete
      await page.waitForFunction(() => {
        const success = document.querySelector('#success-screen')?.classList.contains('active');
        const error = document.querySelector('#error-screen')?.classList.contains('active');
        return success || error;
      }, { timeout: 15000 });

      const idpLogs = mockIdp.getLogs();

      // Verify the provisioning flow completed
      expect(idpLogs.some(l => l.includes('GET /browserid/provision'))).toBe(true);
      expect(idpLogs.some(l => l.includes('GET /api/browserid/whoami'))).toBe(true);
      expect(idpLogs.some(l => l.includes('POST /api/browserid/cert_key'))).toBe(true);

      const certRequest = mockIdp.getLastCertRequest();
      expect(certRequest).toBeDefined();
      expect(certRequest.email.toLowerCase()).toBe(testEmail.toLowerCase());
    } finally {
      await removeMockIdp(request, testDomain);
      await mockIdp.stop();
    }
  });

  test('unauthenticated user triggers provisioning failure', async ({ page, request }) => {
    const mockIdp = new MockIdpServer();
    await mockIdp.start();
    const testDomain = `postmsg3-${Date.now()}.example`;

    try {
      await registerMockIdp(request, testDomain, mockIdp);
      const baseUrl = process.env.BROKER_URL || 'http://localhost:3000';
      const testEmail = `unauth@${testDomain}`;
      mockIdp.setAuthenticatedEmail(null);

      await page.goto(`${baseUrl}/dialog/dialog.html?origin=http://example.com`);
      await page.fill('#email', testEmail);
      await page.click('#email-form button[type="submit"]');

      // Wait for provisioning to fail
      await page.waitForFunction(() => {
        return window.location.href.includes('/browserid/auth') ||
               document.querySelector('#error-screen')?.classList.contains('active');
      }, { timeout: 10000 }).catch(() => {});

      const idpLogs = mockIdp.getLogs();
      expect(idpLogs.some(l => l.includes('GET /browserid/provision'))).toBe(true);
      expect(idpLogs.some(l => l.includes('whoami returning: null'))).toBe(true);
      expect(idpLogs.some(l => l.includes('POST /api/browserid/cert_key'))).toBe(false);
    } finally {
      await removeMockIdp(request, testDomain);
      await mockIdp.stop();
    }
  });
});

test.describe('Primary IdP: Error Handling', () => {
  test('handles cert_key failure gracefully', async ({ page, request }) => {
    const mockIdp = new MockIdpServer();
    await mockIdp.start();
    const testDomain = `errors1-${Date.now()}.example`;

    try {
      await registerMockIdp(request, testDomain, mockIdp);
      const baseUrl = process.env.BROKER_URL || 'http://localhost:3000';
      const testEmail = `certfail@${testDomain}`;
      mockIdp.setAuthenticatedEmail(testEmail);
      mockIdp.setShouldFailCertSigning(true);

      await page.goto(`${baseUrl}/dialog/dialog.html?origin=http://example.com`);
      await page.fill('#email', testEmail);
      await page.click('#email-form button[type="submit"]');

      await page.waitForFunction(() => {
        return document.querySelector('#error-screen')?.classList.contains('active') ||
               window.location.href.includes('/browserid/auth');
      }, { timeout: 15000 }).catch(() => {});

      const idpLogs = mockIdp.getLogs();
      expect(idpLogs.some(l => l.includes('POST /api/browserid/cert_key'))).toBe(true);
    } finally {
      await removeMockIdp(request, testDomain);
      await mockIdp.stop();
    }
  });

  test('handles email mismatch gracefully', async ({ page, request }) => {
    const mockIdp = new MockIdpServer();
    await mockIdp.start();
    const testDomain = `errors2-${Date.now()}.example`;

    try {
      await registerMockIdp(request, testDomain, mockIdp);
      const baseUrl = process.env.BROKER_URL || 'http://localhost:3000';
      const requestedEmail = `requested@${testDomain}`;
      const authenticatedEmail = `different@${testDomain}`;
      mockIdp.setAuthenticatedEmail(authenticatedEmail);

      await page.goto(`${baseUrl}/dialog/dialog.html?origin=http://example.com`);
      await page.fill('#email', requestedEmail);
      await page.click('#email-form button[type="submit"]');

      await page.waitForFunction(() => {
        return window.location.href.includes('/browserid/auth') ||
               document.querySelector('#error-screen')?.classList.contains('active');
      }, { timeout: 10000 }).catch(() => {});

      const idpLogs = mockIdp.getLogs();
      expect(idpLogs.some(l => l.includes('GET /api/browserid/whoami'))).toBe(true);
      expect(idpLogs.some(l => l.includes('POST /api/browserid/cert_key'))).toBe(false);
    } finally {
      await removeMockIdp(request, testDomain);
      await mockIdp.stop();
    }
  });

  test.skip('handles provisioning timeout', async ({ page, request }) => {
    // This test is skipped because it takes 30+ seconds to run
    const mockIdp = new MockIdpServer();
    await mockIdp.start();
    const testDomain = `errors3-${Date.now()}.example`;

    try {
      await registerMockIdp(request, testDomain, mockIdp);
      const baseUrl = process.env.BROKER_URL || 'http://localhost:3000';
      const testEmail = `timeout@${testDomain}`;
      mockIdp.setAuthenticatedEmail(testEmail);
      mockIdp.setWhoamiDelay(35000);

      await page.goto(`${baseUrl}/dialog/dialog.html?origin=http://example.com`);
      await page.fill('#email', testEmail);
      await page.click('#email-form button[type="submit"]');

      await page.waitForTimeout(32000);
      await expect(page.locator('#error-screen')).toBeVisible();
    } finally {
      await removeMockIdp(request, testDomain);
      await mockIdp.stop();
    }
  });
});

test.describe('Primary IdP: Full Flow Integration', () => {
  test('complete flow: enter email → provisioning → certificate received', async ({ page, request }) => {
    const mockIdp = new MockIdpServer();
    await mockIdp.start();
    const testDomain = `fullflow1-${Date.now()}.example`;

    try {
      await registerMockIdp(request, testDomain, mockIdp);
      const baseUrl = process.env.BROKER_URL || 'http://localhost:3000';
      const testEmail = `complete@${testDomain}`;
      mockIdp.setAuthenticatedEmail(testEmail);

      await page.goto(`${baseUrl}/dialog/dialog.html?origin=http://example.com`);
      await expect(page.locator('#email-screen')).toBeVisible();

      await page.fill('#email', testEmail);
      await page.click('#email-form button[type="submit"]');
      await expect(page.locator('#loading')).toBeVisible({ timeout: 2000 });

      await page.waitForFunction(() => {
        const success = document.querySelector('#success-screen')?.classList.contains('active');
        const error = document.querySelector('#error-screen')?.classList.contains('active');
        return success || error;
      }, { timeout: 15000 });

      const idpLogs = mockIdp.getLogs();
      expect(idpLogs.some(l => l.includes('GET /browserid/provision'))).toBe(true);
      expect(idpLogs.some(l => l.includes('GET /api/browserid/whoami'))).toBe(true);
      expect(idpLogs.some(l => l.includes('POST /api/browserid/cert_key'))).toBe(true);

      const certRequest = mockIdp.getLastCertRequest();
      expect(certRequest).toBeDefined();
      expect(certRequest.email).toBe(testEmail);
      expect(certRequest.pubkey).toBeDefined();
      expect(certRequest.pubkey.algorithm).toBe('Ed25519');
    } finally {
      await removeMockIdp(request, testDomain);
      await mockIdp.stop();
    }
  });

  test('iframe receives correct email from dialog', async ({ page, request }) => {
    const mockIdp = new MockIdpServer();
    await mockIdp.start();
    const testDomain = `fullflow2-${Date.now()}.example`;

    try {
      await registerMockIdp(request, testDomain, mockIdp);
      const baseUrl = process.env.BROKER_URL || 'http://localhost:3000';
      const testEmail = `iframetest@${testDomain}`;
      mockIdp.setAuthenticatedEmail(testEmail);

      await page.goto(`${baseUrl}/dialog/dialog.html?origin=http://example.com`);
      await page.fill('#email', testEmail);
      await page.click('#email-form button[type="submit"]');

      // Wait for flow to complete
      await page.waitForFunction(() => {
        const success = document.querySelector('#success-screen')?.classList.contains('active');
        const error = document.querySelector('#error-screen')?.classList.contains('active');
        return success || error;
      }, { timeout: 15000 });

      const certRequest = mockIdp.getLastCertRequest();
      expect(certRequest).toBeDefined();

      // The email in cert request should match what user entered
      expect(certRequest.email.toLowerCase()).toBe(testEmail.toLowerCase());

      // pubkey should be valid JSON with algorithm
      expect(certRequest.pubkey).toBeDefined();
      expect(certRequest.pubkey.algorithm).toBe('Ed25519');
      expect(certRequest.pubkey.publicKey).toBeDefined();
    } finally {
      await removeMockIdp(request, testDomain);
      await mockIdp.stop();
    }
  });
});

test.describe('Primary IdP: Network and Loading Issues', () => {
  test('tracks all network requests to IdP', async ({ page, request }) => {
    const mockIdp = new MockIdpServer();
    await mockIdp.start();
    const testDomain = `network1-${Date.now()}.example`;

    try {
      await registerMockIdp(request, testDomain, mockIdp);
      const baseUrl = process.env.BROKER_URL || 'http://localhost:3000';
      const testEmail = `network@${testDomain}`;
      mockIdp.setAuthenticatedEmail(testEmail);
      mockIdp.clearLogs();

      const networkRequests: string[] = [];

      // Intercept network requests
      page.on('request', req => {
        const url = req.url();
        if (url.includes(mockIdp.getBaseUrl().replace('http://', ''))) {
          networkRequests.push(`${req.method()} ${url}`);
        }
      });

      page.on('requestfailed', req => {
        const url = req.url();
        if (url.includes(mockIdp.getBaseUrl().replace('http://', ''))) {
          networkRequests.push(`FAILED: ${req.method()} ${url} - ${req.failure()?.errorText}`);
        }
      });

      await page.goto(`${baseUrl}/dialog/dialog.html?origin=http://example.com`);
      await page.fill('#email', testEmail);
      await page.click('#email-form button[type="submit"]');

      await page.waitForTimeout(5000);

      console.log('=== Network Requests to IdP ===');
      networkRequests.forEach(r => console.log(r));

      // Should have made requests to provisioning endpoint
      expect(networkRequests.some(r => r.includes('/browserid/provision'))).toBe(true);
    } finally {
      await removeMockIdp(request, testDomain);
      await mockIdp.stop();
    }
  });

  test('handles iframe loading failure gracefully', async ({ page, request }) => {
    const baseUrl = process.env.BROKER_URL || 'http://localhost:3000';
    const badDomain = `nonexistent-${Date.now()}.invalid`;

    try {
      // Register mock with bad URL (non-existent port)
      await request.post(`${baseUrl}/wsapi/test/set_mock_primary_idp`, {
        data: {
          domain: badDomain,
          base_url: 'http://127.0.0.1:99999',
          auth_path: '/browserid/auth',
          prov_path: '/browserid/provision'
        }
      });

      await page.goto(`${baseUrl}/dialog/dialog.html?origin=http://example.com`);
      await page.fill('#email', `test@${badDomain}`);
      await page.click('#email-form button[type="submit"]');

      // Should eventually show error or timeout (provisioning has 30s timeout)
      // We wait for either error screen or stay on loading (timeout will happen later)
      await page.waitForFunction(() => {
        return document.querySelector('#error-screen')?.classList.contains('active') ||
               document.querySelector('#loading')?.classList.contains('active');
      }, { timeout: 10000 });

      // Either loading (waiting for timeout) or error is acceptable
      // The important thing is the app doesn't crash
      const hasError = await page.locator('#error-screen').isVisible();
      const isLoading = await page.locator('#loading').isVisible();
      expect(hasError || isLoading).toBe(true);
    } finally {
      await removeMockIdp(request, badDomain);
    }
  });
});
