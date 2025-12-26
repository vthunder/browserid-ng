/*
 * BrowserID-NG Dialog Logic
 * Based on Mozilla Persona (MPL 2.0) - simplified and modernized
 */

(function() {
  'use strict';

  // State
  let state = {
    email: null,
    origin: null,
    callback: null,
    emails: [],
    selectedEmail: null
  };

  // API endpoints (relative to current origin)
  const API = {
    sessionContext: '/wsapi/session_context',
    stageUser: '/wsapi/stage_user',
    completeUserCreation: '/wsapi/complete_user_creation',
    authenticate: '/wsapi/authenticate_user',
    listEmails: '/wsapi/list_emails',
    certKey: '/wsapi/cert_key',
    stageReset: '/wsapi/stage_reset',
    completeReset: '/wsapi/complete_reset',
    logout: '/wsapi/logout'
  };

  // DOM elements
  const screens = {
    loading: document.getElementById('loading'),
    email: document.getElementById('email-screen'),
    password: document.getElementById('password-screen'),
    create: document.getElementById('create-screen'),
    verify: document.getElementById('verify-screen'),
    resetEmail: document.getElementById('reset-email-screen'),
    resetPassword: document.getElementById('reset-password-screen'),
    pickEmail: document.getElementById('pick-email-screen'),
    success: document.getElementById('success-screen'),
    error: document.getElementById('error-screen')
  };

  // Screen management
  function showScreen(screenId) {
    Object.values(screens).forEach(s => s.classList.remove('active'));
    screens[screenId].classList.add('active');
  }

  function showError(message) {
    document.querySelector('.error-message').textContent = message;
    showScreen('error');
  }

  // API helpers
  async function apiCall(endpoint, method = 'GET', body = null) {
    const options = {
      method,
      headers: {},
      credentials: 'include'
    };

    if (body) {
      options.headers['Content-Type'] = 'application/json';
      options.body = JSON.stringify(body);
    }

    const response = await fetch(endpoint, options);
    const data = await response.json();

    if (!response.ok && !data.success) {
      throw new Error(data.reason || 'Request failed');
    }

    return data;
  }

  // Check if email exists
  async function checkEmail(email) {
    try {
      // Try to authenticate with empty password to see if user exists
      // The API will return different errors for unknown user vs wrong password
      await apiCall(API.authenticate, 'POST', {
        email: email,
        pass: '',
        ephemeral: true
      });
      return { exists: true };
    } catch (e) {
      // "Invalid credentials" means user exists, other errors mean they don't
      if (e.message.includes('Invalid credentials') || e.message.includes('Password')) {
        return { exists: true };
      }
      return { exists: false };
    }
  }

  // Generate keypair and get certificate
  async function generateCertificate(email) {
    // Generate Ed25519 keypair
    const keyPair = await crypto.subtle.generateKey(
      { name: 'Ed25519' },
      true,
      ['sign', 'verify']
    );

    // Export public key
    const publicKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);

    // Request certificate from broker
    const certResponse = await apiCall(API.certKey, 'POST', {
      email: email,
      pubkey: JSON.stringify({
        algorithm: 'Ed25519',
        publicKey: publicKeyJwk.x
      }),
      ephemeral: false
    });

    return {
      certificate: certResponse.cert,
      privateKey: keyPair.privateKey,
      publicKey: keyPair.publicKey
    };
  }

  // Create assertion
  async function createAssertion(privateKey, certificate, audience, expiresAt) {
    // Assertion payload
    const payload = {
      aud: audience,
      exp: expiresAt
    };

    // Sign the assertion
    const header = { alg: 'EdDSA', typ: 'JWT' };
    const headerB64 = btoa(JSON.stringify(header)).replace(/=/g, '');
    const payloadB64 = btoa(JSON.stringify(payload)).replace(/=/g, '');
    const message = `${headerB64}.${payloadB64}`;

    const encoder = new TextEncoder();
    const signature = await crypto.subtle.sign(
      { name: 'Ed25519' },
      privateKey,
      encoder.encode(message)
    );

    const signatureB64 = btoa(String.fromCharCode(...new Uint8Array(signature)))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');

    const assertion = `${message}.${signatureB64}`;

    // Combine certificate and assertion
    return `${certificate}~${assertion}`;
  }

  // Complete sign-in and return assertion
  async function completeSignIn(email) {
    try {
      const audience = state.origin;
      const expiresAt = Date.now() + (5 * 60 * 1000); // 5 minutes

      const { certificate, privateKey } = await generateCertificate(email);
      const assertion = await createAssertion(privateKey, certificate, audience, expiresAt);

      showScreen('success');

      // Return assertion to parent
      setTimeout(() => {
        sendResponse({ assertion });
      }, 1000);
    } catch (e) {
      showError('Failed to generate assertion: ' + e.message);
    }
  }

  // Communication with parent window
  function sendResponse(data) {
    if (window.opener) {
      window.opener.postMessage(data, state.origin);
      window.close();
    } else if (window.parent !== window) {
      window.parent.postMessage(data, state.origin);
    } else if (state.callback) {
      state.callback(data);
    }
  }

  function sendCancel() {
    sendResponse({ assertion: null, cancelled: true });
  }

  // Event handlers
  function setupEventHandlers() {
    // Email form
    document.getElementById('email-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const email = document.getElementById('email').value.trim();

      if (!email) {
        document.getElementById('email-error').textContent = 'Email is required';
        return;
      }

      state.email = email;
      document.querySelectorAll('.email-display').forEach(el => el.textContent = email);

      showScreen('loading');

      try {
        const check = await checkEmail(email);
        if (check.exists) {
          showScreen('password');
        } else {
          showScreen('create');
        }
      } catch (e) {
        showError('Failed to check email: ' + e.message);
      }
    });

    // Password form (sign in)
    document.getElementById('password-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const password = document.getElementById('password').value;

      if (!password) {
        document.getElementById('password-error').textContent = 'Password is required';
        return;
      }

      showScreen('loading');

      try {
        await apiCall(API.authenticate, 'POST', {
          email: state.email,
          pass: password,
          ephemeral: false
        });

        await completeSignIn(state.email);
      } catch (e) {
        showScreen('password');
        document.getElementById('password-error').textContent = e.message;
      }
    });

    // Create account form
    document.getElementById('create-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const password = document.getElementById('create-password').value;
      const confirmPassword = document.getElementById('confirm-password').value;

      if (password.length < 8) {
        document.getElementById('create-password-error').textContent = 'Password must be at least 8 characters';
        return;
      }

      if (password !== confirmPassword) {
        document.getElementById('confirm-password-error').textContent = 'Passwords do not match';
        return;
      }

      state.password = password;
      showScreen('loading');

      try {
        await apiCall(API.stageUser, 'POST', {
          email: state.email,
          pass: password
        });

        showScreen('verify');
      } catch (e) {
        showScreen('create');
        document.getElementById('create-password-error').textContent = e.message;
      }
    });

    // Verification form
    document.getElementById('verify-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const code = document.getElementById('verification-code').value.trim();

      if (!code || code.length !== 6) {
        document.getElementById('verify-error').textContent = 'Please enter the 6-digit code';
        return;
      }

      showScreen('loading');

      try {
        await apiCall(API.completeUserCreation, 'POST', { token: code });
        await completeSignIn(state.email);
      } catch (e) {
        showScreen('verify');
        document.getElementById('verify-error').textContent = e.message;
      }
    });

    // Forgot password link
    document.getElementById('forgot-password-link').addEventListener('click', (e) => {
      e.preventDefault();
      document.getElementById('reset-email').value = state.email || '';
      showScreen('resetEmail');
    });

    // Reset email form
    document.getElementById('reset-email-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const email = document.getElementById('reset-email').value.trim();

      if (!email) {
        document.getElementById('reset-email-error').textContent = 'Email is required';
        return;
      }

      state.email = email;
      showScreen('loading');

      try {
        await apiCall(API.stageReset, 'POST', { email });
        showScreen('resetPassword');
      } catch (e) {
        showScreen('resetEmail');
        document.getElementById('reset-email-error').textContent = e.message;
      }
    });

    // Reset password form
    document.getElementById('reset-password-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const code = document.getElementById('reset-code').value.trim();
      const password = document.getElementById('new-password').value;

      if (!code || code.length !== 6) {
        document.getElementById('reset-code-error').textContent = 'Please enter the 6-digit code';
        return;
      }

      if (password.length < 8) {
        document.getElementById('new-password-error').textContent = 'Password must be at least 8 characters';
        return;
      }

      showScreen('loading');

      try {
        await apiCall(API.completeReset, 'POST', { token: code, pass: password });
        // Now sign in with the new password
        await apiCall(API.authenticate, 'POST', {
          email: state.email,
          pass: password,
          ephemeral: false
        });
        await completeSignIn(state.email);
      } catch (e) {
        showScreen('resetPassword');
        if (e.message.includes('code')) {
          document.getElementById('reset-code-error').textContent = e.message;
        } else {
          document.getElementById('new-password-error').textContent = e.message;
        }
      }
    });

    // Pick email form
    document.getElementById('pick-email-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const selected = document.querySelector('input[name="selected-email"]:checked');

      if (!selected) {
        return;
      }

      state.email = selected.value;
      await completeSignIn(state.email);
    });

    // Add email link
    document.getElementById('add-email-link').addEventListener('click', (e) => {
      e.preventDefault();
      showScreen('email');
    });

    // Back buttons
    document.querySelectorAll('.back').forEach(btn => {
      btn.addEventListener('click', () => {
        showScreen('email');
      });
    });

    // Cancel buttons
    document.querySelectorAll('.cancel').forEach(btn => {
      btn.addEventListener('click', () => {
        sendCancel();
      });
    });

    // Try again button
    document.querySelector('.try-again').addEventListener('click', () => {
      showScreen('email');
    });

    // Handle messages from parent
    window.addEventListener('message', (e) => {
      if (e.data && e.data.type === 'browserid:request') {
        state.origin = e.origin;
        document.querySelectorAll('.rp-name').forEach(el => {
          el.textContent = new URL(e.origin).hostname;
        });
        init();
      }
    });
  }

  // Populate email list
  function populateEmailList(emails) {
    const list = document.getElementById('email-list');
    list.innerHTML = '';

    emails.forEach((email, index) => {
      const li = document.createElement('li');
      li.innerHTML = `
        <label>
          <input type="radio" name="selected-email" value="${email.email}" ${index === 0 ? 'checked' : ''}>
          <span class="email-text">${email.email}</span>
        </label>
      `;
      list.appendChild(li);
    });
  }

  // Initialize
  async function init() {
    try {
      // Check if already authenticated
      const session = await apiCall(API.sessionContext);

      if (session.authenticated) {
        // Get user's emails
        const emailsResponse = await apiCall(API.listEmails);
        state.emails = emailsResponse.emails || [];

        if (state.emails.length === 1) {
          // Only one email, use it directly
          state.email = state.emails[0].email;
          await completeSignIn(state.email);
        } else if (state.emails.length > 1) {
          // Multiple emails, let user pick
          populateEmailList(state.emails);
          showScreen('pickEmail');
        } else {
          // No emails (shouldn't happen), show email entry
          showScreen('email');
        }
      } else {
        // Not authenticated, show email entry
        showScreen('email');
      }
    } catch (e) {
      showScreen('email');
    }
  }

  // Setup and start
  setupEventHandlers();

  // Get origin from URL params or wait for message
  const params = new URLSearchParams(window.location.search);
  const origin = params.get('origin');

  if (origin) {
    state.origin = origin;
    document.querySelectorAll('.rp-name').forEach(el => {
      el.textContent = new URL(origin).hostname;
    });
    init();
  }
  // Otherwise wait for postMessage
})();
