/*
 * BrowserID-NG Dialog Logic
 * Based on Mozilla Persona (MPL 2.0) - simplified and modernized
 */

(function() {
  'use strict';

  // Set storageCheck bit so communication_iframe knows localStorage is accessible
  // (see issue #3905 in original browserid)
  try {
    localStorage.storageCheck = "true";
  } catch (e) {
    // localStorage may not be available (iOS privacy mode, etc.)
  }

  // State
  let state = {
    email: null,
    origin: null,
    callback: null,
    winchanCallback: null,  // WinChan response callback
    emails: [],
    selectedEmail: null,
    newEmail: null  // Email being added to account
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
    logout: '/wsapi/logout',
    addressInfo: '/wsapi/address_info',
    stageEmail: '/wsapi/stage_email',
    completeEmailAddition: '/wsapi/complete_email_addition'
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
    addEmail: document.getElementById('add-email-screen'),
    addEmailVerify: document.getElementById('add-email-verify-screen'),
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

  // Check email address info (type, state, primary IdP URLs)
  async function checkEmail(email) {
    try {
      const response = await fetch(`${API.addressInfo}?email=${encodeURIComponent(email)}`);
      const data = await response.json();
      // Return full addressInfo for primary IdP support
      return data;
    } catch (e) {
      // On error, assume email doesn't exist (new user flow)
      return { type: 'secondary', state: 'unknown' };
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
      pubkey: {
        algorithm: 'Ed25519',
        publicKey: publicKeyJwk.x
      },
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

  // Store logged-in state in localStorage for communication_iframe
  // This mirrors what BrowserID.Storage.site.set does
  function storeLoggedInState(origin, email) {
    try {
      const siteInfo = JSON.parse(localStorage.getItem('siteInfo') || '{}');
      siteInfo[origin] = siteInfo[origin] || {};
      siteInfo[origin].logged_in = email;
      siteInfo[origin].email = email;
      localStorage.setItem('siteInfo', JSON.stringify(siteInfo));
    } catch (e) {
      console.warn('Failed to store logged-in state:', e);
    }
  }

  // Store email keypair and certificate for silent assertions
  // This mirrors what BrowserID.Storage.addEmail does
  async function storeEmailKeypair(email, publicKey, privateKey, certificate) {
    try {
      // Export keys to JWK format
      const pubJwk = await crypto.subtle.exportKey('jwk', publicKey);
      const privJwk = await crypto.subtle.exportKey('jwk', privateKey);

      // Format keys for BrowserID storage format
      // jwcrypto-compat.js expects: pub.x for public key, priv.d and priv.x for secret key
      const pubObj = {
        algorithm: 'Ed25519',
        x: pubJwk.x
      };
      const privObj = {
        algorithm: 'Ed25519',
        d: privJwk.d,
        x: privJwk.x  // Need x for the full keypair when signing
      };

      // Store in emails namespace (default issuer)
      const allEmails = JSON.parse(localStorage.getItem('emails') || '{}');
      allEmails['default'] = allEmails['default'] || {};
      allEmails['default'][email] = {
        pub: pubObj,
        priv: privObj,
        cert: certificate
      };
      localStorage.setItem('emails', JSON.stringify(allEmails));
    } catch (e) {
      console.warn('Failed to store email keypair:', e);
    }
  }

  // Try to provision certificate from primary IdP
  async function tryPrimaryProvisioning(email, provUrl, authUrl) {
    return new Promise((resolve, reject) => {
      BrowserID.Provisioning.start(
        provUrl,
        email,
        function onSuccess(result) {
          resolve(result);
        },
        function onFailure(reason) {
          // Provisioning failed - need to authenticate
          reject({ needsAuth: true, authUrl: authUrl, reason: reason });
        }
      );
    });
  }

  // Handle primary IdP flow
  async function handlePrimaryIdP(email, addressInfo) {
    showScreen('loading');

    try {
      // Try provisioning first
      const result = await tryPrimaryProvisioning(email, addressInfo.prov, addressInfo.auth);

      // Got certificate! Create assertion
      const audience = state.origin;
      const expiresAt = Date.now() + (5 * 60 * 1000);

      const assertion = await createAssertionFromPrimary(
        result.keypair.privateKey,
        result.certificate,
        audience,
        expiresAt
      );

      // Store keypair for future use
      await storeEmailKeypair(
        email,
        result.keypair.publicKey,
        result.keypair.privateKey,
        result.certificate
      );

      // Authenticate with broker to establish session
      await apiCall('/wsapi/auth_with_assertion', 'POST', {
        assertion: assertion,
        ephemeral: false
      });

      storeLoggedInState(audience, email);
      showScreen('success');

      setTimeout(() => {
        sendResponse({ assertion });
      }, 1000);

    } catch (e) {
      if (e.needsAuth) {
        // Need to redirect to auth page
        redirectToPrimaryAuth(email, e.authUrl);
      } else {
        showError('Primary IdP provisioning failed: ' + e.message);
      }
    }
  }

  // Redirect to primary IdP auth page
  function redirectToPrimaryAuth(email, authUrl) {
    // Store state for return
    sessionStorage.setItem('browserid_pending_email', email);
    sessionStorage.setItem('browserid_pending_origin', state.origin);

    // Redirect to IdP auth page
    const url = new URL(authUrl);
    url.searchParams.set('email', email);
    url.searchParams.set('return_to', window.location.origin + '/sign_in');
    window.location.href = url.toString();
  }

  // Create assertion from primary IdP certificate
  async function createAssertionFromPrimary(privateKey, certificate, audience, expiresAt) {
    const payload = { aud: audience, exp: expiresAt };
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

    return `${certificate}~${message}.${signatureB64}`;
  }

  // Complete sign-in and return assertion
  async function completeSignIn(email) {
    try {
      const audience = state.origin;
      const expiresAt = Date.now() + (5 * 60 * 1000); // 5 minutes

      const { certificate, privateKey, publicKey } = await generateCertificate(email);
      const assertion = await createAssertion(privateKey, certificate, audience, expiresAt);

      // Store in localStorage so communication_iframe knows we're logged in
      storeLoggedInState(audience, email);

      // Store keypair and certificate for silent assertions
      await storeEmailKeypair(email, publicKey, privateKey, certificate);

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
    // WinChan callback takes precedence
    if (state.winchanCallback) {
      state.winchanCallback(data);
      state.winchanCallback = null;
      return;
    }
    // Fallback to postMessage for simple popup case
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
    if (state.winchanCallback) {
      state.winchanCallback(null);
      state.winchanCallback = null;
    } else {
      sendResponse({ assertion: null, cancelled: true });
    }
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
        const addressInfo = await checkEmail(email);

        // Handle based on type and state
        if (addressInfo.type === 'primary' && addressInfo.prov) {
          // Primary IdP flow
          if (addressInfo.state === 'transition_to_secondary') {
            // Was primary, now secondary with password
            showScreen('password');
          } else if (addressInfo.state === 'transition_no_password') {
            // Was primary, now secondary without password - need to set one
            // This will be handled in Task 7
            showScreen('create');
          } else {
            // Normal primary flow (known or unknown)
            await handlePrimaryIdP(email, addressInfo);
          }
        } else {
          // Secondary flow
          if (addressInfo.state === 'known') {
            showScreen('password');
          } else if (addressInfo.state === 'transition_to_primary' && addressInfo.prov) {
            // Was secondary, now primary
            await handlePrimaryIdP(email, addressInfo);
          } else {
            showScreen('create');
          }
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

    // Add email link - go to add email screen (not login screen)
    document.getElementById('add-email-link').addEventListener('click', (e) => {
      e.preventDefault();
      document.getElementById('new-email').value = '';
      document.getElementById('add-email-error').textContent = '';
      showScreen('addEmail');
    });

    // Add email form
    document.getElementById('add-email-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const email = document.getElementById('new-email').value.trim();

      if (!email) {
        document.getElementById('add-email-error').textContent = 'Email is required';
        return;
      }

      state.newEmail = email;
      document.querySelectorAll('.new-email-display').forEach(el => el.textContent = email);

      showScreen('loading');

      try {
        await apiCall(API.stageEmail, 'POST', { email });
        showScreen('addEmailVerify');
      } catch (e) {
        showScreen('addEmail');
        document.getElementById('add-email-error').textContent = e.message;
      }
    });

    // Add email verification form
    document.getElementById('add-email-verify-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const code = document.getElementById('add-email-code').value.trim();

      if (!code || code.length !== 6) {
        document.getElementById('add-email-verify-error').textContent = 'Please enter the 6-digit code';
        return;
      }

      showScreen('loading');

      try {
        await apiCall(API.completeEmailAddition, 'POST', { token: code });
        // Email added successfully - use it to sign in
        state.email = state.newEmail;
        await completeSignIn(state.email);
      } catch (e) {
        showScreen('addEmailVerify');
        document.getElementById('add-email-verify-error').textContent = e.message;
      }
    });

    // Back to pick email buttons
    document.querySelectorAll('.back-to-pick').forEach(btn => {
      btn.addEventListener('click', async () => {
        // Refresh email list and go back to pick screen
        try {
          const emailsResponse = await apiCall(API.listEmails);
          state.emails = emailsResponse.emails || [];
          populateEmailList(state.emails);
        } catch (e) {
          // Keep existing list
        }
        showScreen('pickEmail');
      });
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

    emails.forEach((emailStr, index) => {
      const li = document.createElement('li');
      li.innerHTML = `
        <label>
          <input type="radio" name="selected-email" value="${emailStr}" ${index === 0 ? 'checked' : ''}>
          <span class="email-text">${emailStr}</span>
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

        if (state.emails.length >= 1) {
          // Show email picker - even with one email, let user confirm or add another
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

  // Check for auth return from primary IdP
  function checkAuthReturn() {
    const hash = window.location.hash;

    if (hash === '#AUTH_RETURN' || hash === '#AUTH_RETURN_CANCEL') {
      // Clear hash from URL
      history.replaceState(null, '', window.location.pathname + window.location.search);

      // Restore state from sessionStorage
      const email = sessionStorage.getItem('browserid_pending_email');
      const origin = sessionStorage.getItem('browserid_pending_origin');

      if (!email || !origin) {
        console.error('Missing auth return state');
        showScreen('email');
        return true;
      }

      state.email = email;
      state.origin = origin;

      // Clear stored state
      sessionStorage.removeItem('browserid_pending_email');
      sessionStorage.removeItem('browserid_pending_origin');

      // Update UI
      document.querySelectorAll('.email-display').forEach(el => el.textContent = email);
      document.querySelectorAll('.rp-name').forEach(el => {
        el.textContent = new URL(origin).hostname;
      });

      if (hash === '#AUTH_RETURN') {
        // Auth succeeded - retry provisioning
        retryProvisioningAfterAuth(email);
      } else {
        // Auth was cancelled
        showError('Authentication was cancelled');
      }

      return true;  // Signal that auth return was handled
    }

    return false;  // No auth return, proceed with normal init
  }

  // Retry provisioning after user authenticated with primary IdP
  async function retryProvisioningAfterAuth(email) {
    showScreen('loading');

    try {
      // Get address info again to get provisioning URL
      const addressInfo = await checkEmail(email);

      if (addressInfo.type !== 'primary' || !addressInfo.prov) {
        throw new Error('Email is no longer a primary IdP');
      }

      // Retry provisioning (should succeed now that user is authenticated with IdP)
      const result = await tryPrimaryProvisioning(email, addressInfo.prov, addressInfo.auth);

      // Got certificate! Create assertion
      const audience = state.origin;
      const expiresAt = Date.now() + (5 * 60 * 1000);

      const assertion = await createAssertionFromPrimary(
        result.keypair.privateKey,
        result.certificate,
        audience,
        expiresAt
      );

      // Store keypair for future use
      await storeEmailKeypair(
        email,
        result.keypair.publicKey,
        result.keypair.privateKey,
        result.certificate
      );

      // Authenticate with broker to establish session
      await apiCall('/wsapi/auth_with_assertion', 'POST', {
        assertion: assertion,
        ephemeral: false
      });

      storeLoggedInState(audience, email);
      showScreen('success');

      setTimeout(() => {
        sendResponse({ assertion });
      }, 1000);

    } catch (e) {
      if (e.needsAuth) {
        // Still needs auth? Something went wrong
        showError('Authentication failed. Please try again.');
      } else {
        showError('Provisioning failed after authentication: ' + (e.message || e));
      }
    }
  }

  // Setup and start
  setupEventHandlers();

  // Check for auth return from primary IdP before normal init
  if (!checkAuthReturn()) {
    // Normal initialization
    const params = new URLSearchParams(window.location.search);
    const origin = params.get('origin');

    if (origin) {
      state.origin = origin;
      document.querySelectorAll('.rp-name').forEach(el => {
        el.textContent = new URL(origin).hostname;
      });
      init();
    }

    // Also support WinChan protocol for include.js compatibility
    if (typeof WinChan !== 'undefined' && WinChan.onOpen) {
      try {
        WinChan.onOpen(function(origin, args, cb) {
          if (args && args.params) {
            state.origin = origin;
            state.winchanCallback = cb;
            document.querySelectorAll('.rp-name').forEach(el => {
              el.textContent = new URL(origin).hostname;
            });
            init();
          }
        });
      } catch (e) {
        // WinChan.onOpen may throw if not in popup context
        console.log('WinChan not available:', e.message);
      }
    }
  }
})();
