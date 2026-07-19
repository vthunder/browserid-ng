/*
 * BrowserID-NG Login Dialog — device-cert model.
 *
 * The cold-start mediator (design doc Stages 1–4):
 *   1. email → discovery (/wsapi/address_info: _browserid DNSSEC + .well-known)
 *   2. device-cert issuance at the identity's IdP:
 *        - no primary → this broker's fallback surface (SMTP code →
 *          /auth/device_cert), iss = this broker
 *        - primary   → popup to the IdP's device-authorization page, which
 *          issues certs for our (non-extractable) pubkeys first-party
 *      Both yield a USER device cert (authentication) + CONFIG cert
 *      (authorization), stored in the origin keystore (IndexedDB).
 *   3. access-cert mint: sign an access request with the device key, POST to
 *      the IdP's headless mint → short-lived fresh-key access cert.
 *   4. warrant (config-key-signed, over identity+subject→audience) + assertion
 *      (access-key-signed) → return the 4-object presentation
 *      `access_cert~assertion~warrant~config_cert` to the RP.
 *
 * The RP never sees the device cert; the IdP gates every mint online.
 */

(function () {
  'use strict';

  // --- state ----------------------------------------------------------------

  const state = {
    origin: null,            // RP origin = assertion/warrant audience
    email: null,
    winchanCallback: null,
    acceptedFallbacks: null, // RP's accepted fallback issuers (null = {this broker})
    brokerDomain: location.hostname, // refined from /wsapi/session_context
    pendingPrimary: null     // {email, addressInfo} while waiting for a tap-to-continue
  };

  // --- tiny JWS toolkit (Ed25519 via WebCrypto, non-extractable keys) -------

  const enc = new TextEncoder();
  const b64urlJson = (o) =>
    btoa(String.fromCharCode(...enc.encode(JSON.stringify(o))))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const JWS_HDR = b64urlJson({ alg: 'EdDSA', typ: 'JWT' });
  const nowS = () => Math.floor(Date.now() / 1000);
  const rndHex = () => {
    const a = new Uint8Array(16);
    crypto.getRandomValues(a);
    return [...a].map((b) => b.toString(16).padStart(2, '0')).join('');
  };

  // Sign `claims` into a compact JWS with a (non-extractable) private CryptoKey.
  async function signJws(privateKey, claims) {
    const payload = b64urlJson(claims);
    const sig = await Keystore.sign(privateKey, `${JWS_HDR}.${payload}`);
    return `${JWS_HDR}.${payload}.${sig}`;
  }

  function decodeJws(jws) {
    try {
      const parts = jws.split('.');
      if (parts.length !== 3) return null;
      return JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
    } catch (e) { return null; }
  }

  function jwsExpired(jws, skewS) {
    const c = decodeJws(jws);
    if (!c || !c.exp) return true;
    return nowS() + (skewS || 60) >= c.exp;
  }

  // --- screens --------------------------------------------------------------

  const screens = {
    loading: document.getElementById('loading'),
    email: document.getElementById('email-screen'),
    code: document.getElementById('code-screen'),
    primaryContinue: document.getElementById('primary-continue-screen'),
    success: document.getElementById('success-screen'),
    error: document.getElementById('error-screen')
  };

  function showScreen(id, loadingText) {
    Object.values(screens).forEach((s) => s.classList.remove('active'));
    screens[id].classList.add('active');
    if (id === 'loading') {
      document.getElementById('loading-text').textContent = loadingText || 'Working...';
    }
  }

  function showError(message) {
    const el = document.querySelector('.error-message');
    if (el) el.textContent = message;
    showScreen('error');
  }

  function setEmailDisplays(email) {
    document.querySelectorAll('.email-display').forEach((el) => { el.textContent = email; });
  }

  // --- API helpers ----------------------------------------------------------

  async function postJson(url, body) {
    const r = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'accept': 'application/json' },
      credentials: url.startsWith('/') ? 'include' : 'omit',
      body: JSON.stringify(body)
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok && !data.success) {
      throw new Error(data.reason || data.error || `request failed (${r.status})`);
    }
    return data;
  }

  const getJson = (url) => fetch(url, { credentials: 'include' }).then((r) => r.json());

  // --- fallback-acceptance policy (spec §8.1) -------------------------------

  function normalizeAcceptedFallbacks(v) {
    if (v == null) return null;
    if (!Array.isArray(v)) v = [v];
    return v.map((s) => String(s).trim().toLowerCase()).filter(Boolean);
  }

  // Whether this broker's fallback identity is acceptable to the RP. Default
  // (no argument) = {this broker}; an explicit list must name this broker.
  function brokerFallbackAccepted() {
    if (!state.acceptedFallbacks) return true;
    return state.acceptedFallbacks.indexOf(state.brokerDomain.toLowerCase()) !== -1;
  }

  // --- discovery ------------------------------------------------------------

  async function discover(email) {
    const r = await fetch(`/wsapi/address_info?email=${encodeURIComponent(email)}`);
    if (!r.ok) {
      throw new Error(`couldn't look up this email (${r.status}) — please try again`);
    }
    return r.json();
  }

  // --- keystore -------------------------------------------------------------

  // A stored, unexpired (device, config) cert pair for (issuer, email), or null.
  async function storedDevicePair(issuer, email) {
    const device = await Keystore.getDevice(issuer, email, 'device');
    const config = await Keystore.getDevice(issuer, email, 'config');
    if (!device || !config || !device.cert || !config.cert) return null;
    if (jwsExpired(device.cert) || jwsExpired(config.cert)) return null;
    return { device, config };
  }

  async function storeDevicePair(issuer, email, keys, certs) {
    await Keystore.putDevice(issuer, email, 'device', {
      publicKeyX: keys.device.publicKeyX, privateKey: keys.device.privateKey, cert: certs.device_cert
    });
    await Keystore.putDevice(issuer, email, 'config', {
      publicKeyX: keys.config.publicKeyX, privateKey: keys.config.privateKey, cert: certs.config_cert
    });
  }

  // Known sign-in-ready identities (for the one-click list on the email screen).
  async function knownIdentities() {
    try {
      const recs = await Keystore.allDevice();
      const byEmail = {};
      recs.forEach((r) => {
        if (!r || !r.cert || jwsExpired(r.cert)) return;
        byEmail[r.email] = byEmail[r.email] || {};
        byEmail[r.email][r.kind] = true;
      });
      return Object.keys(byEmail).filter((e) => byEmail[e].device && byEmail[e].config).sort();
    } catch (e) {
      return [];
    }
  }

  // --- fallback IdP path (this broker vouches via SMTP) ---------------------

  async function fallbackObtainCerts(email) {
    // Within the 30-day email-cookie window we can silently re-issue.
    try {
      const who = await getJson('/whoami');
      if (who && who.authenticated && who.email === email) {
        return await fallbackIssue(email);
      }
    } catch (e) { /* fall through to SMTP */ }

    await postJson('/auth/send', { email });
    setEmailDisplays(email);
    showScreen('code');
    return null; // continued by the code-form handler
  }

  async function fallbackIssue(email) {
    showScreen('loading', 'Setting up this device...');
    const keys = { device: await Keystore.generate(), config: await Keystore.generate() };
    const certs = await postJson('/auth/device_cert', {
      email,
      device_pubkey: keys.device.publicKeyX,
      config_pubkey: keys.config.publicKeyX
    });
    await storeDevicePair(state.brokerDomain, email, keys, certs);
    return storedDevicePair(state.brokerDomain, email);
  }

  // --- primary IdP path (popup to the IdP's device-authorization page) ------

  // Opens the IdP popup and resolves with {device_cert, config_cert} once the
  // page posts them back. The pubkeys ride the URL fragment (public values;
  // the fragment never hits server logs); the response comes via postMessage
  // with our origin as the target.
  function primaryPopupFlow(email, deviceAuthUrl, keys) {
    return new Promise((resolve, reject) => {
      const idpOrigin = new URL(deviceAuthUrl).origin;
      const url = deviceAuthUrl +
        '#email=' + encodeURIComponent(email) +
        '&device_pubkey=' + encodeURIComponent(keys.device.publicKeyX) +
        '&config_pubkey=' + encodeURIComponent(keys.config.publicKeyX) +
        '&return_origin=' + encodeURIComponent(window.location.origin);

      const popup = window.open(url, 'browserid_device_auth', 'width=600,height=700');
      if (!popup) {
        reject({ popupBlocked: true });
        return;
      }
      showScreen('loading', 'Signing in with your email provider...');

      const TIMEOUT_MS = 3 * 60 * 1000;
      let timeoutId = null;
      let pollId = null;

      function cleanup() {
        clearTimeout(timeoutId);
        clearInterval(pollId);
        window.removeEventListener('message', onMessage);
      }

      function onMessage(ev) {
        if (ev.origin !== idpOrigin) return;
        const d = ev.data;
        if (!d || typeof d !== 'object') return;
        if (d.type === 'browserid:device_certs') {
          cleanup();
          try { popup.close(); } catch (e) { /* already closed */ }
          if (d.device_cert && d.config_cert) resolve({ device_cert: d.device_cert, config_cert: d.config_cert });
          else reject(new Error('identity provider returned no certificates'));
        } else if (d.type === 'browserid:device_error') {
          cleanup();
          try { popup.close(); } catch (e) { /* already closed */ }
          reject(new Error(d.reason || 'identity provider refused'));
        }
      }
      window.addEventListener('message', onMessage);

      timeoutId = setTimeout(() => {
        cleanup();
        try { popup.close(); } catch (e) { /* already closed */ }
        reject(new Error('sign-in with your email provider timed out'));
      }, TIMEOUT_MS);

      pollId = setInterval(() => {
        if (popup.closed) {
          cleanup();
          reject(new Error('the sign-in window was closed'));
        }
      }, 500);
    });
  }

  async function primaryObtainCerts(email, info) {
    if (!info.device_auth) {
      throw new Error(email.split('@')[1] +
        ' runs its own identity provider, but it does not support device sign-in yet.');
    }
    const keys = { device: await Keystore.generate(), config: await Keystore.generate() };
    let certs;
    try {
      certs = await primaryPopupFlow(email, info.device_auth, keys);
    } catch (e) {
      if (e && e.popupBlocked) {
        // Blocked — re-run from a fresh tap gesture.
        state.pendingPrimary = { email, info, keys };
        setEmailDisplays(email);
        document.querySelectorAll('.idp-name').forEach((el) => { el.textContent = email.split('@')[1]; });
        showScreen('primaryContinue');
        return null; // continued by the continue-primary handler
      }
      throw e;
    }
    return finishPrimaryCerts(email, keys, certs);
  }

  async function finishPrimaryCerts(email, keys, certs) {
    // Shape-check what came back before storing (the RP re-verifies fully).
    const dc = decodeJws(certs.device_cert);
    const cc = decodeJws(certs.config_cert);
    const domain = email.split('@')[1];
    if (!dc || !cc || dc.iss !== domain || cc.iss !== domain) {
      throw new Error('identity provider returned certificates for the wrong issuer');
    }
    await storeDevicePair(domain, email, keys, certs);
    return storedDevicePair(domain, email);
  }

  // --- mint + warrant + assertion → presentation ----------------------------

  async function completeLogin(email, issuer, pair, mintUrl) {
    showScreen('loading', 'Signing you in...');
    const audience = state.origin;

    // 1. Fresh access key + device-signed access request → IdP mint.
    const access = await Keystore.generate();
    const accessRequest = await signJws(pair.device.privateKey, {
      typ: 'browserid-access-request-v1',
      iat: nowS(),
      exp: nowS() + 600,
      jti: rndHex(),
      domain: issuer,
      identity: email,
      subject: 'user',
      'access-key': { algorithm: 'Ed25519', publicKey: access.publicKeyX }
    });
    const minted = await postJson(mintUrl, {
      device_cert: pair.device.cert,
      access_request: accessRequest
    });
    if (!minted.access_cert) throw new Error(minted.reason || 'mint failed');

    // 2. Login warrant, signed by the CONFIG key: (identity, user) → audience.
    //    Re-signed per login for now; registry-synced reuse lands with the
    //    device-shaped warrant registry work.
    const warrant = await signJws(pair.config.privateKey, {
      typ: 'browserid-warrant-v1',
      iat: nowS(),
      exp: nowS() + 90 * 86400,
      identifier: email,
      subject: 'user',
      audience,
      scopes: ['login']
    });

    // 3. Assertion for the RP's audience, signed by the fresh access key.
    const assertion = await signJws(access.privateKey, { exp: nowS() + 300, aud: audience });

    const presentation = `${minted.access_cert}~${assertion}~${warrant}~${pair.config.cert}`;
    state.email = email;
    returnPresentation(presentation);
  }

  // --- routing --------------------------------------------------------------

  async function handleEmailChosen(email) {
    showScreen('loading', 'Looking up ' + email + '...');
    setEmailDisplays(email);
    state.email = email;

    const info = await discover(email);
    const isPrimary = info.type === 'primary';
    const issuer = isPrimary ? email.split('@')[1] : state.brokerDomain;
    const mintUrl = isPrimary ? info.access_mint : '/access/mint';

    if (!isPrimary && !brokerFallbackAccepted()) {
      showError('This site doesn’t accept email sign-in via ' + state.brokerDomain +
        '. Use an email whose domain is its own identity provider.');
      return;
    }
    if (isPrimary && !mintUrl) {
      showError(issuer + ' runs its own identity provider, but it does not support device sign-in yet.');
      return;
    }

    // Fast path: this device already holds valid certs from the right issuer.
    const stored = await storedDevicePair(issuer, email);
    if (stored) {
      try {
        return await completeLogin(email, issuer, stored, mintUrl);
      } catch (e) {
        // Mint refused (revoked / IdP policy) — drop the stale pair and re-issue.
        await Keystore.delDevice(issuer, email, 'device');
        await Keystore.delDevice(issuer, email, 'config');
      }
    }

    const pair = isPrimary
      ? await primaryObtainCerts(email, info)
      : await fallbackObtainCerts(email);
    if (pair) await completeLogin(email, issuer, pair, mintUrl);
    // pair === null → an interactive step (code entry / tap-to-continue) took
    // over the flow and will call completeLogin itself.
  }

  // --- returning to the RP --------------------------------------------------

  function returnPresentation(presentation) {
    showScreen('success');
    setTimeout(() => {
      sendResponse({ presentation, email: state.email });
    }, 600);
  }

  function sendResponse(data) {
    if (state.winchanCallback) {
      state.winchanCallback(data);
      state.winchanCallback = null;
      return;
    }
    if (window.opener) {
      window.opener.postMessage(data, state.origin);
      window.close();
    } else if (window.parent !== window) {
      window.parent.postMessage(data, state.origin);
    }
  }

  function sendCancel() {
    if (state.winchanCallback) {
      state.winchanCallback(null);
      state.winchanCallback = null;
      try { window.close(); } catch (e) { /* not a popup */ }
    } else {
      sendResponse({ presentation: null, cancelled: true });
    }
  }

  // --- event wiring ---------------------------------------------------------

  function wireEvents() {
    document.getElementById('email-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const email = document.getElementById('email').value.trim().toLowerCase();
      if (!email) {
        document.getElementById('email-error').textContent = 'Email is required';
        return;
      }
      try {
        await handleEmailChosen(email);
      } catch (err) {
        showError(err.message || String(err));
      }
    });

    document.getElementById('code-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const code = document.getElementById('code').value.trim();
      if (!code || code.length !== 6) {
        document.getElementById('code-error').textContent = 'Please enter the 6-digit code';
        return;
      }
      showScreen('loading', 'Verifying...');
      try {
        await postJson('/auth/verify', { email: state.email, code });
        const pair = await fallbackIssue(state.email);
        if (!pair) throw new Error('device setup failed');
        await completeLogin(state.email, state.brokerDomain, pair, '/access/mint');
      } catch (err) {
        showScreen('code');
        document.getElementById('code-error').textContent = err.message || String(err);
      }
    });

    document.getElementById('resend-code-link').addEventListener('click', async (e) => {
      e.preventDefault();
      try {
        await postJson('/auth/send', { email: state.email });
        document.getElementById('code-error').textContent = 'A new code is on its way.';
      } catch (err) {
        document.getElementById('code-error').textContent = err.message || String(err);
      }
    });

    // Tap-to-continue: rerun the primary popup inside a fresh user gesture.
    document.getElementById('continue-primary').addEventListener('click', async () => {
      const p = state.pendingPrimary;
      if (!p) return showScreen('email');
      state.pendingPrimary = null;
      try {
        const certs = await primaryPopupFlow(p.email, p.info.device_auth, p.keys);
        const pair = await finishPrimaryCerts(p.email, p.keys, certs);
        await completeLogin(p.email, p.email.split('@')[1], pair, p.info.access_mint);
      } catch (err) {
        if (err && err.popupBlocked) {
          showError('Could not open the sign-in window. Please allow popups for this site and try again.');
        } else {
          showError(err.message || String(err));
        }
      }
    });

    document.querySelectorAll('.back').forEach((btn) => {
      btn.addEventListener('click', () => showScreen('email'));
    });
    document.querySelectorAll('.cancel').forEach((btn) => {
      btn.addEventListener('click', sendCancel);
    });
    document.querySelector('.try-again').addEventListener('click', () => showScreen('email'));
  }

  // --- init -----------------------------------------------------------------

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) => (
      { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
    ));
  }

  async function init() {
    document.querySelectorAll('.rp-name').forEach((el) => {
      el.textContent = new URL(state.origin).hostname;
    });

    // This broker's issuer identity (for the acceptedFallbacks gate).
    try {
      const ctx = await getJson('/wsapi/session_context');
      if (ctx && ctx.domain) state.brokerDomain = ctx.domain;
    } catch (e) { /* keep hostname */ }

    // If the RP hinted an email, drive it straight through.
    if (state.emailHint) {
      try {
        return await handleEmailChosen(state.emailHint);
      } catch (err) {
        return showError(err.message || String(err));
      }
    }

    // One-click list of identities this device can already sign in with.
    const known = await knownIdentities();
    if (known.length) {
      const list = document.getElementById('known-list');
      list.innerHTML = '';
      known.forEach((email) => {
        const li = document.createElement('li');
        li.innerHTML = '<label style="cursor:pointer"><span class="email-text">' +
          escapeHtml(email) + '</span></label>';
        li.addEventListener('click', () => {
          handleEmailChosen(email).catch((err) => showError(err.message || String(err)));
        });
        list.appendChild(li);
      });
      list.style.display = '';
    }
    showScreen('email');
  }

  function startRequest(origin, params, winchanCb) {
    state.origin = origin;
    state.winchanCallback = winchanCb || null;
    state.acceptedFallbacks = normalizeAcceptedFallbacks(params && params.acceptedFallbacks);
    state.emailHint = (params && params.email) || null;
    init().catch((e) => showError(e.message || String(e)));
  }

  wireEvents();

  // Entry 1: WinChan popup (the include.js path).
  if (typeof WinChan !== 'undefined' && WinChan.onOpen) {
    try {
      WinChan.onOpen((origin, args, cb) => {
        startRequest(origin, (args && args.params) || {}, cb);
      });
    } catch (e) {
      // Not opened via WinChan — fall through to query params.
    }
  }

  // Entry 2: direct link with ?origin= (dev / debugging).
  if (!state.origin) {
    const params = new URLSearchParams(window.location.search);
    const origin = params.get('origin');
    if (origin) {
      startRequest(origin, {
        acceptedFallbacks: params.get('accepted_fallbacks')
          ? params.get('accepted_fallbacks').split(',') : null,
        email: params.get('email')
      }, null);
    }
  }
})();
