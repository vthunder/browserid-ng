/*
 * BrowserID-NG Dialog Logic
 * Based on Mozilla Persona (MPL 2.0) — the original account-based login flow
 * (broker session, email chooser over ALL account identities, password /
 * create-account / verify / reset screens), completing on the DEVICE-CERT
 * model: the broker session issues a device+config cert pair (/device/issue),
 * the device key mints a fresh access cert (/access/mint), the config key
 * signs the login warrant, and the RP receives the 4-object presentation
 * `access_cert~assertion~warrant~config_cert`. Primary-IdP identities get
 * their pair from the IdP's device-authorization popup instead.
 */

(function() {
  'use strict';

  // Set storageCheck bit so communication_iframe knows localStorage is accessible
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
    derived: {},  // subordinate identity -> controlling parent email (mingo-cm8z)
    newEmail: null,  // Email being added to account
    pendingAddressInfo: null,  // Stored addressInfo for transition flows
    acceptedFallbacks: null,   // RP's accepted fallback IdPs (spec §8.1); null = default {this broker}
    brokerDomain: null,        // this broker's own issuer domain (from session_context)
    sboSign: false,  // RP requested the SBO typed-signing capability
    pendingPresentation: null,  // presentation held while showing the SBO consent screen
    provisionEmail: null,  // RP asked to provision/sign in a SPECIFIC identity (skip the chooser)
    loginHint: null,  // caller pre-filled the email (e.g. /account) → skip the email screen
    pendingPrimary: null,  // {email, info, keys} while waiting on tap-to-continue
    // Full-page redirect mode (Arc / blocked popups): {returnTo, state}. The
    // response navigates back to the RP with the payload in the fragment
    // instead of using WinChan/postMessage.
    redirect: null
  };

  // API endpoints (relative to current origin)
  const API = {
    sessionContext: '/wsapi/session_context',
    stageUser: '/wsapi/stage_user',
    completeUserCreation: '/wsapi/complete_user_creation',
    authenticate: '/wsapi/authenticate_user',
    listEmails: '/wsapi/list_emails',
    deviceIssue: '/device/issue',
    browserHolder: '/wsapi/browser_holder',
    accessMint: '/access/mint',
    stageReset: '/wsapi/stage_reset',
    completeReset: '/wsapi/complete_reset',
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
    primaryTransition: document.getElementById('primary-transition-screen'),
    primaryAuthContinue: document.getElementById('primary-auth-continue-screen'),
    sboConsent: document.getElementById('sbo-consent-screen'),
    success: document.getElementById('success-screen'),
    error: document.getElementById('error-screen')
  };

  // Screens where the FedCM "auto sign-in next time" checkbox belongs — the
  // ones that complete a sign-in and return a presentation.
  const FEDCM_OPTIN_SCREENS = { pickEmail: 1, password: 1, verify: 1 };

  // The checkbox lives outside the screen cards in markup; each .screen is
  // absolutely-positioned, so we MOVE the one checkbox element into the active
  // sign-in screen's .content so it's actually visible inside the card.
  function placeFedcmOptin(screenId) {
    const row = document.getElementById('fedcm-optin-row');
    if (!row || !state.fedcm) return;
    if (FEDCM_OPTIN_SCREENS[screenId]) {
      const content = screens[screenId] && screens[screenId].querySelector('.content');
      if (content) { content.appendChild(row); row.style.display = ''; }
    } else {
      row.style.display = 'none';
    }
  }

  // Screen management
  function showScreen(screenId, loadingText) {
    Object.values(screens).forEach(s => s.classList.remove('active'));
    screens[screenId].classList.add('active');
    if (screenId === 'loading') {
      const t = document.getElementById('loading-text');
      if (t) t.textContent = loadingText || 'Loading...';
    }
    placeFedcmOptin(screenId);
  }

  function showError(message) {
    const errorEl = document.querySelector('.error-message');
    if (errorEl) {
      errorEl.textContent = message;
    } else {
      console.error('Error (no error element):', message);
    }
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
      // State-changing wsapi endpoints require the session's CSRF token.
      // Fetched fresh per call: cheap for a login dialog, never stale
      // across the auth transitions that rotate the session.
      if (method === 'POST' && !('csrf' in body)) {
        try {
          const ctx = await (await fetch(API.sessionContext, { credentials: 'include' })).json();
          if (ctx.csrf_token) body = { ...body, csrf: ctx.csrf_token };
        } catch {}
      }
      options.headers['Content-Type'] = 'application/json';
      options.body = JSON.stringify(body);
    }

    const response = await fetch(endpoint, options);
    const data = await response.json();

    if (!response.ok && !data.success) {
      throw new Error(data.reason || data.error || 'Request failed');
    }

    return data;
  }

  // Plain JSON POST without the session-CSRF injection (mint endpoints are
  // device-cert-authed, and a primary's mint is cross-origin).
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

  // --- JWS toolkit (Ed25519 via WebCrypto, non-extractable keys) -----------

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

  async function signJws(privateKey, claims) {
    const payload = b64urlJson(claims);
    const sig = await Keystore.sign(privateKey, `${JWS_HDR}.${payload}`);
    return `${JWS_HDR}.${payload}.${sig}`;
  }

  function b64urlParse(str) {
    const b = atob(str.replace(/-/g, '+').replace(/_/g, '/'));
    const bytes = new Uint8Array(b.length);
    for (let i = 0; i < b.length; i++) bytes[i] = b.charCodeAt(i);
    return JSON.parse(new TextDecoder().decode(bytes));
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

  // The opaque holder claim carried by a device/config cert (holder model).
  function certHolder(jws) {
    const c = decodeJws(jws);
    return c ? c.holder : null;
  }

  // This browser's stable holder (holder-authorization model): one per browser,
  // reused across every identity. It is a non-secret opaque string, so it lives
  // in localStorage (not the keystore, which is for non-extractable keys), keyed
  // by the account's `browsers` prefix so a second account on this browser gets
  // its own holder. Returns null if it can't be determined (e.g. no session yet)
  // — issuance then falls back to a broker-assigned holder.
  async function browserHolder() {
    let prefix;
    try {
      const r = await apiCall(API.browserHolder, 'GET');
      prefix = r && r.prefix;
    } catch (e) { return null; }
    if (!prefix) return null;
    const key = 'browserid:holder:' + prefix;
    try {
      const cached = localStorage.getItem(key);
      if (cached) return cached;
    } catch (e) { /* fall through */ }
    const holder = prefix + '.' + rndHex().slice(0, 10);
    try { localStorage.setItem(key, holder); } catch (e) { /* best-effort */ }
    return holder;
  }

  // --- device-cert keystore (IndexedDB device store) -----------------------

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

  // Issue a fresh device+config pair for a session-owned email (the device
  // model's replacement for the classic /wsapi/cert_key).
  async function issueDevicePair(email) {
    const keys = { device: await Keystore.generate(), config: await Keystore.generate() };
    const holder = await browserHolder();
    const body = {
      email,
      device_pubkey: keys.device.publicKeyX,
      config_pubkey: keys.config.publicKeyX
    };
    if (holder) body.holder = holder;
    const certs = await apiCall(API.deviceIssue, 'POST', body);
    if (!certs.device_cert || !certs.config_cert) {
      throw new Error(certs.reason || 'device issuance failed');
    }
    await storeDevicePair(state.brokerDomain, email, keys, certs);
    // The account may have MOVED this device: the server silently redirects a
    // stale supplied holder to the move target. Follow it in the local cache
    // so future issuance asks for the right holder directly.
    const issuedHolder = certHolder(certs.device_cert);
    if (holder && issuedHolder && issuedHolder !== holder) {
      try {
        const r = await apiCall(API.browserHolder, 'GET');
        if (r && r.prefix) localStorage.setItem('browserid:holder:' + r.prefix, issuedHolder);
      } catch (e) { /* best-effort */ }
    }
    return storedDevicePair(state.brokerDomain, email);
  }

  // Mint + warrant + assertion → the 4-object presentation for `audience`
  // (the RP's origin, or the broker's own origin for the session join).
  async function buildPresentation(pair, issuer, mintUrl, email, audience, noRegister) {
    audience = audience || state.origin;

    // The opaque broker-assigned holder this device acts as, read from the
    // device cert (holder-authorization model). The mint copies it into the
    // access cert; the login warrant grants the holder's whole namespace
    // (`<prefix>.*`) so a login reuses across the user's browsers.
    const holder = certHolder(pair.device.cert);
    const loginMatcher = (holder && holder.includes('.'))
      ? holder.slice(0, holder.indexOf('.')) + '.*'
      : holder;

    // 1. Fresh access key + device-signed access request → IdP mint.
    const access = await Keystore.generate();
    const accessRequest = await signJws(pair.device.privateKey, {
      typ: 'browserid-access-request-v1',
      iat: nowS(),
      exp: nowS() + 600,
      jti: rndHex(),
      domain: issuer,
      identity: email,
      holder: holder,
      'access-key': { algorithm: 'Ed25519', publicKey: access.publicKeyX }
    });
    const minted = await postJson(mintUrl, {
      device_cert: pair.device.cert,
      access_request: accessRequest
    });
    if (!minted.access_cert) throw new Error(minted.reason || 'mint failed');

    // 2. Login warrant, signed by the CONFIG key: (identity, holder-matcher) → audience.
    // Registered with the hosted broker (best-effort) so it shows up — and is
    // revocable — on the account page's "Authorized sites", per the model
    // ("signed once, stored, reused device-agnostically"). A status ref is
    // allocated FIRST so the registered warrant is status-revocable; repeat
    // logins upsert to the same row. `noRegister` is set only by the internal
    // session-join presentation (not a site grant) — an RP hosted on the
    // broker's own origin (e.g. /broker-demo) still registers.
    let statusRef = null;
    const registerable = !noRegister;
    if (registerable) {
      try {
        const alloc = await apiCall('/wsapi/allocate_warrant_status', 'POST', {
          agent_email: email, audience, scopes: ['login']
        });
        if (alloc && alloc.uri) statusRef = { uri: alloc.uri, idx: alloc.idx };
      } catch (e) { console.warn('warrant status allocation failed:', e.message || e); }
    }
    const warrantClaims = {
      typ: 'browserid-warrant-v1',
      iat: nowS(),
      exp: nowS() + 90 * 86400,
      identifier: email,
      holder: loginMatcher,
      audience,
      scopes: ['login']
    };
    if (statusRef) warrantClaims.status = statusRef;
    const warrant = await signJws(pair.config.privateKey, warrantClaims);
    if (registerable) {
      try {
        await apiCall('/wsapi/register_warrant', 'POST', {
          warrant, config_cert: pair.config.cert
        });
      } catch (e) { console.warn('warrant registration failed:', e.message || e); }
    }

    // 3. Assertion for the RP's audience, signed by the fresh access key.
    const assertion = await signJws(access.privateKey, { exp: nowS() + 300, aud: audience });

    return `${minted.access_cert}~${assertion}~${warrant}~${pair.config.cert}`;
  }

  // Normalize the RP's acceptedFallbacks argument (spec §8.1): null/absent →
  // null (default policy applies); otherwise an array of lowercased issuer
  // domains (an explicit empty array means "primaries only").
  function normalizeAcceptedFallbacks(v) {
    if (v == null) return null;
    if (!Array.isArray(v)) v = [v];
    return v.map(s => String(s).trim().toLowerCase()).filter(Boolean);
  }

  // Whether this broker's own fallback (its `domain`) is acceptable to the RP.
  // Default (no argument) = {this broker}, so email sign-in works as today; an
  // explicit list must name this broker's domain, else the RP declined it.
  // Enforcement is still the RP's verifier (spec §6.1); this is fail-fast UX.
  function brokerFallbackAccepted() {
    if (!state.acceptedFallbacks) return true; // default {this broker}
    const dom = (state.brokerDomain || location.hostname).toLowerCase();
    return state.acceptedFallbacks.indexOf(dom) !== -1;
  }

  // Check email address info (type, state, primary IdP URLs)
  async function checkEmail(email) {
    // A lookup failure must NOT be silently treated as "new user" — doing so routed
    // existing/primary emails into the create-account flow and produced a confusing
    // "email already exists" 409. Surface the error so the caller can show it and let
    // the user retry. A genuinely-new email still returns 200 with state:"unknown".
    const response = await fetch(`${API.addressInfo}?email=${encodeURIComponent(email)}`);
    if (!response.ok) {
      throw new Error(`couldn't look up this email (${response.status}) — please try again`);
    }
    return await response.json();
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

  // Handle email chosen - the original state machine, on device certs.
  // Subordinate-identity substitution (mingo-cm8z). A derived identity (e.g. a
  // minted <handle>@issuer) cannot authenticate to its OWN issuer — the issuer
  // mints it but requires a fresh proof of the controlling parent. So when logging
  // INTO the issuer, we authenticate the parent and deliver ITS presentation
  // instead. For every OTHER relying party the subordinate is a first-class
  // identity (returns null → proceed normally, revealing nothing about the parent).
  async function maybeSubstituteParent(email) {
    if (state.provisionEmail) return null;
    let rpHost = null;
    try { rpHost = new URL(state.origin).hostname.toLowerCase(); } catch (e) { return null; }
    const emailDomain = (email.split('@')[1] || '').toLowerCase();
    if (!rpHost || emailDomain !== rpHost) return null;
    try {
      const pj = await apiCall(`/wsapi/parent_of?email=${encodeURIComponent(email)}`);
      return (pj && pj.parent_email) ? pj.parent_email : null;
    } catch (e) {
      // Not subordinate, not our email, or not signed in → no substitution.
      return null;
    }
  }

  /// A password-less account signing in with a broker-verified email. Proving
  /// control = the emailed reset code, then choose a password. (The classic
  /// signed-in /wsapi/set_password shortcut left with the old protocol — the
  /// reset flow covers both cases.)
  async function handleNoPasswordTransition(email) {
    state.email = email;
    document.querySelectorAll('.email-display').forEach(el => el.textContent = email);
    await apiCall(API.stageReset, 'POST', { email });
    showScreen('resetPassword');
  }

  async function handleEmailChosen(email, _substituted) {
    showScreen('loading');

    try {
      // 0. Subordinate-identity substitution (mingo-cm8z) — see maybeSubstituteParent.
      if (!_substituted) {
        const parent = await maybeSubstituteParent(email);
        if (parent) return await handleEmailChosen(parent, true);
      }

      // 1. Discovery: which IdP roots this email.
      const addressInfo = await checkEmail(email);

      if (addressInfo.type === 'primary') {
        // Primary email — its own IdP issues the device certs.
        return await handlePrimaryIdP(email, addressInfo);
      }

      // Everything below is secondary — this broker acts as the fallback IdP.
      // Fail fast if the RP didn't list this broker in acceptedFallbacks
      // (spec §8.1), rather than issuing and getting rejected at the RP.
      if (!brokerFallbackAccepted()) {
        const dom = state.brokerDomain || location.hostname;
        showError('This site doesn’t accept email sign-in via ' + dom +
          '. Use an email whose domain is its own identity provider.');
        return;
      }

      if (addressInfo.state === 'transition_to_secondary') {
        // Was primary, now secondary - need password
        state.email = email;
        document.querySelectorAll('.email-display').forEach(el => el.textContent = email);
        showScreen('password');
        return;
      }

      if (addressInfo.state === 'transition_no_password') {
        // Account without a password — prove control via code, then set one.
        await handleNoPasswordTransition(email);
        return;
      }

      if (addressInfo.state === 'unverified') {
        // Email not verified - re-verify
        await apiCall(API.stageEmail, 'POST', { email });
        state.email = email;
        document.querySelectorAll('.email-display').forEach(el => el.textContent = email);
        showScreen('verify');
        return;
      }

      // Secondary, known, verified — complete via the session (issue if needed).
      if (addressInfo.state === 'known') {
        return await completeSignIn(email);
      }

      // Unknown state - shouldn't happen for a selected email
      showError('Cannot sign in with this email (unknown state: ' + addressInfo.state + ')');

    } catch (e) {
      showError('Failed to sign in: ' + e.message);
    }
  }

  // --- primary IdP: device-authorization popup ------------------------------

  // Opens the IdP's device-authorization page and resolves with
  // {device_cert, config_cert} once it posts them back. The pubkeys ride the
  // URL fragment (public values; never reach server logs); the response comes
  // via postMessage with our origin as the target.
  //
  // `hold` (cold logins): ask the IdP page to STAY OPEN after posting the
  // certs, so that — once the broker session join reveals the account's
  // canonical `browsers` prefix — the SAME user gesture can re-sign the same
  // keys under the corrected holder (browserid-ng-rrve: a cold-issued holder
  // otherwise orphans a duplicate namespace). The resolved object then also
  // carries `reissue(holder)` and `done()`; an IdP that predates hold support
  // just closes itself, and `reissue` rejects immediately (non-fatal).
  function primaryPopupFlow(email, deviceAuthUrl, keys, holder, hold) {
    return new Promise((resolve, reject) => {
      const idpOrigin = new URL(deviceAuthUrl).origin;
      const url = deviceAuthUrl +
        '#email=' + encodeURIComponent(email) +
        '&device_pubkey=' + encodeURIComponent(keys.device.publicKeyX) +
        '&config_pubkey=' + encodeURIComponent(keys.config.publicKeyX) +
        (holder ? '&holder=' + encodeURIComponent(holder) : '') +
        (hold ? '&hold=1' : '') +
        '&return_origin=' + encodeURIComponent(window.location.origin);

      const popup = window.open(url, 'browserid_device_auth', 'width=600,height=700');
      if (!popup) {
        reject({ popupBlocked: true });
        return;
      }
      showScreen('loading', 'Authenticating with your email provider...');

      const TIMEOUT_MS = 3 * 60 * 1000;
      let timeoutId = null;
      let pollId = null;

      function cleanup() {
        clearTimeout(timeoutId);
        clearInterval(pollId);
        window.removeEventListener('message', onMessage);
      }

      function reissue(newHolder) {
        return new Promise((res, rej) => {
          if (popup.closed) { rej(new Error('the provider window is gone')); return; }
          let tid = null;
          function onMsg(ev) {
            if (ev.origin !== idpOrigin) return;
            const d = ev.data;
            if (!d || typeof d !== 'object') return;
            if (d.type === 'browserid:device_certs') {
              clearTimeout(tid);
              window.removeEventListener('message', onMsg);
              try { popup.close(); } catch (e) { /* already closed */ }
              if (d.device_cert && d.config_cert) res({ device_cert: d.device_cert, config_cert: d.config_cert });
              else rej(new Error('identity provider returned no certificates'));
            } else if (d.type === 'browserid:device_error') {
              clearTimeout(tid);
              window.removeEventListener('message', onMsg);
              try { popup.close(); } catch (e) { /* already closed */ }
              rej(new Error(d.reason || 'identity provider refused'));
            }
          }
          window.addEventListener('message', onMsg);
          popup.postMessage({ type: 'browserid:reissue', holder: newHolder }, idpOrigin);
          tid = setTimeout(() => {
            window.removeEventListener('message', onMsg);
            try { popup.close(); } catch (e) { /* already closed */ }
            rej(new Error('holder re-issue timed out'));
          }, 20 * 1000);
        });
      }

      function release() {
        try { popup.postMessage({ type: 'browserid:done' }, idpOrigin); } catch (e) { /* gone */ }
        try { popup.close(); } catch (e) { /* already closed */ }
      }

      function onMessage(ev) {
        if (ev.origin !== idpOrigin) return;
        const d = ev.data;
        if (!d || typeof d !== 'object') return;
        if (d.type === 'browserid:device_certs') {
          cleanup();
          if (!d.device_cert || !d.config_cert) {
            try { popup.close(); } catch (e) { /* already closed */ }
            reject(new Error('identity provider returned no certificates'));
            return;
          }
          if (hold) {
            // Popup stays open for one optional re-issue; the caller MUST end
            // with reissue() or done().
            resolve({ device_cert: d.device_cert, config_cert: d.config_cert, reissue, done: release });
          } else {
            try { popup.close(); } catch (e) { /* already closed */ }
            resolve({ device_cert: d.device_cert, config_cert: d.config_cert });
          }
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

  // Cold-login browser-holder reconciliation (browserid-ng-rrve). At cold
  // primary login there was no broker session, so the IdP self-assigned a
  // holder under a fresh prefix. The join either ADOPTED that prefix as the
  // account's `browsers` namespace (first-ever device — nothing to fix) or
  // could not (another device already owns `browsers`) — in which case the
  // issued certs sit in an orphan namespace. Now that the session exists,
  // fetch the canonical browsers holder and, on mismatch, re-sign the SAME
  // keys under it: through the still-open hold-mode popup when the IdP
  // supports it, else by RE-OPENING the authorize popup with the canonical
  // holder as an explicit param — plain passthrough every device-model IdP
  // already implements, so lazy IdPs reconcile too. Then replace the stored
  // pair and re-join so the broker records the corrected cert. Best-effort:
  // any failure (e.g. the re-open popup is blocked) keeps the initial
  // (working, if mislabeled) pair.
  async function reconcileBrowserHolder(email, domain, keys, certs, pair, mintUrl, deviceAuthUrl) {
    try {
      const canonical = await browserHolder(); // session exists after the join
      const issued = certHolder(pair.device.cert);
      const issuedPrefix = issued && issued.includes('.') ? issued.slice(0, issued.indexOf('.')) : null;
      const canonicalPrefix = canonical && canonical.includes('.') ? canonical.slice(0, canonical.indexOf('.')) : null;
      if (!canonicalPrefix || !issuedPrefix || issuedPrefix === canonicalPrefix) {
        certs.done();
        return pair;
      }
      let fresh;
      try {
        fresh = await certs.reissue(canonical);
      } catch (holdErr) {
        // The IdP didn't hold the popup open (or the re-issue died there).
        // Fall back to a fresh authorize popup with the holder pinned — the
        // user just finished interacting with this flow's popup, so an
        // immediate re-open is generally allowed. The IdP session is warm, so
        // it auto-issues and the window closes itself in a blink.
        if (!deviceAuthUrl) throw holdErr;
        fresh = await primaryPopupFlow(email, deviceAuthUrl, keys, canonical);
      }
      // The cold cert cached its (orphan) prefix as this browser's holder —
      // drop that so only the canonical entry remains.
      try { localStorage.removeItem('browserid:holder:' + issuedPrefix); } catch (e) { /* best-effort */ }
      const newPair = await finishPrimaryCerts(email, keys, fresh);
      // Re-join so the broker's holder registry records the corrected config
      // cert (upsert on pubkey replaces the orphan-holder row).
      try {
        const p = await buildPresentation(newPair, domain, mintUrl, email, window.location.origin, /* noRegister */ true);
        await apiCall('/wsapi/auth_with_presentation', 'POST', { presentation: p, ephemeral: false });
      } catch (e) {
        console.warn('holder reconcile re-join failed (non-fatal):', e.message || e);
      }
      return newPair;
    } catch (e) {
      console.warn('browser-holder reconciliation failed (non-fatal):', e.message || e);
      try { if (certs.done) certs.done(); } catch (e2) { /* gone */ }
      return pair;
    }
  }

  // Classic dual-assertion dance, on device certs: a primary identity has no
  // broker password, so present a SECOND presentation for the BROKER's own
  // audience to join/create the account (mingo-1c6v). That is what makes the
  // chooser remember primary identities across dialogs. Best-effort — the RP
  // login must not fail because the broker session couldn't be established.
  async function ensureBrokerSession(email, pair, issuer, mintUrl) {
    try {
      if (state.emails.indexOf(email) !== -1) return; // already on the account
      const brokerPresentation = await buildPresentation(
        pair, issuer, mintUrl, email, window.location.origin, /* noRegister */ true);
      await apiCall('/wsapi/auth_with_presentation', 'POST', {
        presentation: brokerPresentation,
        ephemeral: false
      });
    } catch (e) {
      console.warn('broker session join failed (non-fatal):', e.message || e);
    }
  }

  async function finishPrimaryCerts(email, keys, certs) {
    // Shape-check what came back before storing (the RP re-verifies fully).
    const dc = decodeJws(certs.device_cert);
    const cc = decodeJws(certs.config_cert);
    const domain = email.split('@')[1];
    if (!dc || !cc || dc.iss !== domain || cc.iss !== domain) {
      throw new Error('identity provider returned certificates for the wrong issuer');
    }
    // Remember the issued holder as this browser's holder for its prefix. On a
    // COLD first sign-in there was no session, so browserHolder() couldn't fetch
    // the account prefix and the IdP self-assigned one; the broker adopts that
    // prefix as the account's `browsers` namespace on session join. Caching it
    // here makes every later issuance on this browser reuse the SAME holder
    // instead of minting a sibling under the adopted prefix.
    if (dc.holder && dc.holder.includes('.')) {
      const p = dc.holder.slice(0, dc.holder.indexOf('.'));
      try {
        if (!localStorage.getItem('browserid:holder:' + p)) {
          localStorage.setItem('browserid:holder:' + p, dc.holder);
        }
      } catch (e) { /* best-effort */ }
    }
    await storeDevicePair(domain, email, keys, certs);
    return storedDevicePair(domain, email);
  }

  // Account-driven namespace move: is this device's holder still current, or
  // has the account reassigned it? (The move revoked the old certs up front;
  // this check is how the device heals.)
  async function pendingHolderMove(holder) {
    if (!holder) return null;
    try {
      const r = await apiCall('/wsapi/holder_assignment?holder=' + encodeURIComponent(holder), 'GET');
      return (r && r.status === 'moved' && r.new_holder) ? r.new_holder : null;
    } catch (e) { return null; } // no session / hiccup → check again next login
  }

  // Complete a pending move: re-issue the SAME keys under the broker-assigned
  // target holder — /device/issue for broker-rooted identities, the
  // device-authorize popup (explicit holder passthrough) for primary ones —
  // store the new pair, follow the move in the browser-holder cache, and
  // (primary) re-join so the broker records the corrected cert and cleans up
  // the old rows. Best-effort: on failure the old pair is returned (its certs
  // were revoked at move time, so sign-in may fail until a later attempt
  // completes the move).
  async function maybeCompleteHolderMove(email, issuer, pair, mintUrl, deviceAuthUrl) {
    try {
      const holder = certHolder(pair.device.cert);
      const target = await pendingHolderMove(holder);
      if (!target) return pair;
      if (issuer === (state.brokerDomain || location.hostname)) {
        const certs = await apiCall(API.deviceIssue, 'POST', {
          email,
          device_pubkey: pair.device.publicKeyX,
          config_pubkey: pair.config.publicKeyX,
          holder: target
        });
        if (!certs.device_cert || !certs.config_cert) {
          throw new Error(certs.reason || 'device issuance failed');
        }
        await storeDevicePair(issuer, email, pair, certs);
      } else {
        if (!deviceAuthUrl) return pair;
        const certs = await primaryPopupFlow(email, deviceAuthUrl, pair, target);
        await storeDevicePair(issuer, email, pair, certs);
        // Re-join so the broker records the corrected cert (which also
        // deletes the old holder's rows server-side).
        try {
          const moved = await storedDevicePair(issuer, email);
          const p = await buildPresentation(moved, issuer, mintUrl, email, window.location.origin, /* noRegister */ true);
          await apiCall('/wsapi/auth_with_presentation', 'POST', { presentation: p, ephemeral: false });
        } catch (e) {
          console.warn('holder move re-join failed (non-fatal):', e.message || e);
        }
      }
      // This browser's holder cache follows the move.
      try {
        const r = await apiCall(API.browserHolder, 'GET');
        if (r && r.prefix) localStorage.setItem('browserid:holder:' + r.prefix, target);
      } catch (e) { /* best-effort */ }
      return (await storedDevicePair(issuer, email)) || pair;
    } catch (e) {
      console.warn('holder move completion failed (non-fatal):', e.message || e);
      return pair;
    }
  }

  // Handle primary IdP flow: reuse a stored pair, else run the popup.
  async function handlePrimaryIdP(email, addressInfo) {
    showScreen('loading');
    try {
      const domain = email.split('@')[1];
      const mintUrl = addressInfo.access_mint;
      if (!mintUrl) {
        showError(domain + ' runs its own identity provider, but it does not support device sign-in yet.');
        return;
      }

      // Valid stored pair from this IdP → mint straight away.
      const stored = await storedDevicePair(domain, email);
      if (stored) {
        try {
          await ensureBrokerSession(email, stored, domain, mintUrl);
          const current = await maybeCompleteHolderMove(email, domain, stored, mintUrl, addressInfo.device_auth);
          return await finishSignIn(email, current, domain, mintUrl);
        } catch (e) {
          // Mint refused (revoked / IdP policy) — drop the pair and re-authorize.
          await Keystore.delDevice(domain, email, 'device');
          await Keystore.delDevice(domain, email, 'config');
        }
      }

      if (!addressInfo.device_auth) {
        showError(domain + ' runs its own identity provider, but it does not support device sign-in yet.');
        return;
      }
      // This browser's stable holder, passed to the IdP so it passthrough-signs
      // the same holder across all identities on this browser.
      const holder = await browserHolder();
      // Redirect mode cannot open a popup (that is why we are here) — hop to
      // the IdP's device-authorization page in THIS tab and resume on return.
      if (state.redirect) {
        return await primaryRedirectHop(email, addressInfo, holder);
      }
      const keys = { device: await Keystore.generate(), config: await Keystore.generate() };
      let certs;
      try {
        // No known browser holder = cold login: hold the popup open so the
        // post-join reconciliation can re-issue under the canonical prefix
        // without a second gesture.
        certs = await primaryPopupFlow(email, addressInfo.device_auth, keys, holder, /* hold */ !holder);
      } catch (e) {
        if (e && e.popupBlocked) {
          // Blocked — re-run from a fresh tap gesture (mobile).
          state.pendingPrimary = { email, info: addressInfo, keys, holder };
          document.querySelectorAll('.email-display').forEach(el => el.textContent = email);
          document.querySelectorAll('#primary-auth-continue-screen .idp-name')
            .forEach(el => { el.textContent = domain; });
          showScreen('primaryAuthContinue');
          return;
        }
        throw e;
      }
      let pair = await finishPrimaryCerts(email, keys, certs);
      await ensureBrokerSession(email, pair, domain, mintUrl);
      if (certs.reissue) {
        pair = await reconcileBrowserHolder(email, domain, keys, certs, pair, mintUrl, addressInfo.device_auth);
      }
      await finishSignIn(email, pair, domain, mintUrl);
    } catch (e) {
      showError('Sign-in with your email provider failed: ' + (e.message || e));
    }
  }

  // Same-tab primary hop (redirect mode): park the freshly-generated
  // non-extractable keypairs + the dialog's state in the keystore's pending
  // store (IndexedDB structured-clones CryptoKeys across navigations — the
  // same mechanism mingo-ytrs used), then navigate THIS tab to the IdP's
  // device-authorization page with a return_url pointing back at
  // /dialog/dialog.html?resume=device_auth.
  async function primaryRedirectHop(email, info, holder) {
    const keys = { device: await Keystore.generate(), config: await Keystore.generate() };
    await Keystore.putPending({
      kind: 'device_auth',
      deviceKey: keys.device.privateKey,
      devicePubX: keys.device.publicKeyX,
      configKey: keys.config.privateKey,
      configPubX: keys.config.publicKeyX,
      email,
      domain: email.split('@')[1],
      mintUrl: info.access_mint,
      dialog: {
        origin: state.origin,
        redirect: state.redirect,
        sboSign: state.sboSign,
        fedcm: !!state.fedcm,
        provisionEmail: state.provisionEmail,
        acceptedFallbacks: state.acceptedFallbacks,
        emails: state.emails
      }
    });
    const resume = window.location.origin + '/dialog/dialog.html?resume=device_auth';
    window.location.assign(
      info.device_auth +
      '#email=' + encodeURIComponent(email) +
      '&device_pubkey=' + encodeURIComponent(keys.device.publicKeyX) +
      '&config_pubkey=' + encodeURIComponent(keys.config.publicKeyX) +
      (holder ? '&holder=' + encodeURIComponent(holder) : '') +
      '&return_origin=' + encodeURIComponent(window.location.origin) +
      '&return_url=' + encodeURIComponent(resume)
    );
  }

  // Returning from the same-tab hop: certs (or an error) ride the fragment;
  // the keys + dialog state come back out of the pending store.
  async function resumeDeviceAuth() {
    showScreen('loading', 'Finishing sign-in...');
    const frag = new URLSearchParams(window.location.hash.replace(/^#/, ''));
    history.replaceState(null, '', window.location.pathname); // certs out of the URL bar
    let pending = null;
    try { pending = await Keystore.getPending(); } catch (e) { /* fall through */ }
    try { await Keystore.clearPending(); } catch (e) { /* best-effort */ }
    if (!pending || pending.kind !== 'device_auth' || !pending.dialog) {
      showError('Sign-in state was lost — go back to the site and click sign in again.');
      return;
    }
    state.origin = pending.dialog.origin;
    state.redirect = pending.dialog.redirect;
    state.sboSign = !!pending.dialog.sboSign;
    state.provisionEmail = pending.dialog.provisionEmail || null;
    state.acceptedFallbacks = pending.dialog.acceptedFallbacks || null;
    state.emails = pending.dialog.emails || [];
    maybeShowFedcmOptin(!!pending.dialog.fedcm);
    document.querySelectorAll('.rp-name').forEach(el => {
      try { el.textContent = new URL(state.origin).hostname; } catch (e) { /* leave */ }
    });
    const errReason = frag.get('device_error');
    if (errReason) {
      showError('Sign-in with your email provider failed: ' + errReason);
      return;
    }
    const certs = { device_cert: frag.get('device_cert'), config_cert: frag.get('config_cert') };
    if (!certs.device_cert || !certs.config_cert) {
      showError('Your email provider returned no certificates — try again.');
      return;
    }
    const keys = {
      device: { privateKey: pending.deviceKey, publicKeyX: pending.devicePubX },
      config: { privateKey: pending.configKey, publicKeyX: pending.configPubX }
    };
    try {
      const pair = await finishPrimaryCerts(pending.email, keys, certs);
      await ensureBrokerSession(pending.email, pair, pending.domain, pending.mintUrl);
      await finishSignIn(pending.email, pair, pending.domain, pending.mintUrl);
    } catch (e) {
      showError(e.message || String(e));
    }
  }

  // Complete sign-in for a broker-rooted (secondary) email: reuse or issue the
  // device pair under the session, then present.
  async function completeSignIn(email) {
    try {
      showScreen('loading');
      const issuer = state.brokerDomain || location.hostname;
      let pair = await storedDevicePair(issuer, email);
      if (!pair) {
        pair = await issueDevicePair(email);
      }
      pair = await maybeCompleteHolderMove(email, issuer, pair, API.accessMint, null);
      await finishSignIn(email, pair, issuer, API.accessMint);
    } catch (e) {
      showError('Failed to sign in: ' + e.message);
    }
  }

  // Shared tail: mint + warrant + assertion, record login, return to the RP.
  async function finishSignIn(email, pair, issuer, mintUrl) {
    const presentation = await buildPresentation(pair, issuer, mintUrl, email);
    storeLoggedInState(state.origin, email);
    state.email = email;
    returnPresentation(presentation);
  }

  // Single exit for every presentation-returning path. If the RP requested the
  // SBO typed-signing capability and this origin is not yet granted, show the
  // consent screen first; otherwise return immediately.
  function returnPresentation(presentation) {
    if (state.sboSign && !sboSignGranted(state.origin)) {
      state.pendingPresentation = presentation;
      const emailEl = screens.sboConsent.querySelector('.email-display');
      if (emailEl) emailEl.textContent = state.email || '';
      showScreen('sboConsent');
      return;
    }
    showScreen('success');
    setTimeout(() => {
      sendResponse(buildResponse(presentation));
    }, 1000);
  }

  // Show the "automatically sign in next time" checkbox only when the RP's
  // include.js signalled FedCM support (so embedded dialogs that don't set it
  // never show it). state.fedcm tracks the choice.
  //
  // Only on a fresh identity sign-in — NOT when the RP is provisioning a
  // specific identity (provision_email): that's a sub-step where "auto sign-in
  // next time" doesn't belong and would fire a redundant FedCM chooser.
  function maybeShowFedcmOptin(enabled) {
    state.fedcm = enabled && !state.provisionEmail;
    if (!state.fedcm) return;
    const box = document.getElementById('fedcm-optin');
    const note = document.getElementById('fedcm-optin-note');
    if (box && note) {
      const sync = () => { note.style.display = box.checked ? '' : 'none'; };
      box.addEventListener('change', sync);
      sync();
    }
  }

  // The response returned to the RP. When the RP requested SBO signing, report
  // the grant decision explicitly so it never has to guess.
  function buildResponse(presentation) {
    const resp = { presentation, email: state.email };
    if (state.sboSign) {
      resp.sbo_sign_granted = sboSignGranted(state.origin);
    }
    // FedCM opt-in: only if the checkbox was shown (state.fedcm) AND the user
    // actively ticked it. Read at response time so it reflects the real choice
    // on whatever screen they finished on.
    const optin = document.getElementById('fedcm-optin');
    if (state.fedcm && optin && optin.checked) resp.fedcm_optin = true;
    return resp;
  }

  // Per-origin grant for the SBO typed-signing capability, persisted in the same
  // `siteInfo` localStorage map communication_iframe reads via storage.site.get.
  function sboSignGranted(origin) {
    try {
      const siteInfo = JSON.parse(localStorage.getItem('siteInfo') || '{}');
      return !!(siteInfo[origin] && siteInfo[origin].sbo_sign_granted);
    } catch (e) {
      return false;
    }
  }

  function grantSboSign(origin) {
    try {
      const siteInfo = JSON.parse(localStorage.getItem('siteInfo') || '{}');
      siteInfo[origin] = siteInfo[origin] || {};
      siteInfo[origin].sbo_sign_granted = true;
      localStorage.setItem('siteInfo', JSON.stringify(siteInfo));
    } catch (e) {
      console.warn('Failed to store SBO signing grant:', e);
    }
  }

  // Communication with parent window
  function sendResponse(data) {
    // Redirect mode: hand the payload back in the URL fragment of a fresh RP
    // page load. location.replace keeps this dialog page out of history so
    // Back never re-enters a spent sign-in.
    if (state.redirect) {
      data.state = state.redirect.state;
      window.location.replace(state.redirect.returnTo + '#browserid=' + b64urlJson(data));
      return;
    }
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
    if (state.redirect) {
      sendResponse({ cancelled: true });
      return;
    }
    if (state.winchanCallback) {
      state.winchanCallback(null);
      state.winchanCallback = null;
    } else {
      sendResponse({ presentation: null, cancelled: true });
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
        // Subordinate substitution for a TYPED identity (mingo-cm8z), same as the
        // chooser path: typing a subordinate to log into its own issuer
        // authenticates the parent instead. No-ops when not applicable / signed out.
        const parent = await maybeSubstituteParent(email);
        if (parent) return await handleEmailChosen(parent, true);

        const addressInfo = await checkEmail(email);

        // Handle based on type and state
        if (addressInfo.type === 'primary') {
          // Primary IdP flow
          if (addressInfo.state === 'transition_to_secondary') {
            // Was primary, now secondary with password
            showScreen('password');
          } else if (addressInfo.state === 'transition_no_password') {
            // Was primary, now secondary without password - need to set one
            await handleNoPasswordTransition(email);
          } else {
            // Normal primary flow (known or unknown)
            await handlePrimaryIdP(email, addressInfo);
          }
        } else {
          // Secondary flow — also covers a primary email transiently seen as secondary
          // (e.g. a discovery hiccup), whose existing record yields a transition_* state.
          // Mirror handleEmailChosen so an *existing* account never falls into create.
          //
          // Fail fast if the RP didn't accept this broker as a fallback IdP
          // (spec §8.1). transition_to_primary is exempt — it routes to a
          // primary, not the broker.
          if (addressInfo.state !== 'transition_to_primary' && !brokerFallbackAccepted()) {
            const dom = state.brokerDomain || location.hostname;
            showError('This site doesn’t accept email sign-in via ' + dom +
              '. Use an email whose domain is its own identity provider.');
            return;
          }
          if (addressInfo.state === 'known') {
            showScreen('password');
          } else if (addressInfo.state === 'transition_to_secondary') {
            // Existing account (was primary) — authenticate with password
            showScreen('password');
          } else if (addressInfo.state === 'transition_no_password') {
            // Existing account without a password — prove control, set one
            await handleNoPasswordTransition(email);
          } else if (addressInfo.state === 'transition_to_primary' && addressInfo.device_auth) {
            // Was secondary, now primary - show transition info screen
            const domain = email.split('@')[1];
            document.querySelectorAll('.idp-name').forEach(el => el.textContent = domain);
            state.pendingAddressInfo = addressInfo;
            showScreen('primaryTransition');
          } else if (addressInfo.state === 'unknown') {
            // Genuinely new email — create an account
            showScreen('create');
          } else {
            showError('Cannot sign in with this email (unexpected state: ' + addressInfo.state + ')');
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

      showScreen('loading');

      try {
        await apiCall(API.stageUser, 'POST', {
          email: state.email,
          pass: password
        });

        showScreen('verify');
      } catch (e) {
        // The account already exists (e.g. we reached 'create' from a transient
        // mis-detection). Don't dead-end — route to sign-in for the existing account.
        if (/already exists/i.test(e.message)) {
          document.querySelectorAll('.email-display').forEach(el => el.textContent = state.email);
          showScreen('password');
          const pwErr = document.getElementById('password-error');
          if (pwErr) pwErr.textContent = 'This email is already registered — sign in below.';
        } else {
          showScreen('create');
          document.getElementById('create-password-error').textContent = e.message;
        }
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
      await handleEmailChosen(state.email);
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
        // A primary-IdP email is proven via its own IdP (the device-authorization
        // popup), not SMTP. Detect it first — otherwise a primary email would
        // wrongly get an emailed code. Only genuine secondary emails fall
        // through to SMTP staging.
        const addressInfo = await checkEmail(email);
        if (addressInfo.type === 'primary') {
          state.email = email;
          document.querySelectorAll('.email-display').forEach(el => el.textContent = email);
          await handlePrimaryIdP(email, addressInfo);
          return;
        }

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

    // Continue to primary IdP button (for secondary->primary transition)
    document.getElementById('continue-to-primary').addEventListener('click', async () => {
      showScreen('loading');

      try {
        const addressInfo = state.pendingAddressInfo || await checkEmail(state.email);

        if (addressInfo.type === 'primary' || addressInfo.device_auth) {
          await handlePrimaryIdP(state.email, addressInfo);
        } else {
          showError('This email is no longer a primary IdP');
        }
      } catch (e) {
        showError('Failed to connect to email provider: ' + e.message);
      }
    });

    // Tap-to-continue: open the primary-IdP popup from a real user gesture
    // (used when the earlier auto-open was blocked, e.g. on mobile).
    document.getElementById('continue-primary-auth').addEventListener('click', async () => {
      const p = state.pendingPrimary;
      if (!p) return showScreen('email');
      state.pendingPrimary = null;
      try {
        const certs = await primaryPopupFlow(p.email, p.info.device_auth, p.keys, p.holder, /* hold */ !p.holder);
        let pair = await finishPrimaryCerts(p.email, p.keys, certs);
        await ensureBrokerSession(p.email, pair, p.email.split('@')[1], p.info.access_mint);
        if (certs.reissue) {
          pair = await reconcileBrowserHolder(p.email, p.email.split('@')[1], p.keys, certs, pair, p.info.access_mint, p.info.device_auth);
        }
        await finishSignIn(p.email, pair, p.email.split('@')[1], p.info.access_mint);
      } catch (err) {
        if (err && err.popupBlocked) {
          showError('Could not open the sign-in window. Please allow popups for this site and try again.');
        } else {
          showError(err.message || String(err));
        }
      }
    });

    // Back to pick email buttons
    document.querySelectorAll('.back-to-pick').forEach(btn => {
      btn.addEventListener('click', async () => {
        // Refresh email list and go back to pick screen
        try {
          const emailsResponse = await apiCall(API.listEmails);
          state.emails = emailsResponse.emails || [];
          state.derived = derivedMapFromResponse(emailsResponse);
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

    // SBO signing consent: Allow grants this origin the typed-signing
    // capability; Not now returns the presentation without granting (login
    // still succeeds).
    function finishAfterConsent() {
      const presentation = state.pendingPresentation;
      state.pendingPresentation = null;
      showScreen('success');
      setTimeout(() => {
        sendResponse(buildResponse(presentation));
      }, 1000);
    }
    document.getElementById('sbo-consent-allow').addEventListener('click', () => {
      grantSboSign(state.origin);
      finishAfterConsent();
    });
    document.getElementById('sbo-consent-deny').addEventListener('click', () => {
      finishAfterConsent();
    });

    // Handle messages from parent
    window.addEventListener('message', (e) => {
      if (e.data && e.data.type === 'browserid:request') {
        state.origin = e.origin;
        state.sboSign = !!(e.data.params && e.data.params.sboSign);
        state.provisionEmail = (e.data.params && e.data.params.provisionEmail) || null;
        state.acceptedFallbacks = normalizeAcceptedFallbacks(e.data.params && e.data.params.acceptedFallbacks);
        document.querySelectorAll('.rp-name').forEach(el => {
          el.textContent = new URL(e.origin).hostname;
        });
        init();
      }
    });
  }

  // Build the subordinate -> parent map from a list_emails response (mingo-cm8z).
  function derivedMapFromResponse(resp) {
    const map = {};
    (resp && resp.derived || []).forEach(d => { map[d.email] = d.parent_email; });
    return map;
  }

  // Escape a value for safe interpolation into innerHTML.
  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => (
      { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
    ));
  }

  // Populate email list — ALL of the account's identities, whether or not this
  // browser holds device certs for them (issuance happens on selection).
  // Derived/subordinate identities (mingo-cm8z) get a distinct sub-label
  // naming the parent they sign in through.
  function populateEmailList(emails) {
    const list = document.getElementById('email-list');
    list.innerHTML = '';

    emails.forEach((emailStr, index) => {
      const parent = state.derived[emailStr];
      const li = document.createElement('li');
      if (parent) li.className = 'derived';
      const safeEmail = escapeHtml(emailStr);
      const sub = parent
        ? `<span class="email-sub">signs in via ${escapeHtml(parent)}</span>`
        : '';
      li.innerHTML = `
        <label>
          <input type="radio" name="selected-email" value="${safeEmail}" ${index === 0 ? 'checked' : ''}>
          <span class="email-text">${safeEmail}${sub}</span>
        </label>
      `;
      list.appendChild(li);
    });
  }

  // Initialize
  async function init() {
    // Drop any classic-era client state (old identity-cert store, legacy key
    // blobs) — the device store is the only keystore now.
    try { await Keystore.purgeLegacy(); } catch (e) { console.warn('keystore purge:', e); }
    // Learn this broker's own issuer domain (its fallback-IdP identity) so the
    // acceptedFallbacks gate (spec §8.1) works on every entry path, including
    // the provisionEmail fast-path below.
    try { state.brokerDomain = (await apiCall(API.sessionContext)).domain || state.brokerDomain; } catch {}

    // If the RP asked to provision/sign in a SPECIFIC identity, skip the chooser
    // entirely and drive that identity straight through.
    if (state.provisionEmail) {
      showScreen('loading');
      handleEmailChosen(state.provisionEmail);
      return;
    }
    // A caller (e.g. /account) pre-filled the email → skip the email screen and
    // drive that identity straight through, instead of re-prompting.
    if (state.loginHint) {
      showScreen('loading');
      handleEmailChosen(state.loginHint);
      return;
    }
    try {
      // Check if already authenticated
      const session = await apiCall(API.sessionContext);

      if (session.authenticated) {
        // Get user's emails
        const emailsResponse = await apiCall(API.listEmails);
        state.emails = emailsResponse.emails || [];
        state.derived = derivedMapFromResponse(emailsResponse);

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

  // Setup and start
  setupEventHandlers();

  const params = new URLSearchParams(window.location.search);

  if (params.get('resume') === 'device_auth') {
    // Returning from the same-tab primary hop (redirect mode).
    resumeDeviceAuth();
  } else if (params.get('rp_redirect') === '1') {
    // Full-page redirect mode: the RP's include.js navigated here because the
    // popup failed (Arc detaches popups; blockers). The response goes back by
    // navigation, so the return address MUST belong to the requesting origin —
    // in the popup flow postMessage's targetOrigin enforces this; here we must:
    // otherwise a crafted link could deliver a presentation minted for the
    // victim RP's audience to an attacker's page.
    const rpOrigin = params.get('rp_origin') || '';
    const returnTo = params.get('return_to') || '';
    let returnOk = false;
    try { returnOk = !!rpOrigin && new URL(returnTo).origin === rpOrigin; } catch (e) { /* invalid */ }
    if (!returnOk) {
      showError('Invalid sign-in link: the return address does not belong to the requesting site.');
    } else {
      state.origin = rpOrigin;
      state.redirect = { returnTo, state: params.get('state') || '' };
      let opts = {};
      try { opts = b64urlParse(params.get('params') || '') || {}; } catch (e) { /* defaults */ }
      state.sboSign = !!opts.sboSign;
      state.provisionEmail = opts.provisionEmail || null;
      state.loginHint = params.get('login_hint') || null;
      state.acceptedFallbacks = normalizeAcceptedFallbacks(opts.acceptedFallbacks);
      maybeShowFedcmOptin(!!opts.fedcm);
      document.querySelectorAll('.rp-name').forEach(el => {
        el.textContent = new URL(rpOrigin).hostname;
      });
      init();
    }
  } else if (params.get('origin')) {
    // Direct link with ?origin= (dev / debugging).
    const origin = params.get('origin');
    state.origin = origin;
    state.sboSign = params.get('sbo_sign') === '1';
    state.provisionEmail = params.get('provision_email');
    state.acceptedFallbacks = normalizeAcceptedFallbacks(
      params.get('accepted_fallbacks') ? params.get('accepted_fallbacks').split(',') : null);
    document.querySelectorAll('.rp-name').forEach(el => {
      el.textContent = new URL(origin).hostname;
    });
    init();
  }

  // WinChan protocol for include.js
  let winchanBroken = false;
  if (typeof WinChan !== 'undefined' && WinChan.onOpen) {
    try {
      WinChan.onOpen(function(origin, args, cb) {
        if (args && args.params) {
          state.origin = origin;
          state.sboSign = !!args.params.sboSign;
          state.provisionEmail = args.params.provisionEmail || null;
          state.acceptedFallbacks = normalizeAcceptedFallbacks(args.params.acceptedFallbacks);
          state.winchanCallback = cb;
          // FedCM opt-in: include.js sets this when the browser supports FedCM.
          maybeShowFedcmOptin(!!args.params.fedcm);
          document.querySelectorAll('.rp-name').forEach(el => {
            el.textContent = new URL(origin).hostname;
          });
          init();
        }
      });
    } catch (e) {
      // Thrown when this window has NO OPENER (e.g. a browser converted the
      // popup into a detached tab, or the page was opened directly). The RP's
      // request can never arrive, so don't sit on "Loading..." forever.
      winchanBroken = true;
      console.log('WinChan not available:', e.message || e);
    }
  }

  // Fail loudly instead of hanging: if no sign-in request has arrived shortly
  // after load (no ?origin= params and no WinChan message — opener severed,
  // popup turned into a tab, or a stale/refreshed dialog window), tell the
  // user what to do rather than spin forever.
  setTimeout(function () {
    if (state.origin) return; // a request arrived — normal operation
    if (screens.error.classList.contains('active')) return; // a specific error is already showing
    const hint = winchanBroken || !window.opener
      ? 'This sign-in window lost its connection to the site that opened it ' +
        '(some browsers, e.g. Arc, detach popups into tabs). Close this ' +
        'window, go back to the site, and click sign in again — and if it ' +
        'keeps happening, allow popups for the site.'
      : 'The site that opened this window never sent a sign-in request. ' +
        'Close this window and click sign in again.';
    showError(hint);
  }, 3000);
})();
