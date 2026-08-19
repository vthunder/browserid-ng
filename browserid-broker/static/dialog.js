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
    agents: [],       // agent identities (subset of emails) — collapsed section in the picker
    publicNames: {},  // agent identity -> public display name (shown in the picker + success)
    newEmail: null,  // Email being added to account
    pendingAddressInfo: null,  // Stored addressInfo for transition flows
    acceptedFallbacks: null,   // RP's accepted fallback IdPs (spec §8.1); null = default {this broker}
    brokerDomain: null,        // this broker's own issuer domain (from session_context)
    sboSign: false,  // RP requested the SBO typed-signing capability
    pendingPresentation: null,  // presentation held while showing the SBO consent screen
    provisionEmail: null,  // RP asked to provision/sign in a SPECIFIC identity (skip the chooser)
    loginHint: null,  // caller pre-filled the email (e.g. /account) → skip the email screen
    pendingPrimary: null,  // {email, info, keys} while waiting on tap-to-continue
    pendingClaim: null,    // {email, info} while waiting on claim tap-to-continue
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
    setPassword: '/wsapi/set_password',
    addressInfo: '/wsapi/address_info',
    stageEmail: '/wsapi/stage_email',
    completeEmailAddition: '/wsapi/complete_email_addition',
    completeHandleClaim: '/wsapi/complete_handle_claim'
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
    setPassword: document.getElementById('set-password-screen'),
    pickEmail: document.getElementById('pick-email-screen'),
    addEmail: document.getElementById('add-email-screen'),
    addEmailVerify: document.getElementById('add-email-verify-screen'),
    primaryTransition: document.getElementById('primary-transition-screen'),
    primaryAuthContinue: document.getElementById('primary-auth-continue-screen'),
    claimContinue: document.getElementById('claim-continue-screen'),
    managedConsent: document.getElementById('managed-consent-screen'),
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
      if (content) {
        // On the pick screen the checkbox sits between the Sign in button and
        // the bottom links row; elsewhere it goes at the end of the card.
        const links = content.querySelector('.links-split');
        if (links) links.parentNode.insertBefore(row, links);
        else content.appendChild(row);
        row.style.display = '';
      }
    } else {
      row.style.display = 'none';
    }
  }

  // "Signed in!" — or "Signed in as Claude" when an agent identity was used.
  function setSuccessHeading() {
    const h = document.getElementById('success-heading');
    if (!h) return;
    const email = state.email;
    if (email && (state.agents || []).includes(email)) {
      const name = state.publicNames[email] || email.slice(0, email.indexOf('@'));
      h.textContent = 'Signed in as ' + name;
    } else {
      h.textContent = 'Signed in!';
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
    if (screenId === 'success') setSuccessHeading();
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

  // Same-origin channel used to hand a device-authorization result from a
  // resumed /dialog/dialog.html?resume=device_auth page back to the dialog
  // window that started the flow (see primaryPopupFlow / handoffResume).
  const RESUME_CHANNEL = 'browserid:device_auth_resume';
  const RESUME_PATH = '/dialog/dialog.html?resume=device_auth';

  // Handle-identity claims (browserid-ng-xcy6) use a parallel pair: the
  // bridge's claim page hands back an ATTESTATION (no keys, no certs), so
  // the machinery is a simplified sibling of the device_auth one.
  const CLAIM_RESUME_CHANNEL = 'browserid:handle_claim_resume';
  const CLAIM_RESUME_PATH = '/dialog/dialog.html?resume=handle_claim';

  // OIDC (Google) claims (browserid-ng-qer8) reuse the same navigate-out/
  // resume shape, but the broker's /oidc/callback has already verified and
  // attached the identity server-side by the time the resume page loads — so
  // only an ok-or-error status crosses back, never an attestation.
  const OIDC_RESUME_CHANNEL = 'browserid:oidc_claim_resume';

  // The public key a device cert certifies, or null if the cert doesn't
  // declare one in a shape we can read. The claim is advisory (DNSSEC is the
  // trust root), so absence is normal for some IdPs.
  function certPublicKey(jws) {
    const c = decodeJws(jws);
    const pk = c && c['public-key'];
    return (pk && (pk.publicKey || pk.x)) || null;
  }

  // STRICT pairing, for the same-origin handoff: this cert must demonstrably
  // certify `pubX`. Fails closed on an unreadable key, because the handoff has
  // no other discriminator — accepting a cert we can't pair would let a
  // broadcast resolve EVERY dialog window waiting on this origin, and each
  // would then persist a cert that does not match its own key: a broken login
  // cached until the cert expires. Our device-model IdPs all publish the
  // claim, so an IdP that doesn't simply never gets the handoff route (it
  // keeps the postMessage one, which needs no pairing).
  function certKeyMatchesStrict(jws, pubX) {
    const x = certPublicKey(jws);
    return !!x && !!pubX && x === pubX;
  }

  // LENIENT pairing, for discarding a stale pending record: only a cert that
  // demonstrably certifies a DIFFERENT key proves the record is not ours. An
  // unreadable key must pass here — the pending record is the only way a
  // redirect-mode sign-in can finish, and rejecting it would strand every IdP
  // that omits the advisory claim.
  function certKeyConflicts(jws, pubX) {
    const x = certPublicKey(jws);
    return !!x && !!pubX && x !== pubX;
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

  // Managed-identity disclosure (spec §4.7 UA duty) as an in-dialog consent
  // screen. NOT native confirm(): browsers block confirm() in popup/iframe
  // contexts and silently return false, which made every managed login fail
  // as "declined" without the user ever seeing a prompt.
  let managedConsentPending = null;
  function managedDisclosure(issuer, email) {
    return new Promise((resolve, reject) => {
      managedConsentPending = { resolve, reject };
      const e = screens.managedConsent.querySelector('.email-display');
      if (e) e.textContent = email;
      const i = screens.managedConsent.querySelector('.managed-issuer');
      if (i) i.textContent = issuer;
      showScreen('managedConsent');
    });
  }

  async function storeDevicePair(issuer, email, keys, certs) {
    // BEFORE storing certs marked `managed: true`, tell the user what that
    // means — once per identity, re-shown if the marker (re)appears after an
    // unmanaged period.
    const dc = decodeJws(certs.device_cert);
    if (dc && dc.managed === true) {
      const ackKey = 'browserid:managed-ack:' + email;
      let acked = null;
      try { acked = localStorage.getItem(ackKey); } catch (e) { }
      if (!acked) {
        await managedDisclosure(issuer, email);
        try { localStorage.setItem(ackKey, String(Date.now())); } catch (e) { }
      }
    }
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
    const accessRequestClaims = {
      typ: 'browserid-access-request-v1',
      iat: nowS(),
      exp: nowS() + 600,
      jti: rndHex(),
      domain: issuer,
      identity: email,
      holder: holder,
      'access-key': { algorithm: 'Ed25519', publicKey: access.publicKeyX }
    };
    // Managed identities ONLY (spec §4.2/§4.7): a marked device cert may name
    // the audience so the IdP can scope the cert (per-audience posture).
    // Unmanaged mints MUST stay audience-free — the mint is RP-blind for
    // consumers, enforced here, by the user's own agent.
    const deviceClaims = decodeJws(pair.device.cert);
    if (deviceClaims && deviceClaims.managed === true) {
      accessRequestClaims.audience = audience;
    }
    const accessRequest = await signJws(pair.device.privateKey, accessRequestClaims);
    const minted = await postJson(mintUrl, {
      device_cert: pair.device.cert,
      access_request: accessRequest
    });
    if (!minted.access_cert) throw new Error(minted.reason || 'mint failed');
    // Mismatch rule (spec §4.7): an issuer constraining an UNMARKED identity
    // is inconsistent — surface it; the UA treats the identity as managed.
    if (minted.access_cert && (!deviceClaims || deviceClaims.managed !== true)) {
      const mc = decodeJws(minted.access_cert);
      if (mc && mc.constraints) {
        console.warn('browserid: issuer stamped constraints on an unmarked identity (' +
          email + ' @ ' + issuer + ') — treating as managed');
        try { localStorage.removeItem('browserid:managed-ack:' + email); } catch (e) { }
      }
    }

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
      grantor: email,
      grantee: email,
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

    // Self-healing registry (fire-and-forget): re-record this device's config
    // cert so the account view converges to reality on EVERY login — a row
    // removed or swept server-side while the device kept valid certs comes
    // back on next use. Server-side the record is gated cryptographically
    // (signature + fail-closed status), so this can't resurrect a revoked cert.
    try {
      apiCall('/wsapi/record_device_cert', 'POST', { config_cert: pair.config.cert })
        .catch(() => { /* best-effort */ });
    } catch (e) { /* best-effort */ }

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

  // Signed-in check for the set-password shortcut: the current session must
  // own the selected address, else /wsapi/set_password would set a password on
  // the WRONG account (it acts on the session's account, not the email's).
  async function sessionOwnsEmail(email) {
    try {
      const ctx = await apiCall(API.sessionContext);
      if (!ctx.authenticated) return false;
      const resp = await apiCall(API.listEmails);
      const want = email.toLowerCase();
      return (resp.emails || []).some(e => e.toLowerCase() === want);
    } catch (e) {
      return false;
    }
  }

  /// A password-less account signing in with a broker-verified email. When a
  /// session already owns the address it proves control by itself — set the
  /// password in-session, no mailed code (browserid-ng-iudv). Cold (no
  /// session): the emailed reset code, then choose a password.
  async function handleNoPasswordTransition(email) {
    state.email = email;
    document.querySelectorAll('.email-display').forEach(el => el.textContent = email);
    if (await sessionOwnsEmail(email)) {
      showScreen('setPassword');
      return;
    }
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
        const alt = (state.acceptedFallbacks || []).filter(f => f && f !== dom);
        showError('This site doesn’t accept email sign-in via ' + dom + '.' +
          (alt.length ? ' It accepts: ' + alt.join(', ') + '.'
                      : ' Use an email whose domain is its own identity provider.'));
        return;
      }

      // Handle-identity domain: re-proof runs at the bridge, never by
      // password reset or mailed code (browserid-ng-xcy6).
      if (addressInfo.proof === 'atproto' &&
          (addressInfo.state === 'unknown' ||
           addressInfo.state === 'transition_no_password' ||
           addressInfo.state === 'unverified')) {
        return await handleAtprotoClaim(email, addressInfo);
      }

      // Google-hosted mailbox (browserid-ng-qer8): prove it by signing in
      // with Google instead of a mailed code. A 'known' identity with a
      // password still gets the password screen.
      if (addressInfo.proof === 'oidc' &&
          (addressInfo.state === 'unknown' ||
           addressInfo.state === 'transition_no_password' ||
           addressInfo.state === 'unverified')) {
        return await handleOidcClaim(email, addressInfo);
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
        // Marked for re-verification (kgb9: a password reset unverifies the
        // account's sibling SMTP addresses): fresh SMTP challenge, completed
        // through the add-email flow (verify → mint under the chokepoint).
        state.email = email;
        document.querySelectorAll('.email-display').forEach(el => el.textContent = email);
        const ctx = await apiCall(API.sessionContext);
        if (!ctx.authenticated) {
          // Cold: the account password first; the password form re-enters
          // here and the staging below runs on the fresh session.
          state.reverifyAfterAuth = true;
          showScreen('password');
          return;
        }
        await apiCall(API.stageEmail, 'POST', { email });
        state.newEmail = email;
        showScreen('addEmailVerify');
        return;
      }

      // Secondary, known, verified — complete via the session (issue if needed).
      if (addressInfo.state === 'known') {
        // Bridge-vouched (E2) with no cached device pair: issuance requires a
        // live bridge proof (pr3a), so run the bridge up front instead of
        // burning a refused /device/issue. The bridge may reuse a live
        // Google/Bluesky session silently — that's its call.
        if (addressInfo.proof === 'oidc' || addressInfo.proof === 'atproto') {
          const issuer = state.brokerDomain || location.hostname;
          if (!(await storedDevicePair(issuer, email))) {
            return addressInfo.proof === 'oidc'
              ? await handleOidcClaim(email, addressInfo)
              : await handleAtprotoClaim(email, addressInfo);
          }
        }
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
      let chan = null;
      // Set when the IdP page tells us it is about to run a top-level OAuth
      // redirect for OUR device key: a subsequent `popup.closed` is then COOP
      // severing the handle, not the user cancelling.
      let expectingHandoff = false;

      // Stop waiting on the IdP popup, but KEEP the resume channel: on the
      // handoff path that channel is our only way back to the popup, and the
      // holder re-issue still needs it after this promise settles.
      function timersOff() {
        clearTimeout(timeoutId);
        clearInterval(pollId);
        window.removeEventListener('message', onMessage);
      }
      function cleanup() {
        timersOff();
        if (chan) { try { chan.close(); } catch (e) { /* already closed */ } chan = null; }
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
        if (d.type === 'browserid:device_auth_pending') {
          if (d.device_pubkey && d.device_pubkey === keys.device.publicKeyX) expectingHandoff = true;
          return;
        }
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

      // Second handback route, for a primary whose device-authorization page
      // must run a top-level OAuth redirect (atproto's bsky-handle IdP). That
      // navigation takes the popup cross-origin and the PDS's COOP severs its
      // `window.opener`, so it can never postMessage us. It instead sends the
      // popup it still owns to OUR /dialog/dialog.html?resume=device_auth with
      // the certs in the fragment. That page is same-origin with us, and THIS
      // window is still the one holding the non-extractable keys and the RP
      // relationship — so it just hands the result over and closes, and we
      // resolve on exactly the path the postMessage handback takes.
      //
      // That popup is now OUR resume page, which means hold mode still has a
      // window to talk to — just a different one. So this path ALSO resolves
      // with `reissue`/`done`: `reissue` tells the resume page to navigate
      // ITSELF back to the provider with the holder pinned. A same-tab
      // navigation of a window we own needs no user gesture, so unlike
      // re-opening a popup it cannot be blocked (browserid-ng-i8a2).
      let lastNonce = null;        // the resume page we last acknowledged
      let awaitingReissue = null;  // set while that page is off re-issuing
      function ackResume(nonce) {
        // `hold` asks the page to stay put until we say done — we don't know
        // yet whether a re-issue is needed (the broker join hasn't run).
        try { chan.postMessage({ type: 'browserid:device_auth_resume_ack', nonce, hold: true }); } catch (e) { /* closed */ }
      }
      function resumeReissue(newHolder) {
        return new Promise((res, rej) => {
          if (!chan || !lastNonce) { rej(new Error('the provider window is gone')); return; }
          if (!deviceAuthUrl) { rej(new Error('no device-authorization URL')); return; }
          // Same shape as the redirect lane's hop: the provider posts the certs
          // back to our resume page, which hands them over on this channel.
          const url = deviceAuthUrl +
            '#email=' + encodeURIComponent(email) +
            '&device_pubkey=' + encodeURIComponent(keys.device.publicKeyX) +
            '&config_pubkey=' + encodeURIComponent(keys.config.publicKeyX) +
            '&holder=' + encodeURIComponent(newHolder) +
            '&return_origin=' + encodeURIComponent(window.location.origin) +
            '&return_url=' + encodeURIComponent(window.location.origin + RESUME_PATH);
          const timer = setTimeout(() => {
            awaitingReissue = null;
            rej(new Error('holder re-issue timed out'));
          }, 45 * 1000);
          awaitingReissue = { res, rej, timer };
          try {
            chan.postMessage({ type: 'browserid:device_auth_reissue', nonce: lastNonce, url });
          } catch (e) {
            clearTimeout(timer);
            awaitingReissue = null;
            rej(new Error('the provider window is gone'));
          }
        });
      }
      function resumeRelease() {
        if (!chan) return;
        try { chan.postMessage({ type: 'browserid:device_auth_done', nonce: lastNonce }); } catch (e) { /* closed */ }
        try { chan.close(); } catch (e) { /* already closed */ }
        chan = null;
      }
      try { chan = new BroadcastChannel(RESUME_CHANNEL); } catch (e) { /* unsupported: postMessage only */ }
      if (chan) {
        chan.onmessage = (ev) => {
          const m = ev.data;
          if (!m || typeof m !== 'object' || m.type !== 'browserid:device_auth_resume') return;
          const d = m.payload;
          if (!d || typeof d !== 'object') return;
          // EVERY branch must pair before it acts. A broadcast reaches every
          // dialog window on this origin, so an unpaired one would resolve or
          // tear down a sign-in that has nothing to do with it — no attacker
          // needed, just two sign-ins in flight in one browser.
          if (d.type === 'browserid:device_certs') {
            if (!d.device_cert || !d.config_cert) return;
            if (!certKeyMatchesStrict(d.device_cert, keys.device.publicKeyX)) return;
            lastNonce = m.nonce;
            ackResume(m.nonce);
            const got = { device_cert: d.device_cert, config_cert: d.config_cert };
            // Second handback: the re-issue we asked for, under the new holder.
            if (awaitingReissue) {
              const w = awaitingReissue;
              awaitingReissue = null;
              clearTimeout(w.timer);
              w.res(got);
              return;
            }
            timersOff();
            resolve(Object.assign(got, { reissue: resumeReissue, done: resumeRelease }));
          } else if (d.type === 'browserid:device_error') {
            // A failure carries no cert, so the IdP echoes the device pubkey
            // it was given. No pubkey, or someone else's, is not our failure —
            // stay pending and let our own timeout speak.
            if (!d.device_pubkey || d.device_pubkey !== keys.device.publicKeyX) return;
            lastNonce = m.nonce;
            const err = new Error(d.reason || 'identity provider refused');
            if (awaitingReissue) {
              // The re-issue failed; the ORIGINAL certs are still good, so let
              // reconciliation fall back rather than failing the sign-in.
              const w = awaitingReissue;
              awaitingReissue = null;
              clearTimeout(w.timer);
              ackResume(m.nonce);
              w.rej(err);
              return;
            }
            timersOff();
            resumeRelease();
            reject(err);
          }
        };
      }

      timeoutId = setTimeout(() => {
        cleanup();
        try { popup.close(); } catch (e) { /* already closed */ }
        reject(new Error('sign-in with your email provider timed out'));
      }, TIMEOUT_MS);

      pollId = setInterval(() => {
        if (!popup.closed) return;
        clearInterval(pollId);
        pollId = null;
        if (expectingHandoff) return; // COOP made an OAuth-redirecting popup look closed; the handoff is coming
        // The close may have raced an announcement still in flight.
        setTimeout(() => {
          if (expectingHandoff) return;
          cleanup();
          reject(new Error('the sign-in window was closed'));
        }, 800);
      }, 500);
    });
  }

  // Cold-login browser-holder reconciliation (browserid-ng-rrve, i8a2). At cold
  // primary login there was no broker session, so the IdP self-assigned a
  // holder under a fresh prefix. The join either ADOPTED that prefix as the
  // account's `browsers` namespace (first-ever device — nothing to fix) or
  // could not (another device already owns `browsers`), in which case the certs
  // sit in an orphan namespace AND the join scheduled a move into `browsers`.
  // Now that the session exists, re-sign the SAME keys under the right holder,
  // in order of preference:
  //   1. the still-open hold-mode IdP popup, when the IdP supports it;
  //   2. the resume popup navigating ITSELF back to the provider (the OAuth
  //      case — no window.open, so nothing for a popup blocker to refuse);
  //   3. RE-OPENING the authorize popup with the holder pinned — plain
  //      passthrough every device-model IdP implements, but gesture-less and
  //      therefore blockable, which is why it is last.
  // (1) and (2) both arrive as `certs.reissue`. Then replace the stored pair
  // and re-join so the broker records the corrected cert. Best-effort: any
  // failure keeps the initial (working, if miscategorized) pair — the server's
  // pending move survives, so the next sign-in repairs it.
  async function reconcileBrowserHolder(email, domain, keys, certs, pair, mintUrl, deviceAuthUrl) {
    const release = () => { try { if (certs.done) certs.done(); } catch (e) { /* gone */ } };
    try {
      const issued = certHolder(pair.device.cert);
      const prefixOf = (h) => (h && h.includes('.') ? h.slice(0, h.indexOf('.')) : null);
      // The server's explicit assignment wins. Re-issuing under any OTHER
      // holder would leave that pending move — and its orphan row — dangling,
      // so the browser would still show up uncategorized.
      let target = await pendingHolderMove(issued);
      if (!target) {
        const canonical = await browserHolder(); // session exists after the join
        if (!prefixOf(canonical) || !prefixOf(issued) || prefixOf(canonical) === prefixOf(issued)) {
          release();
          return pair;
        }
        target = canonical;
      }
      let fresh;
      try {
        if (!certs.reissue) throw new Error('no window left to re-issue through');
        fresh = await certs.reissue(target);
      } catch (holdErr) {
        // Last resort: a fresh authorize popup with the holder pinned. The user
        // just finished interacting with this flow, so an immediate re-open is
        // often allowed; when it is blocked we fall through to the catch below
        // and the server-side move repairs things on the next sign-in.
        if (!deviceAuthUrl) throw holdErr;
        // Let go of the window we were talking to first, so its channel
        // listener can't race the fresh flow's on the same certs.
        release();
        fresh = await primaryPopupFlow(email, deviceAuthUrl, keys, target);
      }
      const newPair = await finishPrimaryCerts(email, keys, fresh);
      await rejoinBroker(email, newPair, domain, mintUrl);
      await followHolderCache(certHolder(newPair.device.cert), prefixOf(issued));
      release();
      return newPair;
    } catch (e) {
      console.warn('browser-holder reconciliation failed (non-fatal):', e.message || e);
      release();
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

  // Re-present to the broker so it records the CURRENT cert for this holder
  // (the registry upserts on pubkey), which is what completes a pending move
  // server-side and drops the old holder's rows. Best-effort: the sign-in
  // itself already succeeded.
  async function rejoinBroker(email, pair, issuer, mintUrl) {
    try {
      const p = await buildPresentation(
        pair, issuer, mintUrl, email, window.location.origin, /* noRegister */ true);
      await apiCall('/wsapi/auth_with_presentation', 'POST', { presentation: p, ephemeral: false });
    } catch (e) {
      console.warn('holder repair re-join failed (non-fatal):', e.message || e);
    }
  }

  // Point this browser's holder cache at `holder` under the account's canonical
  // browsers prefix, and forget the orphan prefix a cold login may have cached.
  async function followHolderCache(holder, dropPrefix) {
    if (dropPrefix) {
      try { localStorage.removeItem('browserid:holder:' + dropPrefix); } catch (e) { /* best-effort */ }
    }
    if (!holder) return;
    try {
      const r = await apiCall(API.browserHolder, 'GET');
      if (r && r.prefix) localStorage.setItem('browserid:holder:' + r.prefix, holder);
    } catch (e) { /* best-effort */ }
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
        const moved = await storedDevicePair(issuer, email);
        await rejoinBroker(email, moved, issuer, mintUrl);
      }
      // This browser's holder cache follows the move.
      await followHolderCache(target, null);
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
      // Unconditional: reconciliation itself decides whether anything needs
      // fixing, and it now has a repair route even when the IdP window is gone
      // (the OAuth-redirect case, which is where cold logins actually land).
      pair = await reconcileBrowserHolder(email, domain, keys, certs, pair, mintUrl, addressInfo.device_auth);
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
      // Kept so the resume leg can hop back here to repair the holder without
      // a popup (browserid-ng-i8a2).
      deviceAuth: info.device_auth,
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
    const resume = window.location.origin + RESUME_PATH;
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

  // Hand a device-authorization result to the dialog window still waiting on
  // it in primaryPopupFlow (same origin, same browser — BroadcastChannel).
  // Resolves true once that window acknowledges, false if nobody claims it
  // within the grace window (then the caller reports lost state as before).
  // The certs never leave this origin: BroadcastChannel is same-origin by
  // construction, and they arrived in the fragment, never the query.
  function handoffResume(certs, errReason, errPubX) {
    return new Promise((resolve) => {
      let chan = null;
      try { chan = new BroadcastChannel(RESUME_CHANNEL); } catch (e) { return resolve(false); }
      const payload = errReason
        ? { type: 'browserid:device_error', reason: errReason, device_pubkey: errPubX || null }
        : (certs.device_cert && certs.config_cert
          ? { type: 'browserid:device_certs', device_cert: certs.device_cert, config_cert: certs.config_cert }
          : null);
      if (!payload) {
        try { chan.close(); } catch (e) { /* ignore */ }
        return resolve(false);
      }
      const nonce = Math.random().toString(36).slice(2) + Date.now().toString(36);
      let settled = false;
      let retryId = null;
      let giveUpId = null;
      let holdId = null;
      // This window was opened by script (primaryPopupFlow), so it may close
      // itself. If a browser refuses, say something honest instead of sitting
      // on a spinner — the sign-in itself already completed next door.
      function closeSelf() {
        try { window.close(); } catch (e) { /* fall through */ }
        showScreen('loading', 'Signed in — you can close this window.');
      }
      function stopChannel() {
        clearTimeout(holdId);
        try { chan.close(); } catch (e) { /* ignore */ }
      }
      function finish(ok) {
        if (settled) return;
        settled = true;
        clearInterval(retryId);
        clearTimeout(giveUpId);
        resolve(ok);
      }
      chan.onmessage = (ev) => {
        const m = ev.data;
        if (!m || typeof m !== 'object' || m.nonce !== nonce) return;
        if (m.type === 'browserid:device_auth_resume_ack') {
          finish(true);
          clearInterval(retryId);
          if (!m.hold) { stopChannel(); closeSelf(); return; }
          // The dialog may still send us back to the provider to re-issue under
          // the account's real holder — stay put until it says done. Bounded, so
          // a dialog that dies mid-flow doesn't strand this window forever.
          showScreen('loading', 'Finishing sign-in...');
          clearTimeout(holdId);
          holdId = setTimeout(() => { stopChannel(); closeSelf(); }, 60 * 1000);
        } else if (m.type === 'browserid:device_auth_reissue' && m.url) {
          // The holder repair: hop THIS window back to the provider. Navigating
          // a window we already own needs no user gesture — that is the whole
          // point, since the popup-blocker case is exactly what stranded these
          // sign-ins before. The channel is same-origin by construction; we
          // still refuse anything but a secure provider URL.
          let ok = false;
          try {
            const u = new URL(m.url, window.location.href);
            ok = u.protocol === 'https:' || u.hostname === 'localhost' || u.hostname === '127.0.0.1';
          } catch (e) { /* refuse */ }
          if (!ok) return;
          finish(true);
          stopChannel();
          window.location.replace(m.url);
        } else if (m.type === 'browserid:device_auth_done') {
          finish(true);
          stopChannel();
          closeSelf();
        }
      };
      const send = () => {
        try { chan.postMessage({ type: 'browserid:device_auth_resume', nonce, payload }); } catch (e) { /* closed */ }
      };
      send();
      retryId = setInterval(send, 250);
      giveUpId = setTimeout(() => { stopChannel(); finish(false); }, 2500);
    });
  }

  // Redirect-lane holder repair: the same second hop the popup lane performs,
  // minus the window juggling — THIS tab goes back to the provider with the
  // account's holder pinned and returns here. The provider session is warm, so
  // it auto-issues and bounces straight back. Returns true when it is
  // navigating away (the caller must stop). Best-effort: on any doubt we keep
  // the working pair and let the server-side move repair the next sign-in.
  async function reissueViaRedirectHop(pending, pair) {
    if (pending.holderHop) return false;   // one repair attempt per sign-in
    if (!pending.deviceAuth) return false;
    let target = null;
    try { target = await pendingHolderMove(certHolder(pair.device.cert)); } catch (e) { return false; }
    if (!target) return false;
    try {
      await Keystore.putPending(Object.assign({}, pending, { holderHop: true }));
    } catch (e) {
      return false;
    }
    window.location.assign(
      pending.deviceAuth +
      '#email=' + encodeURIComponent(pending.email) +
      '&device_pubkey=' + encodeURIComponent(pending.devicePubX) +
      '&config_pubkey=' + encodeURIComponent(pending.configPubX) +
      '&holder=' + encodeURIComponent(target) +
      '&return_origin=' + encodeURIComponent(window.location.origin) +
      '&return_url=' + encodeURIComponent(window.location.origin + RESUME_PATH)
    );
    return true;
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
    const fragCerts = { device_cert: frag.get('device_cert'), config_cert: frag.get('config_cert') };
    // A parked record only belongs to THIS handback if the returned cert
    // certifies the key it parked; otherwise it is the leftover of an
    // abandoned redirect hop and using it would mint an unusable pair.
    if (pending && pending.kind === 'device_auth' && fragCerts.device_cert &&
        certKeyConflicts(fragCerts.device_cert, pending.devicePubX)) {
      pending = null;
    }
    if (!pending || pending.kind !== 'device_auth' || !pending.dialog) {
      // Popup mode with an OAuth-redirecting primary: nothing was ever parked,
      // because the dialog window that opened this popup is still open and
      // still holds the keys AND the RP response path. Hand the result to it
      // and get out of the way — it finishes exactly as on the postMessage
      // path. Only when nobody claims the result is the state really lost.
      if (await handoffResume(fragCerts, frag.get('device_error'), frag.get('device_pubkey'))) return;
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
    const certs = fragCerts;
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
      if (pending.holderHop) {
        // THIS leg is the repair. Force the re-join (rather than relying on
        // ensureBrokerSession, which no-ops once the email is on the account)
        // so the broker records the corrected cert, which completes the move
        // and drops the orphan's rows.
        await rejoinBroker(pending.email, pair, pending.domain, pending.mintUrl);
        await followHolderCache(certHolder(pair.device.cert), pending.orphanPrefix);
      } else {
        await ensureBrokerSession(pending.email, pair, pending.domain, pending.mintUrl);
        const issued = certHolder(pair.device.cert);
        pending.orphanPrefix = issued && issued.includes('.')
          ? issued.slice(0, issued.indexOf('.')) : null;
        if (await reissueViaRedirectHop(pending, pair)) return; // navigating away
      }
      await finishSignIn(pending.email, pair, pending.domain, pending.mintUrl);
    } catch (e) {
      showError(e.message || String(e));
    }
  }

  // --- handle-identity claims (browserid-ng-xcy6) --------------------------
  //
  // A handle identity (`me@dan.bsky.social`) is an ordinary broker-issued
  // secondary identity whose OWNERSHIP proof runs at the bsky bridge instead
  // of an email loop: one navigation out to the bridge's claim page, one
  // return carrying a short-lived signed attestation, which we redeem at the
  // broker. From there completeSignIn runs unchanged.

  // Popup lane. Resolves with the attestation string.
  function claimPopupFlow(email, claimUrl) {
    return new Promise((resolve, reject) => {
      const claimOrigin = new URL(claimUrl).origin;
      const url = claimUrl +
        '#email=' + encodeURIComponent(email) +
        '&return_origin=' + encodeURIComponent(window.location.origin);
      const popup = window.open(url, 'browserid_handle_claim', 'width=600,height=700');
      if (!popup) {
        reject({ popupBlocked: true });
        return;
      }
      showScreen('loading', 'Verifying your Bluesky handle...');

      const TIMEOUT_MS = 3 * 60 * 1000;
      let timeoutId = null;
      let pollId = null;
      let chan = null;
      // Set when the claim page announces its OAuth navigation: a subsequent
      // `popup.closed` is COOP severing the handle, not the user cancelling.
      let expectingHandoff = false;
      let settled = false;

      function cleanup() {
        clearTimeout(timeoutId);
        clearInterval(pollId);
        window.removeEventListener('message', onMessage);
        if (chan) { try { chan.close(); } catch (e) { /* closed */ } chan = null; }
      }
      function finish(err, attestation) {
        if (settled) return;
        settled = true;
        cleanup();
        if (err) reject(err); else resolve(attestation);
      }

      function onMessage(ev) {
        if (ev.origin !== claimOrigin) return;
        const d = ev.data || {};
        if (d.email && String(d.email).toLowerCase() !== email.toLowerCase()) return;
        if (d.type === 'browserid:handle_claim_pending') { expectingHandoff = true; return; }
        if (d.type === 'browserid:handle_attestation') finish(null, d.attestation);
        else if (d.type === 'browserid:handle_error') {
          finish(new Error(d.reason || 'handle verification failed'));
        }
      }
      window.addEventListener('message', onMessage);

      // After the OAuth hop the popup's opener is severed; the result comes
      // back through our resume page on this same-origin channel instead.
      try {
        chan = new BroadcastChannel(CLAIM_RESUME_CHANNEL);
        chan.onmessage = (ev) => {
          const m = ev.data || {};
          if (m.type !== 'browserid:handle_claim_result') return;
          if (String(m.email || '').toLowerCase() !== email.toLowerCase()) return;
          try { chan.postMessage({ type: 'browserid:handle_claim_ack', nonce: m.nonce }); } catch (e) { /* closed */ }
          if (m.attestation) finish(null, m.attestation);
          else finish(new Error(m.reason || 'handle verification failed'));
        };
      } catch (e) { /* unsupported: postMessage lane only */ }

      timeoutId = setTimeout(() => {
        try { popup.close(); } catch (e) { /* gone */ }
        finish(new Error('Timed out waiting for Bluesky verification'));
      }, TIMEOUT_MS);
      pollId = setInterval(() => {
        if (popup.closed && !expectingHandoff) {
          finish(new Error('The verification window was closed'));
        }
      }, 500);
    });
  }

  // Same-tab hop (redirect mode): park the dialog's state, navigate to the
  // claim page with a return_url back to our resume entry point. Unlike the
  // primary hop there are no keys to park — the attestation is the only
  // thing that crosses back.
  async function claimRedirectHop(email, info) {
    await Keystore.putPending({
      kind: 'handle_claim',
      email,
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
    const resume = window.location.origin + CLAIM_RESUME_PATH;
    window.location.assign(
      info.claim +
      '#email=' + encodeURIComponent(email) +
      '&return_origin=' + encodeURIComponent(window.location.origin) +
      '&return_url=' + encodeURIComponent(resume)
    );
  }

  // Redeem the attestation at the broker. apiCall attaches the session CSRF
  // automatically when one exists (the add-to-signed-in-account case); a
  // cold claim has no session and the broker requires none.
  async function redeemHandleAttestation(email, attestation) {
    return await apiCall(API.completeHandleClaim, 'POST', { email, attestation });
  }

  async function handleAtprotoClaim(email, info) {
    if (!info.claim) {
      showError('This identity needs Bluesky verification, but the service for it is unavailable.');
      return;
    }
    if (state.redirect) return await claimRedirectHop(email, info);
    let attestation;
    try {
      attestation = await claimPopupFlow(email, info.claim);
    } catch (e) {
      if (e && e.popupBlocked) {
        // Blocked — re-run from a fresh tap gesture (mobile).
        state.pendingClaim = { kind: 'atproto', email, info };
        document.querySelectorAll('.claim-handle').forEach(el => {
          el.textContent = email.split('@')[1];
        });
        document.querySelectorAll('.claim-provider').forEach(el => { el.textContent = 'Bluesky'; });
        showScreen('claimContinue');
        return;
      }
      showError('Bluesky verification failed: ' + (e.message || e));
      return;
    }
    try {
      showScreen('loading', 'Finishing sign-in...');
      await redeemHandleAttestation(email, attestation);
      await completeSignIn(email, true);
    } catch (e) {
      showError('Could not complete sign-in: ' + (e.message || e));
    }
  }

  // Hand a claim result to the dialog window still waiting in
  // claimPopupFlow (same origin — BroadcastChannel). Resolves true once
  // that window acknowledges, false if nobody claims it.
  function handoffClaimResume(email, attestation, errReason) {
    return new Promise((resolve) => {
      let chan = null;
      try { chan = new BroadcastChannel(CLAIM_RESUME_CHANNEL); } catch (e) { return resolve(false); }
      if (!email || (!attestation && !errReason)) {
        try { chan.close(); } catch (e) { /* ignore */ }
        return resolve(false);
      }
      const nonce = Math.random().toString(36).slice(2) + Date.now().toString(36);
      const payload = {
        type: 'browserid:handle_claim_result',
        email,
        attestation: attestation || null,
        reason: errReason || null,
        nonce
      };
      let settled = false;
      let retryId = null;
      chan.onmessage = (ev) => {
        const m = ev.data || {};
        if (m.type !== 'browserid:handle_claim_ack' || m.nonce !== nonce || settled) return;
        settled = true;
        clearInterval(retryId);
        try { chan.close(); } catch (e) { /* ignore */ }
        // This window was opened by script; if the browser refuses to close
        // it, say something honest — the sign-in completed next door.
        window.close();
        showScreen('loading', 'Signed in — you can close this window.');
        resolve(true);
      };
      try { chan.postMessage(payload); } catch (e) { /* ignore */ }
      retryId = setInterval(() => { try { chan.postMessage(payload); } catch (e) { /* ignore */ } }, 300);
      setTimeout(() => {
        if (settled) return;
        clearInterval(retryId);
        try { chan.close(); } catch (e) { /* ignore */ }
        resolve(false);
      }, 3000);
    });
  }

  // Entry point for /dialog/dialog.html?resume=handle_claim — the return leg
  // of both the redirect lane and the COOP-severed popup lane.
  async function resumeHandleClaim() {
    showScreen('loading', 'Finishing sign-in...');
    const frag = new URLSearchParams(window.location.hash.replace(/^#/, ''));
    history.replaceState(null, '', window.location.pathname); // attestation out of the URL bar
    const email = frag.get('email') || '';
    const attestation = frag.get('handle_attestation');
    const errReason = frag.get('handle_error');

    let pending = null;
    try { pending = await Keystore.getPending(); } catch (e) { /* fall through */ }
    if (pending && pending.kind !== 'handle_claim') pending = null;
    if (pending) { try { await Keystore.clearPending(); } catch (e) { /* best-effort */ } }

    if (!pending || !pending.dialog) {
      // Popup lane: the dialog window that opened the claim popup is still
      // open and still holds the RP response path — hand the result over.
      if (await handoffClaimResume(email, attestation, errReason)) return;
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

    if (errReason) {
      showError('Bluesky verification failed: ' + errReason);
      return;
    }
    const claimed = pending.email || email;
    if (!attestation || !claimed) {
      showError('Bluesky verification returned nothing — try again.');
      return;
    }
    if (email && claimed.toLowerCase() !== email.toLowerCase()) {
      showError('Sign-in state did not match — try again.');
      return;
    }
    try {
      await redeemHandleAttestation(claimed, attestation);
      await completeSignIn(claimed, true);
    } catch (e) {
      showError(e.message || String(e));
    }
  }

  // --- OIDC (Google) claims (browserid-ng-qer8) -----------------------------
  //
  // A Google-hosted mailbox (gmail.com, or a Workspace domain whose MX is
  // Google) can be claimed by signing in with Google instead of a mailed
  // code. One navigation out to the broker's /oidc/claim (which 302s to
  // Google), one return to /dialog/dialog.html?resume=oidc_claim — by which
  // time the broker's /oidc/callback has verified the ID token and attached
  // the identity to a session, cookie included. "Redeem" therefore collapses
  // to completing sign-in on that session. The SMTP loop stays an
  // equal-strength fallback ceremony on the broker for the same domain.

  // Mirror the broker's Gmail normalization (dots/+tag collapse on consumer
  // domains) so the typed address recognizes the canonical one the callback
  // attached.
  function normalizeGoogleEmail(email) {
    const lower = String(email || '').toLowerCase();
    const at = lower.lastIndexOf('@');
    if (at < 0) return lower;
    let local = lower.slice(0, at);
    const domain = lower.slice(at + 1);
    if (domain === 'gmail.com' || domain === 'googlemail.com') {
      local = local.split('+')[0].replace(/\./g, '');
    }
    return local + '@' + domain;
  }

  function oidcEmailsMatch(a, b) {
    return normalizeGoogleEmail(a) === normalizeGoogleEmail(b);
  }

  function oidcClaimUrl(email, info) {
    return info.claim + '?email=' + encodeURIComponent(email);
  }

  // Popup lane. Resolves with the attached (broker-normalized) email.
  function oidcPopupFlow(email, info) {
    return new Promise((resolve, reject) => {
      const popup = window.open(oidcClaimUrl(email, info), 'browserid_oidc_claim', 'width=600,height=700');
      if (!popup) {
        reject({ popupBlocked: true });
        return;
      }
      showScreen('loading', 'Signing you in with Google...');

      const TIMEOUT_MS = 3 * 60 * 1000;
      let timeoutId = null;
      let chan = null;
      let settled = false;

      function cleanup() {
        clearTimeout(timeoutId);
        if (chan) { try { chan.close(); } catch (e) { /* closed */ } chan = null; }
      }
      function finish(err, attachedEmail) {
        if (settled) return;
        settled = true;
        cleanup();
        if (err) reject(err); else resolve(attachedEmail);
      }

      // The popup 302s straight to Google, whose COOP severs our window
      // handle — popup.closed cannot distinguish "user closed it" from
      // "still signing in", so there is no closed-poll here. The result
      // arrives on this same-origin channel from the resume page;
      // abandonment falls to the timeout.
      try {
        chan = new BroadcastChannel(OIDC_RESUME_CHANNEL);
        chan.onmessage = (ev) => {
          const m = ev.data || {};
          if (m.type !== 'browserid:oidc_claim_result') return;
          // An error may arrive without an email (the broker had no flow to
          // name it with); any waiting claim accepts those — concurrent OIDC
          // claims in one browser are not a real case.
          const anonymousError = !m.ok && !m.email;
          if (!anonymousError && !oidcEmailsMatch(email, m.email)) return;
          try { chan.postMessage({ type: 'browserid:oidc_claim_ack', nonce: m.nonce }); } catch (e) { /* closed */ }
          if (m.ok) finish(null, m.email);
          else finish(new Error(m.reason || 'Google sign-in failed'));
        };
      } catch (e) {
        // No BroadcastChannel: the popup result cannot reach us — use the
        // same-tab lane instead of hanging until the timeout.
        try { popup.close(); } catch (e2) { /* gone */ }
        reject({ popupBlocked: true });
        return;
      }

      timeoutId = setTimeout(() => {
        try { popup.close(); } catch (e) { /* gone */ }
        finish(new Error('Timed out waiting for Google sign-in'));
      }, TIMEOUT_MS);
    });
  }

  // Same-tab hop (redirect mode): park the dialog's state and navigate. The
  // broker's callback redirects to our resume entry point by itself — no
  // return_url crosses, and no keys are parked (the session cookie is the
  // only thing that comes back).
  async function oidcRedirectHop(email, info) {
    await Keystore.putPending({
      kind: 'oidc_claim',
      email,
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
    window.location.assign(oidcClaimUrl(email, info));
  }

  async function handleOidcClaim(email, info) {
    if (!info.claim) {
      showError('This identity needs Google sign-in, but it is unavailable right now.');
      return;
    }
    if (state.redirect) return await oidcRedirectHop(email, info);
    let attached;
    try {
      attached = await oidcPopupFlow(email, info);
    } catch (e) {
      if (e && e.popupBlocked) {
        // Blocked — re-run from a fresh tap gesture (mobile).
        state.pendingClaim = { kind: 'oidc', email, info };
        document.querySelectorAll('.claim-handle').forEach(el => { el.textContent = email; });
        document.querySelectorAll('.claim-provider').forEach(el => { el.textContent = 'Google'; });
        showScreen('claimContinue');
        return;
      }
      showError('Google sign-in failed: ' + (e.message || e));
      return;
    }
    try {
      showScreen('loading', 'Finishing sign-in...');
      await completeSignIn(attached, true);
    } catch (e) {
      showError('Could not complete sign-in: ' + (e.message || e));
    }
  }

  // Hand the claim outcome to the dialog window still waiting in
  // oidcPopupFlow (same origin — BroadcastChannel). Resolves true once that
  // window acknowledges, false if nobody claims it.
  function handoffOidcResume(email, ok, errReason) {
    return new Promise((resolve) => {
      let chan = null;
      try { chan = new BroadcastChannel(OIDC_RESUME_CHANNEL); } catch (e) { return resolve(false); }
      // A success with no email is useless to the dialog; an ERROR without
      // one (expired/replayed state — the broker had no flow to name) still
      // hands off, so the waiting window fails fast instead of timing out.
      if (!email && ok) {
        try { chan.close(); } catch (e) { /* ignore */ }
        return resolve(false);
      }
      const nonce = Math.random().toString(36).slice(2) + Date.now().toString(36);
      const payload = {
        type: 'browserid:oidc_claim_result',
        email,
        ok: !!ok,
        reason: errReason || null,
        nonce
      };
      let settled = false;
      let retryId = null;
      chan.onmessage = (ev) => {
        const m = ev.data || {};
        if (m.type !== 'browserid:oidc_claim_ack' || m.nonce !== nonce || settled) return;
        settled = true;
        clearInterval(retryId);
        try { chan.close(); } catch (e) { /* ignore */ }
        // This window was opened by script; if the browser refuses to close
        // it, say something honest — the sign-in completed next door.
        window.close();
        showScreen('loading', 'Signed in — you can close this window.');
        resolve(true);
      };
      try { chan.postMessage(payload); } catch (e) { /* ignore */ }
      retryId = setInterval(() => { try { chan.postMessage(payload); } catch (e) { /* ignore */ } }, 300);
      setTimeout(() => {
        if (settled) return;
        clearInterval(retryId);
        try { chan.close(); } catch (e) { /* ignore */ }
        resolve(false);
      }, 3000);
    });
  }

  // Entry point for /dialog/dialog.html?resume=oidc_claim — the return leg
  // of both lanes. The identity is already attached (or the attempt already
  // failed); the fragment only says which.
  async function resumeOidcClaim() {
    showScreen('loading', 'Finishing sign-in...');
    const frag = new URLSearchParams(window.location.hash.replace(/^#/, ''));
    history.replaceState(null, '', window.location.pathname); // status out of the URL bar
    const email = frag.get('email') || '';
    const ok = frag.get('status') === 'ok';
    const errReason = frag.get('oidc_error');

    let pending = null;
    try { pending = await Keystore.getPending(); } catch (e) { /* fall through */ }
    if (pending && pending.kind !== 'oidc_claim') pending = null;
    if (pending) { try { await Keystore.clearPending(); } catch (e) { /* best-effort */ } }

    if (!pending || !pending.dialog) {
      // Popup lane: the dialog window that opened the claim popup is still
      // open and still holds the RP response path — hand the result over.
      if (await handoffOidcResume(email, ok, errReason)) return;
      // No taker (or no email to hand off, e.g. an expired/replayed state
      // reaches the callback with no flow): show the REAL reason when we
      // have one instead of the generic lost-state message.
      if (!ok && errReason) {
        showError('Google sign-in failed: ' + errReason);
        return;
      }
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

    if (!ok) {
      showError('Google sign-in failed: ' + (errReason || 'try again'));
      return;
    }
    const claimed = email || pending.email;
    if (!claimed) {
      showError('Google sign-in returned nothing — try again.');
      return;
    }
    if (pending.email && !oidcEmailsMatch(pending.email, claimed)) {
      showError('Sign-in state did not match — try again.');
      return;
    }
    try {
      await completeSignIn(claimed, true);
    } catch (e) {
      showError(e.message || String(e));
    }
  }

  // Complete sign-in for a broker-rooted (secondary) email: reuse or issue the
  // device pair under the session, then present. `_afterBridge` marks the
  // re-entry from a just-completed bridge proof, so a refused delegated mint
  // can't loop back into the bridge forever.
  async function completeSignIn(email, _afterBridge) {
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
      // Step-up from the mint chokepoint (u4xz): an SMTP-proven (E3) address
      // under a lightweight session needs the account password to mint. The
      // password form re-authenticates (full session) and re-enters here.
      if (/password required/i.test(e.message)) {
        state.email = email;
        document.querySelectorAll('.email-display').forEach(el => el.textContent = email);
        showScreen('password');
        return;
      }
      // Delegated mint (u4xz/pr3a): an E2 address only mints against a live
      // bridge proof. Run the bridge once — it may reuse a live Google/Bluesky
      // session silently — and it re-enters here with the grant recorded.
      if (!_afterBridge && /live bridge proof|delegated/i.test(e.message)) {
        try {
          const info = await checkEmail(email);
          if (info.proof === 'oidc') return await handleOidcClaim(email, info);
          if (info.proof === 'atproto') return await handleAtprotoClaim(email, info);
        } catch (e2) { /* fall through to the generic error */ }
      }
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
    // A bare handle ("dan.bsky.social") is the most likely way to get the
    // Bluesky path wrong. The input stays type=email — the identity IS an
    // email, and native validation should keep saying so — but when
    // validation blocks a handle-shaped value, teach the address it maps to
    // instead of showing the browser's generic bubble (browserid-ng-xcy6).
    // The bare handle is never accepted as an identity; it is only how
    // ownership gets proven once the address form is right.
    document.getElementById('email').addEventListener('invalid', (e) => {
      const val = e.target.value.trim();
      if (!val || val.indexOf('@') !== -1) return; // native message is right
      if (!/^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(val)) return;
      e.preventDefault();
      const err = document.getElementById('email-error');
      err.textContent = '';
      const suggested = 'me@' + val.toLowerCase();
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.textContent = 'Did you mean ' + suggested + '?';
      btn.style.cssText = 'background:none;border:none;padding:0;font:inherit;color:inherit;text-decoration:underline;cursor:pointer';
      btn.addEventListener('click', () => {
        document.getElementById('email').value = suggested;
        err.textContent = '';
        document.getElementById('email-form').requestSubmit();
      });
      err.appendChild(document.createTextNode('Your browserid is an address at your handle. '));
      err.appendChild(btn);
    });

    // Email form
    document.getElementById('email-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const email = document.getElementById('email').value.trim().toLowerCase();

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
            const alt = (state.acceptedFallbacks || []).filter(f => f && f !== dom);
            showError('This site doesn’t accept email sign-in via ' + dom + '.' +
              (alt.length ? ' It accepts: ' + alt.join(', ') + '.'
                          : ' Use an email whose domain is its own identity provider.'));
            return;
          }
          // Handle-identity domain (browserid-ng-xcy6): ownership is proven
          // at the bridge via atproto OAuth, not by password or mailed code.
          // A 'known' identity with a password still gets the password screen.
          if (addressInfo.proof === 'atproto' &&
              (addressInfo.state === 'unknown' ||
               addressInfo.state === 'transition_no_password' ||
               addressInfo.state === 'unverified')) {
            return await handleAtprotoClaim(email, addressInfo);
          }
          // Google-hosted mailbox (browserid-ng-qer8): same shape, proven by
          // a Google sign-in at the broker.
          if (addressInfo.proof === 'oidc' &&
              (addressInfo.state === 'unknown' ||
               addressInfo.state === 'transition_no_password' ||
               addressInfo.state === 'unverified')) {
            return await handleOidcClaim(email, addressInfo);
          }
          if (addressInfo.proof === 'none' && addressInfo.state === 'unknown') {
            showError(email.split('@')[1] + ' can’t receive email and isn’t a ' +
              'Bluesky handle, so this address can’t be verified.');
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

        // A re-verification-pending address (kgb9) can't mint yet — re-enter
        // the chooser flow so the fresh session stages its SMTP challenge.
        if (state.reverifyAfterAuth) {
          state.reverifyAfterAuth = false;
          return await handleEmailChosen(state.email);
        }
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
        await apiCall(API.completeUserCreation, 'POST', { email: state.email, token: code });
        await completeSignIn(state.email);
      } catch (e) {
        showScreen('verify');
        document.getElementById('verify-error').textContent = e.message;
      }
    });

    // Set password form: signed-in passwordless account choosing its first
    // password — the session proves control, so no mailed code (iudv).
    document.getElementById('set-password-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const password = document.getElementById('set-password-input').value;

      if (password.length < 8) {
        document.getElementById('set-password-error').textContent = 'Password must be at least 8 characters';
        return;
      }

      showScreen('loading');

      try {
        await apiCall(API.setPassword, 'POST', { pass: password });
        await completeSignIn(state.email);
      } catch (e) {
        showScreen('setPassword');
        document.getElementById('set-password-error').textContent = e.message;
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
        await apiCall(API.completeReset, 'POST', { email: state.email, token: code, pass: password });
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

    // Agents disclosure on the picker: collapsed by default; hidden entirely
    // (in populateEmailList) when the account has no agent identities.
    const agentsToggle = document.getElementById('agents-toggle');
    if (agentsToggle) agentsToggle.addEventListener('click', () => {
      const section = document.getElementById('agents-section');
      const open = section.classList.toggle('open');
      const chev = agentsToggle.querySelector('.chev');
      if (chev) chev.textContent = open ? '▾' : '▸';
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
      const email = document.getElementById('new-email').value.trim().toLowerCase();

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

        // A handle identity is proven at the bridge, not by mailed code —
        // the same claim hop attaches it to the signed-in account, because
        // complete_handle_claim lands on the session when one exists
        // (browserid-ng-xcy6).
        if (addressInfo.proof === 'atproto') {
          await handleAtprotoClaim(email, addressInfo);
          return;
        }

        // Same for a Google-hosted mailbox (browserid-ng-qer8): the OIDC
        // callback attaches to the signed-in session when one exists.
        if (addressInfo.proof === 'oidc') {
          await handleOidcClaim(email, addressInfo);
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
        await apiCall(API.completeEmailAddition, 'POST', { email: state.newEmail, token: code });
        // Email added successfully - use it to sign in
        state.email = state.newEmail;
        // First SMTP address on a passwordless account: the add code just
        // verified is the ONE roundtrip — chain straight into choosing a
        // password on the session instead of mailing a second code (iudv).
        const emails = await apiCall(API.listEmails);
        if (emails.has_password === false) {
          document.querySelectorAll('.email-display').forEach(el => el.textContent = state.email);
          showScreen('setPassword');
          return;
        }
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
        pair = await reconcileBrowserHolder(p.email, p.email.split('@')[1], p.keys, certs, pair, p.info.access_mint, p.info.device_auth);
        await finishSignIn(p.email, pair, p.email.split('@')[1], p.info.access_mint);
      } catch (err) {
        if (err && err.popupBlocked) {
          showError('Could not open the sign-in window. Please allow popups for this site and try again.');
        } else {
          showError(err.message || String(err));
        }
      }
    });

    // Tap-to-continue for a blocked claim popup (atproto browserid-ng-xcy6,
    // OIDC browserid-ng-qer8): same shape as the primary one — re-run from a
    // real user gesture.
    document.getElementById('continue-handle-claim').addEventListener('click', async () => {
      const p = state.pendingClaim;
      if (!p) return showScreen('email');
      state.pendingClaim = null;
      if (p.kind === 'oidc') await handleOidcClaim(p.email, p.info);
      else await handleAtprotoClaim(p.email, p.info);
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
    // Managed-identity disclosure: Continue resumes the sign-in (the flow is
    // awaiting the promise inside storeDevicePair); Cancel aborts the flow and
    // returns control to the RP as a user cancellation.
    document.getElementById('managed-consent-continue').addEventListener('click', () => {
      const p = managedConsentPending;
      managedConsentPending = null;
      showScreen('loading', 'Signing in…');
      if (p) p.resolve();
    });
    document.getElementById('managed-consent-cancel').addEventListener('click', () => {
      const p = managedConsentPending;
      managedConsentPending = null;
      if (p) p.reject(new Error('managed identity declined'));
      sendCancel();
    });

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

  // Populate the picker — ALL of the account's identities, whether or not this
  // browser holds device certs for them (issuance happens on selection).
  // USER addresses go in the primary radio card; AGENT identities go in the
  // collapsed section below (display name first, mono address second; the
  // selected agent row explains the site will see it's an agent). One radio
  // group (`selected-email`) spans both lists. Derived/subordinate identities
  // (mingo-cm8z) get a sub-label naming the parent they sign in through.
  function populateEmailList(emails) {
    const list = document.getElementById('email-list');
    list.innerHTML = '';
    const agents = state.agents || [];
    const userEmails = emails.filter(e => !agents.includes(e));
    const agentEmails = emails.filter(e => agents.includes(e));

    userEmails.forEach((emailStr, index) => {
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

    const section = document.getElementById('agents-section');
    const agentList = document.getElementById('agent-list');
    if (section && agentList) {
      agentList.innerHTML = '';
      section.hidden = agentEmails.length === 0;
      const count = document.getElementById('agents-count');
      if (count) count.textContent = '· ' + agentEmails.length;
      agentEmails.forEach((emailStr, index) => {
        const safeEmail = escapeHtml(emailStr);
        const name = state.publicNames[emailStr] || emailStr.slice(0, emailStr.indexOf('@'));
        const li = document.createElement('li');
        li.innerHTML = `
          <label>
            <input type="radio" name="selected-email" value="${safeEmail}" ${!userEmails.length && index === 0 ? 'checked' : ''}>
            <span class="agent-main">
              <span>${escapeHtml(name)} <span class="agent-addr">${safeEmail}</span></span>
              <span class="agent-note">the site will see it's an agent acting for you</span>
            </span>
          </label>
        `;
        agentList.appendChild(li);
      });
    }
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
        state.agents = emailsResponse.agents || [];
        state.publicNames = {};
        (emailsResponse.public_names || []).forEach(p => { state.publicNames[p.email] = p.public_name; });

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

  if (params.get('resume') === 'oidc_claim') {
    // Returning from the Google claim hop (browserid-ng-qer8).
    resumeOidcClaim();
  } else if (params.get('resume') === 'device_auth') {
    // Returning from the same-tab primary hop (redirect mode).
    resumeDeviceAuth();
  } else if (params.get('resume') === 'handle_claim') {
    // Returning from the bridge's handle-claim hop (browserid-ng-xcy6).
    resumeHandleClaim();
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
    if (params.get('resume')) return; // a resume page never receives an RP request
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
