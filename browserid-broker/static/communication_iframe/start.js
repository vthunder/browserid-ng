/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

(function() {
  var bid = BrowserID,
      network = bid.Network,
      user = bid.User,
      storage = bid.Storage,
      interactionData = bid.Models.InteractionData;

  // Initialize all localstorage values to default values.  Neccesary for
  // proper sync of IE8 localStorage across multiple simultaneous
  // browser sessions.
  storage.setDefaultValues();

  network.init();
  user.init();

  var chan = Channel.build({
    window: window.parent,
    origin: "*",
    scope: "mozid_ni"
  });

  var remoteOrigin;

  function setRemoteOrigin(o) {
    if (!remoteOrigin) {
      remoteOrigin = o;
      var options = {
        origin: remoteOrigin
      };

      var issuer = storage.site.get(remoteOrigin, "issuer");
      if (issuer) options.issuer = issuer;

      var rpInfo = bid.Models.RpInfo.create(options);
      user.setRpInfo(rpInfo);
    }
  }

  var loggedInUser;

  // the controlling page may "pause" the iframe when someone else (the dialog)
  // is supposed to emit events
  var pause = false;

  function checkAndEmit(oncomplete) {
    if (pause) return;

    function onError(err) {
      chan.notify({ method: 'logout' });
      loggedInUser = null;
      oncomplete && oncomplete();
    }

    // All XHR requests are aborted when the user browsers away from the RP.
    // Outstanding calls to cookiesEnabled (which calls /wsapi/session_context)
    // will be aborted, the onError callback will not be invoked. All other XHR
    // errors will call onError. See issues #2423, #3619
    network.cookiesEnabled(function(enabled) {
      if (!enabled) {
        // cookies are disabled, call onready and do nothing more.
        // By not setting loggedInUser to null, the RP can call .logout
        // a single time and have the .onlogout callback fired, which in
        // turn allows the RP to sign the user out of their site.
        return oncomplete && oncomplete();
      }

      // iOS7 has new privacy settings which prevent the communication iframe
      // from working.  We can retain *some* semantics, but not all.  We cannot
      // read local storage, so we cannot generate assertions.  We do have access to
      // cookies, however, so we can log users out.
      if (!storage.storageCheck.get()) {
        user.checkAuthentication(function(authenticated) {
          if ((loggedInUser === undefined || loggedInUser) && !authenticated) {
            chan.notify({ method: 'logout' });
            loggedInUser = null;
          } else if (loggedInUser === null && !authenticated) {
            chan.notify({ method: 'match' });
          }
          oncomplete && oncomplete();
        });
      } else {
        // this will re-certify the user if neccesary
        user.getSilentAssertion(loggedInUser, function(email, assertion) {
          if (loggedInUser === email) {
            chan.notify({ method: 'match' });
          } else if (email) {
            // only send login events when the assertion is defined - when
            // the 'loggedInUser' is already logged in, it's false - that is
            // when the site already has the user logged in and does not want
            // the resources or cost required to generate an assertion
            if (assertion) chan.notify({ method: 'login', params: assertion });
            loggedInUser = email;
          } else if (loggedInUser !== null) {
            // only send logout events when loggedInUser is not null, which is an
            // indicator that the site thinks the user is logged out
            chan.notify({ method: 'logout' });
            loggedInUser = null;
          }
          oncomplete && oncomplete();
        }, onError);
      }
    }, onError);
  }

  function watchState() {
    storage.watchLoggedIn(remoteOrigin, checkAndEmit);
  }

  // one of two events will cause us to begin checking to
  // see if an event shall be emitted - either an explicit
  // loggedInUser event or page load.
  chan.bind("loggedInUser", function(trans, email) {
    loggedInUser = email;
  });

  chan.bind("loaded", function(trans, params) {
    trans.delayReturn(true);
    setRemoteOrigin(trans.origin);
    checkAndEmit(function() {
      watchState();
      trans.complete();
    });
  });

  chan.bind("logout", function(trans, params) {
    // set remote origin so that .logout can be called even if .request has
    // not.
    // See https://github.com/mozilla/browserid/pull/2529
    setRemoteOrigin(trans.origin);
    // loggedInUser will be undefined if none of loaded, loggedInUser nor
    // logout have been called before. This allows the user to be force logged
    // out.
    if (loggedInUser !== null) {
      storage.site.remove(remoteOrigin, "logged_in");
      loggedInUser = null;
      chan.notify({ method: 'logout' });
    }
  });

  chan.bind("redirect_flow", function(trans, params) {
    setRemoteOrigin(trans.origin);
    storage.rpRequest.set({
      origin: remoteOrigin,
      params: JSON.parse(params)
    });
    return true;
  });

  // ==========================================================================
  // Typed signing extension — SBO envelopes (Phase 7.4)
  //
  // A second, domain-separated capability over the cert-bound key: sign a typed,
  // parsed-and-bound SBO envelope. Origin-gated (per-app grant), identity-bound
  // (Owner == signing email; Public-Key/Auth-Cert overridden to the agent's),
  // and the canonical bytes are rebuilt in-agent via sbo-wasm — never opaque
  // caller bytes. See common/js/sbo-sign.js and the design note in the SBO repo.
  // ==========================================================================

  // Where the agent records that the user granted an origin the SBO signing
  // capability (a one-time per-app grant; the consent UI lives in the dialog).
  var SBO_GRANT_KEY = "sbo_sign_granted";

  // sbo-wasm is an ES module; load + init once and cache the promise.
  var sboWasmPromise = null;
  function loadSboWasm() {
    if (!sboWasmPromise) {
      sboWasmPromise = import("/common/js/sbo-wasm/sbo_wasm.js").then(function(mod) {
        // `--target web` exports a default init() that fetches the .wasm.
        return Promise.resolve(mod.default && mod.default()).then(function() {
          return mod;
        });
      });
    }
    return sboWasmPromise;
  }

  // Sign a typed SBO envelope for `email` as `remoteOrigin`. The request carries
  // the caller-built envelope spec (sbo-wasm shape); the agent binds it to the
  // identity, rebuilds canonical bytes, and signs with the stored key.
  chan.bind("signSboEnvelope", function(trans, params) {
    setRemoteOrigin(trans.origin);
    trans.delayReturn(true);

    try {
      params = params || {};
      var email = params.email;
      var envelope = params.envelope;
      if (!email || !envelope) {
        return trans.error("bad_request", "email and envelope are required");
      }

      // Origin gating: the capability is offered only to granted origins.
      if (!storage.site.get(remoteOrigin, SBO_GRANT_KEY)) {
        return trans.error("not_granted",
          "origin " + remoteOrigin + " has not been granted SBO signing");
      }

      // Load the stored cert-bound identity (private JWK + Auth-Cert).
      var issuer = params.issuer || storage.site.get(remoteOrigin, "issuer");
      var record = storage.getEmail(email, issuer);
      if (!record || !record.priv || !record.cert) {
        return trans.error("no_identity",
          "no cert-bound key for " + email + (issuer ? " @ " + issuer : ""));
      }

      var identity = {
        email: email,
        pubkeyHex: bid.SboSign.pubkeyHexFromJwkX(record.pub ? record.pub.x : record.priv.x),
        cert: record.cert
      };

      loadSboWasm().then(function(sbo) {
        return bid.SboSign.signEnvelope(sbo, envelope, identity, record.priv);
      }).then(function(res) {
        trans.complete({
          signature: res.signature,
          cert: res.cert,
          pubkey: res.pubkey
        });
      }).catch(function(err) {
        trans.error("sign_failed", (err && err.message) || String(err));
      });
    } catch (e) {
      trans.error("sign_failed", (e && e.message) || String(e));
    }
  });

  chan.bind("dialog_running", function(trans, params) {
    pause = true;
  });

  chan.bind("dialog_complete", function(trans, checkAuthStatus) {
    pause = false;
    // The dialog has closed, so that we get results from users who only open
    // the dialog a single time, send the KPIs immediately. Errors sending the
    // KPI data should not affect anything else.
    try {
      var currentData = interactionData.getCurrent();
      if (currentData) {
        // set the last KPIs from the current state of the world.
        _.extend(currentData, {
          number_emails: storage.getEmailCount() || 0,
          number_sites_signed_in: storage.loggedInCount() || 0,
          number_sites_remembered: storage.site.count() || 0
        });

        interactionData.setCurrent(currentData);
        interactionData.publishCurrent();
      }
    } catch(e) {}

    if (checkAuthStatus) {
      // the dialog running can change authentication status,
      // lets manually purge our network cache
      user.clearContext();
      checkAndEmit();
    }
  });
}());
