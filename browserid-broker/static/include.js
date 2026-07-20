/**
 * BrowserID-NG include.js
 * Based on Mozilla Persona (MPL 2.0)
 *
 * Include this script to get the navigator.id API (watch/request/logout).
 * Device-cert model: onlogin receives the 4-object ACCESS PRESENTATION
 * (`access_cert~assertion~warrant~config_cert`) — verify it server-side via
 * POST /verify-access (or the @browserid-ng/verify SDK).
 *
 * Popup-hostile browsers (Arc's detached popups, blockers): when the dialog
 * popup fails, the flow falls back to a FULL-PAGE REDIRECT and the
 * presentation is delivered on the return page load through the SAME
 * onlogin observer — which is why watch()+request() is the only API: a
 * promise cannot survive the navigation.
 * Configure broker URL via:
 *   - data-browserid-url attribute on script tag
 *   - window.BROWSERID_URL global variable
 *   - defaults to same origin as this script
 */
(function() {
  var undefined;
  if (navigator.mozId) { navigator.id = navigator.mozId; }
  else { (function() {
  var undefined;
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

  // local embedded copy of jschannel: http://github.com/mozilla/jschannel
  /**
   * js_channel is a very lightweight abstraction on top of
   * postMessage which defines message formats and semantics
   * to support interactions more rich than just message passing
   * js_channel supports:
   *  + query/response - traditional rpc
   *  + query/update/response - incremental async return of results
   *    to a query
   *  + notifications - fire and forget
   *  + error handling
   *
   * js_channel is based heavily on json-rpc, but is focused at the
   * problem of inter-iframe RPC.
   *
   * Message types:
   *  There are 5 types of messages that can flow over this channel,
   *  and you may determine what type of message an object is by
   *  examining its parameters:
   *  1. Requests
   *    + integer id
   *    + string method
   *    + (optional) any params
   *  2. Callback Invocations (or just "Callbacks")
   *    + integer id
   *    + string callback
   *    + (optional) params
   *  3. Error Responses (or just "Errors)
   *    + integer id
   *    + string error
   *    + (optional) string message
   *  4. Responses
   *    + integer id
   *    + (optional) any result
   *  5. Notifications
   *    + string method
   *    + (optional) any params
   */

;WinChan = (function() {
  var RELAY_FRAME_NAME = "__winchan_relay_frame";
  var CLOSE_CMD = "die";

  // a portable addListener implementation
  function addListener(w, event, cb) {
    if(w.attachEvent) w.attachEvent('on' + event, cb);
    else if (w.addEventListener) w.addEventListener(event, cb, false);
  }

  // a portable removeListener implementation
  function removeListener(w, event, cb) {
    if(w.detachEvent) w.detachEvent('on' + event, cb);
    else if (w.removeEventListener) w.removeEventListener(event, cb, false);
  }

  // checking for IE8 or above
  function isInternetExplorer() {
    var rv = -1; // Return value assumes failure.
    var ua = navigator.userAgent;
    if (navigator.appName === 'Microsoft Internet Explorer') {
      var re = new RegExp("MSIE ([0-9]{1,}[\.0-9]{0,})");
      if (re.exec(ua) != null)
        rv = parseFloat(RegExp.$1);
    }
    else if (ua.indexOf("Trident") > -1) {
      var re = new RegExp("rv:([0-9]{2,2}[\.0-9]{0,})");
      if (re.exec(ua) !== null) {
        rv = parseFloat(RegExp.$1);
      }
    }

    return rv >= 8;
  }

  // checking Mobile Firefox (Fennec)
  function isFennec() {
    try {
      // We must check for both XUL and Java versions of Fennec.  Both have
      // distinct UA strings.
      var userAgent = navigator.userAgent;
      return (userAgent.indexOf('Fennec/') != -1) ||  // XUL
             (userAgent.indexOf('Firefox/') != -1 && userAgent.indexOf('Android') != -1);   // Java
    } catch(e) {}
    return false;
  }

  // feature checking to see if this platform is supported at all
  function isSupported() {
    return (window.JSON && window.JSON.stringify &&
            window.JSON.parse && window.postMessage);
  }

  // given a URL, extract the origin
  function extractOrigin(url) {
    if (!/^https?:\/\//.test(url)) url = window.location.href;
    var m = /^(https?:\/\/[\-_a-zA-Z\.0-9:]+)/.exec(url);
    if (m) return m[1];
    return url;
  }

  // find the relay iframe in the opener
  function findRelay() {
    var loc = window.location;
    var frames = window.opener.frames;
    for (var i = frames.length - 1; i >= 0; i--) {
      try {
        if (frames[i].location.protocol === window.location.protocol &&
            frames[i].location.host === window.location.host &&
            frames[i].name === RELAY_FRAME_NAME)
        {
          return frames[i];
        }
      } catch(e) { }
    }
    return;
  }

  var isIE = isInternetExplorer();

  if (isSupported()) {
    /*  General flow:
     *                  0. user clicks
     *  (IE SPECIFIC)   1. caller adds relay iframe (served from trusted domain) to DOM
     *                  2. caller opens window (with content from trusted domain)
     *                  3. window on opening adds a listener to 'message'
     *  (IE SPECIFIC)   4. window on opening finds iframe
     *                  5. window checks if iframe is "loaded" - has a 'doPost' function yet
     *  (IE SPECIFIC5)  5a. if iframe.doPost exists, window uses it to send ready event to caller
     *  (IE SPECIFIC5)  5b. if iframe.doPost doesn't exist, window waits for frame ready
     *  (IE SPECIFIC5)  5bi. once ready, window calls iframe.doPost to send ready event
     *                  6. caller upon reciept of 'ready', sends args
     */
    return {
      open: function(opts, cb) {
        if (!cb) throw "missing required callback argument";

        // test required options
        var err;
        if (!opts.url) err = "missing required 'url' parameter";
        if (!opts.relay_url) err = "missing required 'relay_url' parameter";
        if (err) setTimeout(function() { cb(err); }, 0);

        // supply default options
        if (!opts.window_name) opts.window_name = null;
        if (!opts.window_features || isFennec()) opts.window_features = undefined;

        // opts.params may be undefined

        var iframe;

        // sanity check, are url and relay_url the same origin?
        var origin = extractOrigin(opts.url);
        if (origin !== extractOrigin(opts.relay_url)) {
          return setTimeout(function() {
            cb('invalid arguments: origin of url and relay_url must match');
          }, 0);
        }

        var messageTarget;

        if (isIE) {
          // first we need to add a "relay" iframe to the document that's served
          // from the target domain.  We can postmessage into a iframe, but not a
          // window
          iframe = document.createElement("iframe");
          // iframe.setAttribute('name', framename);
          iframe.setAttribute('src', opts.relay_url);
          iframe.style.display = "none";
          iframe.setAttribute('name', RELAY_FRAME_NAME);
          document.body.appendChild(iframe);
          messageTarget = iframe.contentWindow;
        }

        var w = window.open(opts.url, opts.window_name, opts.window_features);

        // If the popup was blocked (mobile browsers with pop-ups disabled return
        // null), report it asynchronously so the caller's callback runs — which
        // clears the opener-side window handle. Otherwise the request hangs
        // forever AND the stale handle short-circuits every later request
        // (`if (w) { w.focus(); return; }`), wedging auth until a reload.
        if (!w) {
          if (cb) setTimeout(function() { cb('popup blocked'); cb = null; }, 0);
          return { close: function() {}, focus: function() {} };
        }

        if (!messageTarget) messageTarget = w;

        // lets listen in case the window blows up before telling us
        var closeInterval = setInterval(function() {
          if (w && w.closed) {
            cleanup();
            if (cb) {
              cb('unknown closed window');
              cb = null;
            }
          }
        }, 500);

        var req = JSON.stringify({a: 'request', d: opts.params});

        // cleanup on unload
        function cleanup() {
          if (iframe) document.body.removeChild(iframe);
          iframe = undefined;
          if (closeInterval) closeInterval = clearInterval(closeInterval);
          removeListener(window, 'message', onMessage);
          removeListener(window, 'unload', cleanup);
          if (w) {
            try {
              w.close();
            } catch (securityViolation) {
              // This happens in Opera 12 sometimes
              // see https://github.com/mozilla/browserid/issues/1844
              messageTarget.postMessage(CLOSE_CMD, origin);
            }
          }
          w = messageTarget = undefined;
        }

        addListener(window, 'unload', cleanup);

        function onMessage(e) {
          if (e.origin !== origin) { return; }
          try {
            var d = JSON.parse(e.data);
            if (d.a === 'ready') {
              // The dialog window is alive and connected (not a detached tab).
              if (opts.onReady) { try { opts.onReady(); } catch (e2) { } }
              messageTarget.postMessage(req, origin);
            }
            else if (d.a === 'error') {
              cleanup();
              if (cb) {
                cb(d.d);
                cb = null;
              }
            } else if (d.a === 'response') {
              cleanup();
              if (cb) {
                cb(null, d.d);
                cb = null;
              }
            }
          } catch(err) { }
        }

        addListener(window, 'message', onMessage);

        return {
          close: cleanup,
          focus: function() {
            if (w) {
              try {
                w.focus();
              } catch (e) {
                // IE7 blows up here, do nothing
              }
            }
          }
        };
      },
      onOpen: function(cb) {
        var o = "*";
        var msgTarget = isIE ? findRelay() : window.opener;
        if (!msgTarget) throw "can't find relay frame";
        function doPost(msg) {
          msg = JSON.stringify(msg);
          if (isIE) msgTarget.doPost(msg, o);
          else msgTarget.postMessage(msg, o);
        }

        function onMessage(e) {
          // only one message gets through, but let's make sure it's actually
          // the message we're looking for (other code may be using
          // postmessage) - we do this by ensuring the payload can
          // be parsed, and it's got an 'a' (action) value of 'request'.
          var d;
          try {
            d = JSON.parse(e.data);
          } catch(err) { }
          if (!d || d.a !== 'request') return;
          removeListener(window, 'message', onMessage);
          o = e.origin;
          if (cb) {
            // this setTimeout is critically important for IE8 -
            // in ie8 sometimes addListener for 'message' can synchronously
            // cause your callback to be invoked.  awesome.
            setTimeout(function() {
              cb(o, d.d, function(r) {
                cb = undefined;
                doPost({a: 'response', d: r});
              });
            }, 0);
          }
        }

        function onDie(e) {
          if (e.data === CLOSE_CMD) {
            try { window.close(); } catch (o_O) {}
          }
        }
        addListener(isIE ? msgTarget : window, 'message', onMessage);
        addListener(isIE ? msgTarget : window, 'message', onDie);

        // we cannot post to our parent that we're ready before the iframe
        // is loaded. (IE specific possible failure)
        try {
          doPost({a: "ready"});
        } catch(e) {
          // this code should never be exectued outside IE
          addListener(msgTarget, 'load', function(e) {
            doPost({a: "ready"});
          });
        }

        // if window is unloaded and the client hasn't called cb, it's an error
        var onUnload = function() {
          try {
            // IE8 doesn't like this...
            removeListener(isIE ? msgTarget : window, 'message', onDie);
          } catch (ohWell) { }
          if (cb) doPost({ a: 'error', d: 'client closed window' });
          cb = undefined;
          // explicitly close the window, in case the client is trying to reload or nav
          try { window.close(); } catch (e) { }
        };
        addListener(window, 'unload', onUnload);
        return {
          detach: function() {
            removeListener(window, 'unload', onUnload);
          }
        };
      }
    };
  } else {
    return {
      open: function(url, winopts, arg, cb) {
        setTimeout(function() { cb("unsupported browser"); }, 0);
      },
      onOpen: function(cb) {
        setTimeout(function() { cb("unsupported browser"); }, 0);
      }
    };
  }
})();
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

  var BrowserSupport = (function() {
    var win = window,
        nav = navigator,
        reason;

    // For unit testing
    function setTestEnv(newNav, newWindow) {
      nav = newNav;
      win = newWindow;
    }

    function getInternetExplorerVersion() {
      var rv = -1; // Return value assumes failure.
      if (nav.appName == 'Microsoft Internet Explorer') {
        var ua = nav.userAgent;
        var re = new RegExp("MSIE ([0-9]{1,}[\.0-9]{0,})");
        if (re.exec(ua) != null)
          rv = parseFloat(RegExp.$1);
      }

      return rv;
    }

    function checkIE() {
      var ieVersion = getInternetExplorerVersion(),
          ieNosupport = ieVersion > -1 && ieVersion < 8;

      if(ieNosupport) {
        return "BAD_IE_VERSION";
      }
    }

    function explicitNosupport() {
      return checkIE();
    }

    function checkLocalStorage() {
      // Firefox/Fennec/Chrome blow up when trying to access or
      // write to localStorage. We must do two explicit checks, first
      // whether the browser has localStorage.  Second, we must check
      // whether the localStorage can be written to.  Firefox (at v11)
      // throws an exception when querying win['localStorage']
      // when cookies are disabled. Chrome (v17) excepts when trying to
      // write to localStorage when cookies are disabled. If an
      // exception is thrown, then localStorage is disabled. If no
      // exception is thrown, hasLocalStorage will be true if the
      // browser supports localStorage and it can be written to.
      try {
        var hasLocalStorage = 'localStorage' in win
                        // Firefox will except here if cookies are disabled.
                        && win['localStorage'] !== null;

        if(hasLocalStorage) {
          // browser has localStorage, check if it can be written to. If
          // cookies are disabled, some browsers (Chrome) will except here.
          win['localStorage'].setItem("test", "true");
          win['localStorage'].removeItem("test");
        }
        else {
          // Browser does not have local storage.
          return "LOCALSTORAGE_NOT_SUPPORTED";
        }
      } catch(e) {
          return "LOCALSTORAGE_DISABLED";
      }
    }

    function checkPostMessage() {
      if(!win.postMessage) {
        return "POSTMESSAGE_NOT_SUPPORTED";
      }
    }

    function checkJSON() {
      if(!(window.JSON && window.JSON.stringify && window.JSON.parse)) {
        return "JSON_NOT_SUPPORTED";
      }
    }

    function isSupported() {
      reason = explicitNosupport() || checkLocalStorage() || checkPostMessage() || checkJSON();

      return !reason;
    }


    function getNoSupportReason() {
      return reason;
    }

    return {
      /**
       * Set the test environment.
       * @method setTestEnv
       */
      setTestEnv: setTestEnv,
      /**
       * Check whether the current browser is supported
       * @method isSupported
       * @returns {boolean}
       */
      isSupported: isSupported,
      /**
       * Called after isSupported, if isSupported returns false.  Gets the reason
       * why browser is not supported.
       * @method getNoSupportReason
       * @returns {string}
       */
      getNoSupportReason: getNoSupportReason
    };
  }());

  if (!navigator.id) {
    navigator.id = {};
  }

  if (!navigator.id.request || navigator.id._shimmed) {
    // Detect broker URL from script tag or global variable
    var ipServer = (function() {
      // Check for global variable
      if (window.BROWSERID_URL) return window.BROWSERID_URL;
      // Check for data attribute on script tag
      var scripts = document.getElementsByTagName('script');
      for (var i = 0; i < scripts.length; i++) {
        var src = scripts[i].src || '';
        if (src.indexOf('include.js') !== -1) {
          var url = scripts[i].getAttribute('data-browserid-url');
          if (url) return url;
          // Default to same origin as script
          var match = src.match(/^(https?:\/\/[^\/]+)/);
          if (match) return match[1];
        }
      }
      // Fallback to current origin
      return window.location.protocol + '//' + window.location.host;
    })();
    var userAgent = navigator.userAgent;
    // We must check for both XUL and Java versions of Fennec.  Both have
    // distinct UA strings.
    var isFennec = (userAgent.indexOf('Fennec/') != -1) ||  // XUL
                     (userAgent.indexOf('Firefox/') != -1 && userAgent.indexOf('Android') != -1);   // Java

    var windowOpenOpts =
      (isFennec ? undefined :
       "menubar=0,location=1,resizable=1,scrollbars=1,status=0,width=480,height=660");

    var WINDOW_NAME = "__persona_dialog";
    var w;

    // table of registered observers
    var observers = {
      login: null,
      logout: null,
      match: null,
      ready: null
    };

    // dialog appearance options (siteLogo, siteName, backgroundColor)
    var displayOpts = {};

    var loggedInUser;

    var compatMode = undefined;
    function checkCompat(requiredMode) {
      if (requiredMode === true) {
        // this deprecation warning should be re-enabled when the .watch and .request APIs become final.
        // try { console.log("this site uses deprecated APIs (see documentation for navigator.id.request())"); } catch(e) { }
      }

      if (compatMode === undefined) compatMode = requiredMode;
      else if (compatMode != requiredMode) {
        throw new Error("you cannot combine the navigator.id.watch() API with navigator.id.getVerifiedEmail() or navigator.id.get()" +
              "this site should instead use navigator.id.request() and navigator.id.watch()");
      }
    }

    var waitingForDOM = false,
        browserSupported = BrowserSupport.isSupported();

    function domReady(callback) {
      if (document.addEventListener) {
        document.addEventListener('DOMContentLoaded', function contentLoaded() {
          document.removeEventListener('DOMContentLoaded', contentLoaded);
          callback();
        }, false);
      } else if (document.attachEvent && document.readyState) {
        document.attachEvent('onreadystatechange', function ready() {
          var state = document.readyState;
          // 'interactive' is the same as DOMContentLoaded,
          // but not all browsers use it, sadly.
          if (state === 'loaded' || state === 'complete' || state === 'interactive') {
            document.detachEvent('onreadystatechange', ready);
            callback();
          }
        });
      }
    }


    function defined(item) {
      return typeof item !== "undefined";
    }

    function warn(message) {
      try {
        console.warn(message);
      } catch(e) {
        /* ignore error */
      }
    }

    function checkDeprecated(options, field) {
      if(defined(options[field])) {
        warn(field + " has been deprecated");
        return true;
      }
    }

    function checkRenamed(options, oldName, newName) {
      if (defined(options[oldName]) &&
          defined(options[newName])) {
        throw new Error("you cannot supply *both* " + oldName + " and " + newName);
      }
      else if(checkDeprecated(options, oldName)) {
        options[newName] = options[oldName];
        delete options[oldName];
      }
    }

    function internalWatch(options) {
      if (typeof options !== 'object') return;

      if (options.onlogin && typeof options.onlogin !== 'function' ||
          options.onlogout && typeof options.onlogout !== 'function' ||
          options.onmatch && typeof options.onmatch !== 'function' ||
          options.onready && typeof options.onready !== 'function')
      {
        throw new Error("non-function where function expected in parameters to navigator.id.watch()");
      }

      if (!options.onlogin) throw new Error("'onlogin' is a required argument to navigator.id.watch()");
      if (!options.onlogout && (options.onmatch || ('loggedInUser' in options)))
        throw new Error('stateless api only allows onlogin and onready options');

      observers.login = options.onlogin || null;
      observers.logout = options.onlogout || null;
      observers.match = options.onmatch || null;
      // NOTE: Do not modify without reading GH-2017
      observers.ready = options.onready || null;

      // back compat support for loggedInEmail
      checkRenamed(options, "loggedInEmail", "loggedInUser");
      loggedInUser = options.loggedInUser;
      if (loggedInUser === false) {
        loggedInUser = null;
      }
      if (!isNull(loggedInUser)  &&
          !isUndefined(loggedInUser) &&
          !isString(loggedInUser))
      {
        throw new Error("loggedInUser is not a valid type");
      }

      // Save dialog appearance options
      if (options.siteName) displayOpts.siteName = options.siteName;
      if (options.siteLogo) displayOpts.siteLogo = options.siteLogo;
      if (options.backgroundColor) displayOpts.backgroundColor = options.backgroundColor;
      // The RP's accepted fallback IdPs for no-primary emails (spec §8.1).
      // A routing hint for the dialog; the RP's verifier enforces (§6.1).
      if (options.acceptedFallbacks) displayOpts.acceptedFallbacks = options.acceptedFallbacks;

      // Opted-in silent FedCM: attempt a zero-UI auto-login for returning users.
      // No chooser, no popup.
      if (fedcmAvailable()) trySilentFedCM();

      // Deliver a redirect-mode return now that the observer exists.
      if (pendingRedirectReturn) {
        var pr = pendingRedirectReturn;
        pendingRedirectReturn = null;
        setTimeout(function () {
          if (observers.login) {
            try { observers.login(pr.presentation); } catch (clientError) { console.log(clientError); }
          }
          if (pr.fedcm_optin && fedcmAvailable()) establishFedCMGrant();
        }, 0);
      }
    }

    function isNull(arg) {
      return arg === null;
    }

    function isUndefined(arg) {
      return (typeof arg === 'undefined');
    }

    function isString(arg) {
      return Object.prototype.toString.apply(arg) === "[object String]";
    }

    var api_called;
    function getRPAPI() {
      var rp_api = api_called;
      if (rp_api === "request") {
        if (observers.logout) {
          rp_api = observers.ready ? "watch_with_onready" : "watch_without_onready";
        } else {
          rp_api = "stateless";
        }
      }

      return rp_api;
    }

    function internalRequest(options) {
      checkDeprecated(options, "requiredEmail");
      checkRenamed(options, "tosURL", "termsOfService");
      checkRenamed(options, "privacyURL", "privacyPolicy");
      checkRenamed(options, "experimental_emailHint", "email");

      options.rp_api = getRPAPI();

      if (options.rp_api === "stateless") {
        if (options.termsOfService || options.privacyPolicy) {
          warn("Deprecation notice: termsOfService and privacyPolicy options are deprecated in the stateless (\"Goldilocks\") Persona API, and will eventually be removed. More info: https://github.com/mozilla/persona/issues/4134#issuecomment-44859342");
        }
      }

      if (options.termsOfService && !options.privacyPolicy) {
        warn("termsOfService ignored unless privacyPolicy also defined");
      }

      if (options.privacyPolicy && !options.termsOfService) {
        warn("privacyPolicy ignored unless termsOfService also defined");
      }

      if (options.siteLogo) warn("Please pass siteLogo to .watch() instead of .request()");
      if (options.siteName) warn("Please pass siteName to .watch() instead of .request()");
      if (options.backgroundColor) warn("Please pass backgroundColor to .watch() instead of .request()");

      // Options passed to .watch() always win.
      // Necessary for backwards compatibility between Goldilocks and Observer
      options.siteLogo = displayOpts.siteLogo || options.siteLogo;
      options.siteName = displayOpts.siteName || options.siteName;
      options.backgroundColor = displayOpts.backgroundColor || options.backgroundColor;
      options.acceptedFallbacks = displayOpts.acceptedFallbacks || options.acceptedFallbacks;
      // Tell the dialog whether to offer the "auto sign-in next time" (FedCM)
      // checkbox — only when this browser supports FedCM and the RP opted in.
      options.fedcm = fedcmAvailable();

      options.rp_api = getRPAPI();

      // reset the api_called in case the site implementor changes which api
      // method called the next time around.
      api_called = null;

      options.start_time = (new Date()).getTime();

      // focus an existing window
      if (w) {
        try {
          w.focus();
        }
        catch(e) {
          /* IE7 blows up here, do nothing */
        }
        return;
      }

      if (!BrowserSupport.isSupported()) {
        var reason = BrowserSupport.getNoSupportReason();
        var url = (reason === "LOCALSTORAGE_DISABLED") ? "cookies_disabled" : "unsupported_dialog";
        w = window.open(
          ipServer + "/" + url,
          WINDOW_NAME,
          windowOpenOpts);
        return;
      }

      // Explicit redirect mode: skip the popup attempt entirely.
      if (options.redirect === true && observers.login) {
        return engageRedirect(options);
      }

      // Detached-popup watchdog (Arc converts popups to opener-less tabs: the
      // window exists but WinChan's 'ready' ping can never arrive). If the
      // dialog hasn't pinged within the timeout, close the orphan and fall
      // back to the full-page redirect flow.
      var readyTimer = null;
      function armDetachedPopupWatchdog(popupOptions) {
        readyTimer = setTimeout(function () {
          readyTimer = null;
          if (!observers.login) return; // stateless API cannot survive a navigation
          try { if (w) w.close(); } catch (e) { }
          w = undefined;
          engageRedirect(popupOptions);
        }, 4000);
      }

      armDetachedPopupWatchdog(options);
      w = WinChan.open({
        onReady: function () {
          if (readyTimer) { clearTimeout(readyTimer); readyTimer = null; }
        },
        url: ipServer + '/sign_in',
        relay_url: ipServer + '/relay',
        window_features: windowOpenOpts,
        window_name: WINDOW_NAME,
        params: {
          method: "get",
          params: options
        }
      }, function(err, r) {
        if (readyTimer) { clearTimeout(readyTimer); readyTimer = null; }
        // Popup blocked outright: fall back to the full-page redirect flow
        // (only possible in watch mode — the observer survives navigation).
        if (err === 'popup blocked' && observers.login) {
          w = undefined;
          return engageRedirect(options);
        }
        // clear the window handle
        w = undefined;
        if (!err && r && r.presentation) {
          try {
            if (observers.login) observers.login(r.presentation);
          } catch(clientError) {
            // client's observer threw an exception
            // help developers debug by logging the error
            console.log(clientError);
            throw clientError;
          }
          // If the user ticked "auto sign-in next time" in the dialog, show the
          // FedCM chooser once to bank the grant, so future page loads can
          // silently auto-login. Runs after the dialog closed (no gesture) —
          // FedCM widget-mode allows that.
          if (r.fedcm_optin && fedcmAvailable()) establishFedCMGrant();
        }

        // if either err indicates the user canceled the signin (expected) or a
        // null response was sent (unexpected), invoke the .oncancel() handler.
        if (err === 'client closed window' || !r) {
          if (options && options.oncancel) options.oncancel();
          delete options.oncancel;
        }
      });
    };

    // --- full-page redirect fallback (Arc / blocked popups) ---------------
    // The dialog runs as a top-level navigation instead of a popup; the
    // presentation returns in the URL FRAGMENT of a fresh page load and is
    // delivered through observers.login (the reason watch() is the only API).
    var REDIRECT_STASH = 'browserid_redirect';

    function b64urlJson(obj) {
      var bytes = new TextEncoder().encode(JSON.stringify(obj));
      var bin = '';
      for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
      return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }
    function b64urlParse(str) {
      var b = atob(str.replace(/-/g, '+').replace(/_/g, '/'));
      var bytes = new Uint8Array(b.length);
      for (var i = 0; i < b.length; i++) bytes[i] = b.charCodeAt(i);
      return JSON.parse(new TextDecoder().decode(bytes));
    }
    function redirectNonce() {
      var a = new Uint8Array(16);
      crypto.getRandomValues(a);
      var out = '';
      for (var i = 0; i < a.length; i++) out += ('0' + a[i].toString(16)).slice(-2);
      return out;
    }

    // Navigate this tab to the dialog. The pre-redirect URL (including any
    // SPA fragment) is stashed so the return restores it exactly; the nonce
    // binds the return to this tab (login-CSRF guard).
    function engageRedirect(options) {
      try {
        var nonce = redirectNonce();
        sessionStorage.setItem(REDIRECT_STASH, JSON.stringify({
          state: nonce,
          resumeUrl: window.location.href
        }));
        var params = {
          sboSign: !!options.sboSign,
          provisionEmail: options.provisionEmail || null,
          acceptedFallbacks: options.acceptedFallbacks || null,
          fedcm: fedcmAvailable()
        };
        window.location.assign(
          ipServer + '/dialog/dialog.html' +
          '?rp_redirect=1' +
          '&rp_origin=' + encodeURIComponent(window.location.origin) +
          '&return_to=' + encodeURIComponent(
            window.location.origin + window.location.pathname + window.location.search) +
          '&state=' + encodeURIComponent(nonce) +
          '&params=' + encodeURIComponent(b64urlJson(params))
        );
      } catch (e) {
        warn('browserid: redirect fallback failed: ' + e);
      }
    }

    // Returning from a redirect-mode dialog? Consume `#browserid=<payload>`:
    // verify the nonce, strip the fragment (restoring the pre-redirect URL),
    // and hold the presentation until watch() registers its observer.
    var pendingRedirectReturn = null;
    (function consumeRedirectReturn() {
      var h = window.location.hash;
      if (!h || h.indexOf('#browserid=') !== 0) return;
      var stored = null;
      try { stored = JSON.parse(sessionStorage.getItem(REDIRECT_STASH) || 'null'); } catch (e) { }
      try { sessionStorage.removeItem(REDIRECT_STASH); } catch (e) { }
      var payload = null;
      try { payload = b64urlParse(h.slice('#browserid='.length)); } catch (e) { }
      try {
        history.replaceState(null, '', (stored && stored.resumeUrl)
          ? stored.resumeUrl
          : window.location.pathname + window.location.search);
      } catch (e) { }
      if (!payload || !stored || !payload.state || payload.state !== stored.state) return; // forged/stale
      if (payload.cancelled || !payload.presentation) return;
      pendingRedirectReturn = payload;
    })();

    // --- FedCM fast path (browserid-ng-mhyp, device-cert model) -----------
    // FedCM is used automatically wherever the browser supports it — RPs do
    // nothing and never know FedCM was involved. It only ever ADDS a silent
    // auto-login path (opt-in per user via the dialog checkbox, server-enforced)
    // and degrades to the popup dialog everywhere else. The token FedCM returns
    // is a standard access presentation, delivered through observers.login
    // exactly like the dialog path.
    function fedcmAvailable() {
      return typeof navigator !== 'undefined' && navigator.credentials &&
        typeof navigator.credentials.get === 'function' &&
        ('IdentityCredential' in window);
    }

    // SILENT FedCM auto-reauthn (opted-in). Runs on watch() at page load — NOT
    // on the sign-in click — so it NEVER shows a chooser or any UI.
    // `mediation:'silent'` returns a token only if the browser can silently
    // auto-reauthenticate a returning user; otherwise it fails quietly and the
    // normal flow (popup dialog on the sign-in click) is unaffected.
    // We gate silent auto-login on OUR OWN per-origin flag, set only when the
    // user ticks the dialog checkbox (see establishFedCMGrant) and cleared on
    // logout — deterministic "only when the user asked".
    var FEDCM_AUTOLOGIN_KEY = 'browserid_fedcm_autologin';
    function fedcmAutologinEnabled() {
      try { return localStorage.getItem(FEDCM_AUTOLOGIN_KEY) === '1'; } catch (e) { return false; }
    }
    function setFedcmAutologin(on) {
      try { on ? localStorage.setItem(FEDCM_AUTOLOGIN_KEY, '1') : localStorage.removeItem(FEDCM_AUTOLOGIN_KEY); } catch (e) {}
    }

    function trySilentFedCM() {
      if (!fedcmAutologinEnabled()) return; // user hasn't opted in this session
      try {
        navigator.credentials.get({
          mediation: 'silent',
          identity: {
            providers: [{
              configURL: ipServer + '/fedcm/config.json',
              // Registration-free: the RP's own origin is the clientId; the
              // /fedcm/assertion endpoint uses the Origin header as the audience.
              clientId: window.location.origin,
              nonce: String(new Date().getTime())
            }]
          }
        }).then(function(cred) {
          var token = cred && cred.token;
          if (token && observers.login) {
            try { observers.login(token); } catch (clientError) { console.log(clientError); }
          }
        }).catch(function() { /* no silent session; normal flow continues */ });
      } catch (e) { /* FedCM unavailable */ }
    }

    // Show the FedCM chooser ONCE (mediation:'required') to bank the grant that
    // makes future silent auto-logins work. Called after a dialog sign-in where
    // the user opted in. The returned token is discarded — we only want the
    // grant side-effect. Widget-mode get() needs no user gesture, so this fires
    // fine from the dialog-completion callback.
    function establishFedCMGrant() {
      try {
        navigator.credentials.get({
          mediation: 'required',
          identity: {
            providers: [{
              configURL: ipServer + '/fedcm/config.json',
              clientId: window.location.origin,
              nonce: String(new Date().getTime())
            }]
          }
        }).then(function() {
          // Grant banked AND the user opted in → enable silent auto-login on
          // future page loads (until the next logout clears it).
          setFedcmAutologin(true);
        }).catch(function(e) {
          try { console.log('browserid: FedCM grant not established:', e && e.message); } catch (x) {}
        });
      } catch (e) { /* FedCM unavailable */ }
    }
    // ----------------------------------------------------------------------

    navigator.id = {
      request: function(options) {
        if (this != navigator.id)
          throw new Error("all navigator.id calls must be made on the navigator.id object");

        if (!observers.login)
          throw new Error("navigator.id.watch must be called before navigator.id.request");

        options = options || {};
        checkCompat(false);
        api_called = "request";
        // returnTo is used for post-email-verification redirect
        if (!options.returnTo) options.returnTo = document.location.pathname;
        return internalRequest(options);
      },
      watch: function(options) {
        if (this != navigator.id)
          throw new Error("all navigator.id calls must be made on the navigator.id object");
        checkCompat(false);
        internalWatch(options);
      },
      // logout from the current website
      // The callback parameter is DEPRECATED, instead you should use the
      // the .onlogout observer of the .watch() api.
      logout: function(callback) {
        if (this != navigator.id)
          throw new Error("all navigator.id calls must be made on the navigator.id object");
        // FedCM: after logout, DISABLE silent auto-login until the user signs in
        // and opts in again. The flag is re-set only by a subsequent sign-in
        // where the user re-ticks the checkbox (establishFedCMGrant).
        setFedcmAutologin(false);
        try {
          if (navigator.credentials && navigator.credentials.preventSilentAccess) {
            navigator.credentials.preventSilentAccess();
          }
        } catch (e) {}
        // Tell the SERVER to drop the silent-auto-login consent for this RP, so
        // it refuses future silent assertions until the user opts in again.
        // Fire-and-forget; the FedCM cookie (path /fedcm) identifies us.
        try {
          fetch(ipServer + '/fedcm/reset', { method: 'POST', credentials: 'include', keepalive: true })
            .catch(function () {});
        } catch (e) {}
        if (typeof callback === 'function') {
          warn('navigator.id.logout callback argument has been deprecated.');
          setTimeout(callback, 0);
        }
      },
      // get an assertion
      get: function(callback, passedOptions) {
        var opts = {};
        passedOptions = passedOptions || {};
        opts.privacyPolicy =  passedOptions.privacyPolicy || undefined;
        opts.termsOfService = passedOptions.termsOfService || undefined;
        opts.privacyURL = passedOptions.privacyURL || undefined;
        opts.tosURL = passedOptions.tosURL || undefined;
        opts.experimental_emailHint = passedOptions.experimental_emailHint || undefined;
        opts.email = passedOptions.email || undefined;
        // api_called could have been set to getVerifiedEmail already
        api_called = api_called || "get";
        if (checkDeprecated(passedOptions, "silent")) {
          // Silent has been deprecated, do nothing.  Placing the check here
          // prevents the callback from being called twice, once with null and
          // once after internalWatch has been called.  See issue #1532
          if (callback) setTimeout(function() { callback(null); }, 0);
          return;
        }

        checkCompat(true);
        internalWatch({
          onlogin: function(assertion) {
            if (callback) {
              callback(assertion);
              callback = null;
            }
          },
          onlogout: function() {},
          siteName: passedOptions.siteName,
          siteLogo: passedOptions.siteLogo,
          backgroundColor: passedOptions.backgroundColor
        });
        opts.oncancel = function() {
          if (callback) {
            callback(null);
            callback = null;
          }
          observers.login = observers.logout = observers.match = observers.ready = null;
        };
        internalRequest(opts);
      },
      // backwards compatibility with old API
      getVerifiedEmail: function(callback) {
        warn("navigator.id.getVerifiedEmail has been deprecated");
        checkCompat(true);
        api_called = "getVerifiedEmail";
        navigator.id.get(callback);
      },
      // _shimmed was originally required in April 2011 (79d3119db036725c5b51a305758a7816fdc8920a)
      // so we could deal with firefox behavior - which was in certain reload scenarios to caching
      // properties on navigator.id.  The effect would be upon reload-via back/forward,
      // navigator.id would be populated with the previous sessions stale object, and thus
      // the shim would not be properly inserted.
      _shimmed: true
    };

  }
  }());
  }
}());
