/**
 * BrowserID-NG include.js — device-cert model.
 *
 * Include this script to get the `browserid` RP API:
 *
 *   const { presentation, email } = await browserid.login({
 *     acceptedFallbacks: ['browserid.me'],   // optional (default: the broker)
 *     email: 'hint@example.com'              // optional identity hint
 *   });
 *
 * `presentation` is the 4-object device-model bundle
 * `access_cert~assertion~warrant~config_cert`; POST it to your verifier (e.g.
 * the broker's /verify-access with your audience) or verify it yourself.
 * Call login() from a click handler — it opens the sign-in popup.
 *
 * Rejects with err.cancelled === true when the user closes/cancels the dialog.
 *
 * Configure the broker URL via:
 *   - data-browserid-url attribute on the script tag
 *   - window.BROWSERID_URL global
 *   - defaults to the origin this script was loaded from
 */
(function () {
  'use strict';

  /* ------------------------------------------------------------------ *
   * WinChan (Mozilla Persona, MPL 2.0) — durable popup + postMessage
   * channel with close detection and an IE relay-iframe fallback.
   * ------------------------------------------------------------------ */
  var WinChan = (function() {
    var RELAY_FRAME_NAME = "__winchan_relay_frame";
    var CLOSE_CMD = "die";

    function addListener(w, event, cb) {
      if (w.attachEvent) w.attachEvent('on' + event, cb);
      else if (w.addEventListener) w.addEventListener(event, cb, false);
    }
    function removeListener(w, event, cb) {
      if (w.detachEvent) w.detachEvent('on' + event, cb);
      else if (w.removeEventListener) w.removeEventListener(event, cb, false);
    }

    function isInternetExplorer() {
      var rv = -1;
      var ua = navigator.userAgent;
      if (navigator.appName === 'Microsoft Internet Explorer') {
        var re = new RegExp("MSIE ([0-9]{1,}[\\.0-9]{0,})");
        if (re.exec(ua) != null) rv = parseFloat(RegExp.$1);
      } else if (ua.indexOf("Trident") > -1) {
        var re2 = new RegExp("rv:([0-9]{2,2}[\\.0-9]{0,})");
        if (re2.exec(ua) !== null) rv = parseFloat(RegExp.$1);
      }
      return rv >= 8;
    }

    function isSupported() {
      return (window.JSON && window.JSON.stringify &&
              window.JSON.parse && window.postMessage);
    }

    function extractOrigin(url) {
      if (!/^https?:\/\//.test(url)) url = window.location.href;
      var m = /^(https?:\/\/[\-_a-zA-Z\.0-9:]+)/.exec(url);
      if (m) return m[1];
      return url;
    }

    var isIE = isInternetExplorer();

    if (!isSupported()) {
      return {
        open: function (opts, cb) {
          setTimeout(function () { cb('unsupported browser'); }, 0);
        }
      };
    }

    return {
      open: function(opts, cb) {
        if (!cb) throw "missing required callback argument";

        var err;
        if (!opts.url) err = "missing required 'url' parameter";
        if (!opts.relay_url) err = "missing required 'relay_url' parameter";
        if (err) setTimeout(function() { cb(err); }, 0);

        if (!opts.window_name) opts.window_name = null;

        var iframe;

        var origin = extractOrigin(opts.url);
        if (origin !== extractOrigin(opts.relay_url)) {
          return setTimeout(function() {
            cb('invalid arguments: origin of url and relay_url must match');
          }, 0);
        }

        var messageTarget;

        if (isIE) {
          iframe = document.createElement("iframe");
          iframe.setAttribute('src', opts.relay_url);
          iframe.style.display = "none";
          iframe.setAttribute('name', RELAY_FRAME_NAME);
          document.body.appendChild(iframe);
          messageTarget = iframe.contentWindow;
        }

        var w = window.open(opts.url, opts.window_name, opts.window_features);

        // Popup blocked: report it async so the caller's callback runs and the
        // login promise rejects instead of hanging forever.
        if (!w) {
          if (cb) setTimeout(function() { cb('popup blocked'); cb = null; }, 0);
          return { close: function() {}, focus: function() {} };
        }

        if (!messageTarget) messageTarget = w;

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
            if (d.a === 'ready') messageTarget.postMessage(req, origin);
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
          } catch(err2) { }
        }

        addListener(window, 'message', onMessage);

        return {
          close: cleanup,
          focus: function() {
            if (w) {
              try { w.focus(); } catch (e) { /* IE7 */ }
            }
          }
        };
      }
    };
  })();

  /* ------------------------------------------------------------------ *
   * The RP API.
   * ------------------------------------------------------------------ */

  // Broker origin: data attribute > global > the origin this script came from.
  var brokerUrl = (function () {
    if (window.BROWSERID_URL) return window.BROWSERID_URL;
    var scripts = document.getElementsByTagName('script');
    for (var i = 0; i < scripts.length; i++) {
      var src = scripts[i].src || '';
      if (src.indexOf('include.js') !== -1) {
        var url = scripts[i].getAttribute('data-browserid-url');
        if (url) return url;
        var match = src.match(/^(https?:\/\/[^\/]+)/);
        if (match) return match[1];
      }
    }
    return window.location.protocol + '//' + window.location.host;
  })();

  var WINDOW_NAME = '__browserid_dialog';
  var WINDOW_FEATURES =
    'menubar=0,location=1,resizable=1,scrollbars=1,status=0,width=480,height=660';

  var activeDialog = null;

  /**
   * Open the sign-in dialog. Resolves {presentation, email}; rejects with
   * err.cancelled === true on user cancel, or a descriptive Error otherwise.
   */
  function login(options) {
    options = options || {};
    return new Promise(function (resolve, reject) {
      if (activeDialog) {
        activeDialog.focus();
        reject(cancelError('a sign-in dialog is already open'));
        return;
      }
      activeDialog = WinChan.open({
        url: brokerUrl + '/dialog/dialog.html',
        relay_url: brokerUrl + '/relay',
        window_features: WINDOW_FEATURES,
        window_name: WINDOW_NAME,
        params: {
          params: {
            acceptedFallbacks: options.acceptedFallbacks || null,
            // Sign in / provision a SPECIFIC identity (skips the chooser).
            provisionEmail: options.provisionEmail || options.email || null,
            // Request the SBO typed-signing capability (consent-gated).
            sboSign: !!options.sboSign
          }
        }
      }, function (err, r) {
        activeDialog = null;
        if (err === 'client closed window' || err === 'unknown closed window') {
          reject(cancelError('sign-in was cancelled'));
        } else if (err) {
          reject(new Error(String(err)));
        } else if (!r || !r.presentation) {
          reject(cancelError((r && r.cancelled) ? 'sign-in was cancelled' : 'no presentation returned'));
        } else {
          resolve({ presentation: r.presentation, email: r.email || null });
        }
      });
    });
  }

  function cancelError(message) {
    var e = new Error(message);
    e.cancelled = true;
    return e;
  }

  window.browserid = {
    login: login,
    brokerUrl: brokerUrl
  };
})();
