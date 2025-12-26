/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Takes care of providing jwcrypto
 *
 * BrowserID-NG: Uses jwcrypto-compat.js (Web Crypto API + Ed25519)
 * instead of the original jwcrypto (DSA/RSA).
 */

BrowserID.CryptoLoader = (function() {
  "use strict";

  var bid = BrowserID,
      network = bid.Network;

  // The jwcrypto shim is loaded synchronously via script tag,
  // so it should already be available on window.jwcrypto
  var jwCrypto = null;

  var Module = {
    /**
     * Load JWCrypto. Since we use the synchronously-loaded shim,
     * this just ensures network context is available (for server time)
     * and then calls the callback.
     *
     * @method load
     */
    load: function(onSuccess, onFailure) {
      // Lazy-load reference to jwcrypto (it may not be on window yet when this module loads)
      if (!jwCrypto) {
        jwCrypto = window.jwcrypto;
      }

      if (!jwCrypto) {
        // Shim not loaded - this shouldn't happen if scripts are included correctly
        if (onFailure) {
          onFailure('jwcrypto-compat.js not loaded');
        }
        return;
      }

      // Ensure we have network context before proceeding
      // (original code used this to seed the random number generator)
      network.withContext(function(context) {
        onSuccess(jwCrypto);
      }, onFailure);
    }
  };

  return Module;
}());
