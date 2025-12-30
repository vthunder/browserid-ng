/*
 * BrowserID Provisioning Module
 * Handles hidden iframe communication with primary IdP provisioning pages
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

(function(global) {
  'use strict';

  const Provisioning = {
    _iframe: null,
    _iframeOrigin: null,
    _pendingCallbacks: {},
    _callId: 0,
    _onSuccess: null,
    _onFailure: null,
    _email: null,
    _keypair: null,
    _timeout: null,

    /**
     * Attempt to provision a certificate from a primary IdP
     * @param {string} provisioningUrl - The IdP's provisioning endpoint
     * @param {string} email - The email to provision
     * @param {function} onSuccess - Called with {certificate, keypair} on success
     * @param {function} onFailure - Called with reason on failure
     */
    start: function(provisioningUrl, email, onSuccess, onFailure) {
      this._onSuccess = onSuccess;
      this._onFailure = onFailure;
      this._email = email;

      // Determine origin from URL
      const url = new URL(provisioningUrl);
      this._iframeOrigin = url.origin;

      // Create hidden iframe
      this._cleanup();
      this._iframe = document.createElement('iframe');
      this._iframe.style.display = 'none';
      this._iframe.src = provisioningUrl;
      document.body.appendChild(this._iframe);

      // Set timeout for provisioning
      this._timeout = setTimeout(() => {
        this._cleanup();
        onFailure('Provisioning timeout');
      }, 30000); // 30 second timeout
    },

    /**
     * Handle messages from provisioning iframe
     */
    handleMessage: function(event) {
      if (!this._iframe || event.source !== this._iframe.contentWindow) {
        return;
      }

      if (event.origin !== this._iframeOrigin) {
        return;
      }

      const data = event.data;
      if (!data || data.type !== 'browserid:provisioning') {
        return;
      }

      switch (data.method) {
        case 'beginProvisioning':
          // Respond with email and duration
          this._respond(data.id, {
            email: this._email,
            cert_duration_s: 24 * 60 * 60  // 24 hours
          });
          break;

        case 'genKeyPair':
          // Generate keypair and return public key
          this._generateKeyPair().then(keypair => {
            this._keypair = keypair;
            this._respond(data.id, { publicKey: keypair.publicKeyJson });
          }).catch(err => {
            this._fail('Key generation failed: ' + err.message);
          });
          break;

        case 'registerCertificate':
          // Success! Store certificate and notify
          clearTimeout(this._timeout);
          const cert = data.data.certificate;
          if (this._onSuccess) {
            this._onSuccess({
              certificate: cert,
              keypair: this._keypair
            });
          }
          this._cleanup();
          break;

        case 'raiseProvisioningFailure':
          // Provisioning failed
          clearTimeout(this._timeout);
          if (this._onFailure) {
            this._onFailure(data.data.reason || 'Provisioning failed');
          }
          this._cleanup();
          break;
      }
    },

    /**
     * Send response back to iframe
     */
    _respond: function(id, result) {
      if (this._iframe && this._iframe.contentWindow) {
        this._iframe.contentWindow.postMessage({
          type: 'browserid:provisioning:response',
          id: id,
          result: result
        }, this._iframeOrigin);
      }
    },

    /**
     * Generate Ed25519 keypair
     */
    _generateKeyPair: async function() {
      const keyPair = await crypto.subtle.generateKey(
        { name: 'Ed25519' },
        true,
        ['sign', 'verify']
      );

      const publicKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
      const privateKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);

      return {
        publicKey: keyPair.publicKey,
        privateKey: keyPair.privateKey,
        publicKeyJson: JSON.stringify({
          algorithm: 'Ed25519',
          publicKey: publicKeyJwk.x
        }),
        publicKeyJwk: publicKeyJwk,
        privateKeyJwk: privateKeyJwk
      };
    },

    /**
     * Clean up iframe and state
     */
    _cleanup: function() {
      if (this._iframe) {
        this._iframe.remove();
        this._iframe = null;
      }
      this._iframeOrigin = null;
      this._keypair = null;
      this._email = null;
      if (this._timeout) {
        clearTimeout(this._timeout);
        this._timeout = null;
      }
    },

    _fail: function(reason) {
      clearTimeout(this._timeout);
      if (this._onFailure) {
        this._onFailure(reason);
      }
      this._cleanup();
    }
  };

  // Listen for messages
  window.addEventListener('message', function(event) {
    Provisioning.handleMessage(event);
  });

  global.BrowserID = global.BrowserID || {};
  global.BrowserID.Provisioning = Provisioning;

})(window);
