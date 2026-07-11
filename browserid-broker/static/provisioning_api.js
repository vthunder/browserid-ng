/*
 * BrowserID Provisioning API Shim
 * Include this on your primary IdP's provisioning page
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

(function() {
  'use strict';

  if (typeof navigator.id === 'undefined') {
    navigator.id = {};
  }

  // The only party we may exchange provisioning messages with is the broker
  // dialog that embedded this page. Pin its origin so we neither broadcast
  // requests/certificates to arbitrary parents nor accept forged responses:
  // without this, a page that frames a signed-in IdP could post a fake
  // beginProvisioning response with an attacker-chosen email + pubkey and drive
  // the IdP into signing a cert for it (cert forgery).
  //
  // ancestorOrigins[0] (Blink/WebKit) is the browser-set, unforgeable origin of
  // the immediate parent. Firefox lacks it, so fall back to the referrer the
  // browser attached to this subframe. Either way we ALSO require the inbound
  // message's source to be window.parent, which no third-party window can spoof.
  const PARENT_ORIGIN = (function() {
    try {
      const ao = window.location.ancestorOrigins;
      if (ao && ao.length) return ao[0];
    } catch (e) {}
    try {
      if (document.referrer) return new URL(document.referrer).origin;
    } catch (e) {}
    return null; // unknown → target '*' but still gate inbound on source
  })();

  const targetOrigin = PARENT_ORIGIN || '*';

  // Simple postMessage channel to parent (broker dialog)
  const channel = {
    _callbacks: {},
    _callId: 0,

    call: function(method, callback) {
      const id = ++this._callId;
      this._callbacks[id] = callback;
      window.parent.postMessage({
        type: 'browserid:provisioning',
        method: method,
        id: id
      }, targetOrigin);
    },

    notify: function(method, data) {
      window.parent.postMessage({
        type: 'browserid:provisioning',
        method: method,
        data: data
      }, targetOrigin);
    }
  };

  // Handle responses from parent. Accept them ONLY from the embedding broker:
  // the message must come from the parent frame itself, and (when we could pin
  // it) from the expected origin.
  window.addEventListener('message', function(event) {
    if (event.source !== window.parent) return;
    if (PARENT_ORIGIN && event.origin !== PARENT_ORIGIN) return;
    if (event.data && event.data.type === 'browserid:provisioning:response') {
      const callback = channel._callbacks[event.data.id];
      if (callback) {
        delete channel._callbacks[event.data.id];
        callback(event.data.result);
      }
    }
  });

  navigator.id.beginProvisioning = function(callback) {
    channel.call('beginProvisioning', function(params) {
      callback(params.email, params.cert_duration_s);
    });
  };

  navigator.id.genKeyPair = function(callback) {
    channel.call('genKeyPair', function(result) {
      callback(result.publicKey);
    });
  };

  // `metadata` (optional): private IdP-supplied provisioning metadata forwarded
  // to the dialog over this same-broker channel (NEVER placed in the cert, which
  // is public in assertions). Extensible object; e.g. { subordinate_to } marks a
  // derived identity's controlling parent (mingo-cm8z).
  navigator.id.registerCertificate = function(certificate, metadata) {
    channel.notify('registerCertificate', {
      certificate: certificate,
      metadata: metadata || null
    });
  };

  navigator.id.raiseProvisioningFailure = function(reason) {
    channel.notify('raiseProvisioningFailure', { reason: reason });
  };
})();
