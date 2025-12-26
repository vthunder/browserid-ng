/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * jwcrypto compatibility shim
 *
 * Provides the same API as the original jwcrypto library but uses
 * Web Crypto API with Ed25519 instead of DSA/RSA.
 */

(function(exports) {
  "use strict";

  // Base64URL encoding/decoding
  function base64urlEncode(buffer) {
    var bytes = new Uint8Array(buffer);
    var binary = '';
    for (var i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary)
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  function base64urlDecode(str) {
    // Add padding if needed
    var padding = str.length % 4;
    if (padding) {
      str += '='.repeat(4 - padding);
    }
    var binary = atob(str.replace(/-/g, '+').replace(/_/g, '/'));
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  // PublicKey wrapper
  function PublicKey(cryptoKey, jwk) {
    this._cryptoKey = cryptoKey;
    this._jwk = jwk;
  }

  PublicKey.prototype.serialize = function() {
    // Return JWK format that server expects
    return JSON.stringify({
      algorithm: 'Ed25519',
      publicKey: this._jwk.x
    });
  };

  PublicKey.prototype.toSimpleObject = function() {
    return {
      algorithm: 'Ed25519',
      x: this._jwk.x
    };
  };

  // SecretKey wrapper
  function SecretKey(cryptoKey, jwk) {
    this._cryptoKey = cryptoKey;
    this._jwk = jwk;
  }

  SecretKey.prototype.toSimpleObject = function() {
    return {
      algorithm: 'Ed25519',
      d: this._jwk.d,
      x: this._jwk.x
    };
  };

  SecretKey.prototype.sign = function(message, callback) {
    var encoder = new TextEncoder();
    var data = encoder.encode(message);

    crypto.subtle.sign(
      { name: 'Ed25519' },
      this._cryptoKey,
      data
    ).then(function(signature) {
      callback(null, base64urlEncode(signature));
    }).catch(function(err) {
      callback(err);
    });
  };

  // Keypair wrapper
  function Keypair(publicKey, secretKey) {
    this.publicKey = publicKey;
    this.secretKey = secretKey;
  }

  // Main jwcrypto API
  var jwcrypto = {
    // Generate a new keypair
    // Original: {algorithm: "DS", keysize: 256}
    // We use Ed25519 regardless of what's requested
    generateKeypair: function(options, callback) {
      crypto.subtle.generateKey(
        { name: 'Ed25519' },
        true, // extractable
        ['sign', 'verify']
      ).then(function(keyPair) {
        // Export both keys to JWK for serialization
        return Promise.all([
          crypto.subtle.exportKey('jwk', keyPair.publicKey),
          crypto.subtle.exportKey('jwk', keyPair.privateKey)
        ]).then(function(jwks) {
          var pubJwk = jwks[0];
          var privJwk = jwks[1];

          var publicKey = new PublicKey(keyPair.publicKey, pubJwk);
          var secretKey = new SecretKey(keyPair.privateKey, privJwk);
          var keypair = new Keypair(publicKey, secretKey);

          callback(null, keypair);
        });
      }).catch(function(err) {
        callback(err);
      });
    },

    // Load a public key from a simple object
    loadPublicKeyFromObject: function(obj) {
      // For validation purposes, just return the object wrapped
      // Full crypto validation would require async, but this is used synchronously
      return {
        _obj: obj,
        algorithm: obj.algorithm || 'Ed25519'
      };
    },

    // Load a secret key from a simple object (async version for actual use)
    loadSecretKeyFromObject: function(obj) {
      // Return a wrapper that can sign
      // The actual CryptoKey will be created on first use
      var secretKey = {
        _obj: obj,
        _cryptoKey: null,
        sign: function(message, callback) {
          var self = this;

          // Import the key if not already done
          if (self._cryptoKey) {
            doSign(self._cryptoKey);
          } else {
            var jwk = {
              kty: 'OKP',
              crv: 'Ed25519',
              d: obj.d,
              x: obj.x
            };

            crypto.subtle.importKey(
              'jwk',
              jwk,
              { name: 'Ed25519' },
              false,
              ['sign']
            ).then(function(cryptoKey) {
              self._cryptoKey = cryptoKey;
              doSign(cryptoKey);
            }).catch(function(err) {
              callback(err);
            });
          }

          function doSign(cryptoKey) {
            var encoder = new TextEncoder();
            var data = encoder.encode(message);

            crypto.subtle.sign(
              { name: 'Ed25519' },
              cryptoKey,
              data
            ).then(function(signature) {
              callback(null, base64urlEncode(signature));
            }).catch(function(err) {
              callback(err);
            });
          }
        }
      };

      return secretKey;
    },

    // Add entropy - no-op since Web Crypto handles this
    addEntropy: function(seed) {
      // Web Crypto API handles entropy internally
    },

    // Extract components from a JWT
    extractComponents: function(jwt) {
      var parts = jwt.split('.');
      if (parts.length < 2) {
        throw new Error('Invalid JWT format');
      }

      var header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
      var payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));

      return {
        header: header,
        payload: payload,
        signature: parts[2] || null
      };
    },

    // Assertion signing
    assertion: {
      sign: function(userAssertedClaims, options, secretKey, callback) {
        var header = { alg: 'EdDSA', typ: 'JWT' };
        var payload = Object.assign({}, userAssertedClaims, {
          aud: options.audience,
          exp: options.expiresAt.getTime()
        });

        var headerB64 = base64urlEncode(new TextEncoder().encode(JSON.stringify(header)));
        var payloadB64 = base64urlEncode(new TextEncoder().encode(JSON.stringify(payload)));
        var message = headerB64 + '.' + payloadB64;

        secretKey.sign(message, function(err, signature) {
          if (err) return callback(err);
          callback(null, message + '.' + signature);
        });
      }
    },

    // Certificate bundling
    cert: {
      bundle: function(certs, signedAssertion) {
        // Format: cert1~cert2~...~assertion
        return certs.concat([signedAssertion]).join('~');
      }
    }
  };

  // Export
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = jwcrypto;
  } else {
    exports.jwcrypto = jwcrypto;
  }

})(typeof window !== 'undefined' ? window : this);
