// Fallback-IdP provisioning page (apgv). Same primary-IdP protocol a real
// primary uses (provisioning_api.js):
//   beginProvisioning -> the email to provision
//   genKeyPair        -> the DIALOG generates the keypair, hands us the pubkey
//                        (the private key never leaves the mediator's origin)
// We sign it via /cert_key, gated on the SMTP-established email cookie. No
// cookie -> /cert_key 401s -> raiseProvisioningFailure -> the dialog opens the
// interactive /auth page for the SMTP dance.
(function () {
  "use strict";

  function fail(reason) {
    navigator.id.raiseProvisioningFailure(String(reason || "provisioning failed"));
  }

  navigator.id.beginProvisioning(function (email /*, certDuration */) {
    if (!email) return fail("no email to provision");

    navigator.id.genKeyPair(function (publicKey) {
      var pk;
      try {
        pk = typeof publicKey === "string" ? JSON.parse(publicKey) : publicKey;
      } catch (e) {
        return fail("bad keypair: " + e);
      }

      fetch("/cert_key", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email, pubkey: pk }),
      })
        .then(function (r) {
          if (r.status === 401 || r.status === 403) {
            // No valid SMTP session for this email — drop to interactive /auth.
            return fail("authentication required");
          }
          if (!r.ok) {
            return r.text().then(function (t) {
              throw new Error("cert_key " + r.status + " " + t);
            });
          }
          return r.json().then(function (res) {
            navigator.id.registerCertificate(res.cert);
          });
        })
        .catch(fail);
    });
  });
})();
