//! Audience-proof fetching (spec §7.5): the broker-side implementation of the
//! registrar's [`browserid_registrar::AudienceProofFetcher`].
//!
//! A record request (connection grant / authoring ceremony) is authenticated
//! by **proof of audience control**: the resource publishes the challenge
//! nonce at `https://<audience-origin>/.well-known/browserid-audience-proof/
//! <request_id>`, and the broker fetches it before the consent page renders.
//! The URL's origin comes from an attacker-authored audience string, so the
//! fetch runs under the same SSRF discipline as foreign status lists
//! (audit H1): TLS required, redirects refused, every resolved address must
//! be public unicast, short timeout, small body cap — fail-closed.

use browserid_registrar::RegistrarError;

/// Max bytes read from a proof document. The body is one nonce (~32 b64url
/// chars) plus optional trailing whitespace; 4 KiB is generous.
const MAX_PROOF_BODY: usize = 4096;

pub struct BrokerProofFetcher {
    /// Relax the SSRF guard (permit `http` and private/loopback hosts) —
    /// MUST be `false` in production; `true` only for localhost dev/tests.
    pub allow_private: bool,
}

impl browserid_registrar::AudienceProofFetcher for BrokerProofFetcher {
    fn fetch_proof<'a>(
        &'a self,
        origin: &'a str,
        request_id: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<String, RegistrarError>> + Send + 'a>,
    > {
        Box::pin(async move {
            let url = format!("{origin}/.well-known/browserid-audience-proof/{request_id}");
            let err = |e: String| {
                RegistrarError::ValidationError(format!("audience proof fetch failed: {e}"))
            };
            crate::verifier::validate_status_url(&url, self.allow_private)
                .await
                .map_err(err)?;
            let resp = crate::verifier::status_http()
                .get(&url)
                .send()
                .await
                .and_then(|r| r.error_for_status())
                .map_err(|e| err(e.to_string()))?;
            crate::verifier::read_capped(resp, MAX_PROOF_BODY).await.map_err(err)
        })
    }
}
