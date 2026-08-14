//! /.well-known/browserid endpoint

use std::sync::Arc;

use axum::extract::State;
use axum::Json;

use browserid_core::discovery::SupportDocument;

use crate::email::EmailSender;
use crate::state::AppState;
use crate::store::{SessionStore, UserStore};

/// GET /.well-known/browserid
///
/// Host-aware: when the request arrives on the hosted-primary IdP host (what
/// tenants name in their DNSSEC `host=`, bean g5qt), serve the tenant §7
/// support document — no key (each tenant's key lives in its own DNS record),
/// pointing at the `/idp/*` surface. Otherwise serve the broker's own doc.
pub async fn get_support_document<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    headers: axum::http::HeaderMap,
) -> Json<SupportDocument>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let host = headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    // The idp host differs from the broker's own domain only when a dedicated
    // origin is configured; when they coincide the broker doc wins (a hosted
    // primary then shares the origin, which is fine locally/in tests).
    if !state.idp_host.eq_ignore_ascii_case(&state.domain)
        && host.eq_ignore_ascii_case(&state.idp_host)
    {
        return Json(super::hosted_idp::tenant_support_document());
    }

    let mut doc = SupportDocument::new(state.keypair.public_key())
        .with_authentication("/auth")
        .with_provisioning("/provision")
        // Device-cert conformance: browser device issuance rides the fallback
        // SMTP surface; the mint is headless (device cert = the credential).
        .with_device_cert("/auth/device_cert")
        .with_access_cert("/access/mint");
    // Admission-record flows (spec §7.5): the support advertisement resources
    // capability-detect before using the credential-less connection lane.
    // Advertised only when the consent surface is on.
    if state.agent_provisioning_enabled {
        doc = doc.with_record_grants("/warrant/record-request");
    }

    // The support document carries NO key (spec §3/§3.1, bean zexp): an IdP's
    // identity key comes solely from the authenticated `_browserid` DNSSEC
    // record. Serving an advisory key here is a downgrade vector for any
    // verifier that reads it instead of DNS — exactly what bean 0p5f closed
    // across our verifiers. The struct field stays (the DNSSEC resolver fills
    // it in from the record); we simply do not advertise one.
    doc.public_key = None;

    Json(doc)
}
