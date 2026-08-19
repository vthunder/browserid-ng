//! Bridge-delegated E2 minting (browserid-ng-pr3a, epic shyj): a completed
//! bridge proof records a single-use grant that /device/issue redeems for the
//! delegated (E2) mint, with the cert TTL decided by the BRIDGE (~1wk
//! default) rather than the broker's 90-day constant. The handle-claim bridge
//! is driven for real (forged attestor key); the same record/redeem seam
//! serves the OIDC bridge.

mod common;

use browserid_broker::store::{EmailType, ProofMethod, UserStore};
use browserid_core::device::DeviceCert;
use browserid_core::{HandleAttestation, KeyPair};
use common::{create_test_context_customized, get_csrf, TestContext};
use serde_json::{json, Value};

const ATTESTOR: &str = "bsky.browserid.test";
const BROKER: &str = "localhost:3000";

fn context(attestor_key: &KeyPair) -> TestContext {
    let public = attestor_key.public_key();
    create_test_context_customized(move |state| {
        state.handle_attestor = Some(ATTESTOR.to_string());
        state.handle_attestor_key_override = Some(public);
    })
}

fn attest(key: &KeyPair, handle: &str, did: &str) -> String {
    HandleAttestation::create(ATTESTOR, BROKER, handle, did, key)
        .unwrap()
        .encoded()
        .to_string()
}

async fn device_issue(ctx: &TestContext, session: &str, email: &str) -> (u16, Value) {
    let csrf = get_csrf(&ctx.server, session).await;
    let response = ctx
        .server
        .post("/device/issue")
        .add_cookie(cookie::Cookie::new(
            "browserid_session",
            session.to_string(),
        ))
        .json(&json!({
            "csrf": csrf,
            "email": email,
            "device_pubkey": KeyPair::generate().public_key().to_base64(),
            "config_pubkey": KeyPair::generate().public_key().to_base64(),
        }))
        .await;
    (response.status_code().as_u16(), response.json())
}

/// The full delegated-mint round trip: bridge proof → grant → one mint whose
/// TTL is the bridge's (~7d, not the broker's 90d) → a second mint without a
/// fresh proof is refused (single-use).
#[tokio::test]
async fn bridge_proof_grants_one_mint_with_bridge_ttl() {
    let key = KeyPair::generate();
    let ctx = context(&key);
    let email = "me@dan.bsky.social";

    // Cold handle claim: attaches the E2 identity, signs in (lightweight),
    // and records the live bridge grant.
    let resp = ctx
        .server
        .post("/wsapi/complete_handle_claim")
        .json(&json!({
            "email": email,
            "attestation": attest(&key, "dan.bsky.social", "did:plc:dan"),
        }))
        .await;
    assert_eq!(resp.status_code(), 200);
    let session = resp
        .maybe_cookie("browserid_session")
        .expect("claim signs in")
        .value()
        .to_string();

    // The mint rides the fresh proof — no password, no full session needed
    // (invariant 1/3: the bridge is the voucher, the level is irrelevant).
    let (status, body) = device_issue(&ctx, &session, email).await;
    assert_eq!(status, 200, "{body}");
    let cert = DeviceCert::parse(body["device_cert"].as_str().unwrap()).unwrap();
    assert_eq!(
        cert.claims().prov.as_deref(),
        Some("atproto"),
        "E2 cert is stamped with its bridge class (kts0)"
    );
    let ttl_secs = cert.claims().exp - cert.claims().iat;
    assert_eq!(
        ttl_secs,
        7 * 24 * 3600,
        "E2 cert TTL must be the bridge's decision (~1wk), not the broker's 90d"
    );

    // The grant was consumed: a second issuance without a fresh bridge proof
    // is refused, full stop.
    let (status, body) = device_issue(&ctx, &session, email).await;
    assert_eq!(status, 403, "{body}");
    assert!(
        body["reason"]
            .as_str()
            .unwrap()
            .contains("live bridge proof"),
        "{body}"
    );

    // Re-running the bridge re-arms exactly one more mint.
    let resp = ctx
        .server
        .post("/wsapi/complete_handle_claim")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({
            "email": email,
            "attestation": attest(&key, "dan.bsky.social", "did:plc:dan"),
            "csrf": get_csrf(&ctx.server, &session).await,
        }))
        .await;
    assert_eq!(resp.status_code(), 200);
    let (status, body) = device_issue(&ctx, &session, email).await;
    assert_eq!(status, 200, "{body}");
}

/// A grant is scoped to the exact (account, email) the bridge proved — it
/// must not unlock a mint for a DIFFERENT E2 address on the same account.
#[tokio::test]
async fn bridge_grant_is_per_email() {
    let key = KeyPair::generate();
    let ctx = context(&key);
    let proven = "me@dan.bsky.social";

    let resp = ctx
        .server
        .post("/wsapi/complete_handle_claim")
        .json(&json!({
            "email": proven,
            "attestation": attest(&key, "dan.bsky.social", "did:plc:dan"),
        }))
        .await;
    assert_eq!(resp.status_code(), 200);
    let session = resp
        .maybe_cookie("browserid_session")
        .unwrap()
        .value()
        .to_string();

    // Another E2 (oidc-proven) address on the same account, NOT just proven.
    let user = ctx.user_store.get_user_by_email(proven).unwrap().unwrap();
    ctx.user_store
        .add_email_with_type(user.id, "other@example.com", true, EmailType::Secondary)
        .unwrap();
    ctx.user_store
        .set_email_proof("other@example.com", ProofMethod::Oidc, Some("s"))
        .unwrap();

    let (status, body) = device_issue(&ctx, &session, "other@example.com").await;
    assert_eq!(status, 403, "{body}");

    // The proven address itself still mints.
    let (status, body) = device_issue(&ctx, &session, proven).await;
    assert_eq!(status, 200, "{body}");
}
