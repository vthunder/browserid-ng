//! `complete_handle_claim` (browserid-ng-tsqk, bean 77mw): the broker
//! consumes the bridge's signed handle attestation and attaches
//! `<label>@<handle>` as a verified identity with proof method `atproto`.

mod common;

use browserid_core::{HandleAttestation, KeyPair};
use browserid_broker::store::ProofMethod;
use browserid_broker::UserStore;
use common::{create_test_context_customized, create_user, get_csrf, TestContext};
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

#[tokio::test]
async fn a_cold_claim_creates_an_account_and_signs_in() {
    let key = KeyPair::generate();
    let ctx = context(&key);

    let resp = ctx
        .server
        .post("/wsapi/complete_handle_claim")
        .json(&json!({
            "email": "Me@Dan.BSky.Social",
            "attestation": attest(&key, "dan.bsky.social", "did:plc:dan"),
        }))
        .await;
    assert_eq!(resp.status_code(), 200);
    let body: Value = resp.json();
    assert_eq!(body["success"], true);
    assert_eq!(body["email"], "me@dan.bsky.social");
    // The claim ends signed in, like completing an email verification.
    assert!(resp.maybe_cookie("browserid_session").is_some());

    let rec = ctx.user_store.get_email("me@dan.bsky.social").unwrap().unwrap();
    assert!(rec.verified);
    assert_eq!(rec.proof, ProofMethod::Atproto);
    assert_eq!(rec.proof_subject.as_deref(), Some("did:plc:dan"));
}

/// The scope asymmetry: the attestation proves the whole domain, so any
/// label attaches — but only at exactly the attested handle.
#[tokio::test]
async fn any_label_at_the_proven_handle_but_only_that_handle() {
    let key = KeyPair::generate();
    let ctx = context(&key);

    let resp = ctx
        .server
        .post("/wsapi/complete_handle_claim")
        .json(&json!({
            "email": "claude@dan.bsky.social",
            "attestation": attest(&key, "dan.bsky.social", "did:plc:dan"),
        }))
        .await;
    assert_eq!(resp.status_code(), 200);

    // A different domain under the same attestation: refused.
    let resp = ctx
        .server
        .post("/wsapi/complete_handle_claim")
        .json(&json!({
            "email": "me@other.example",
            "attestation": attest(&key, "dan.bsky.social", "did:plc:dan"),
        }))
        .await;
    assert_eq!(resp.status_code(), 400);
    assert!(ctx.user_store.get_email("me@other.example").unwrap().is_none());
}

#[tokio::test]
async fn forged_and_misdirected_attestations_are_refused() {
    let key = KeyPair::generate();
    let ctx = context(&key);

    // Signed by the wrong key.
    let wrong_key = KeyPair::generate();
    let resp = ctx
        .server
        .post("/wsapi/complete_handle_claim")
        .json(&json!({
            "email": "me@dan.bsky.social",
            "attestation": attest(&wrong_key, "dan.bsky.social", "did:plc:dan"),
        }))
        .await;
    assert_eq!(resp.status_code(), 400);

    // Addressed to a different broker.
    let misdirected = HandleAttestation::create(
        ATTESTOR,
        "other-broker.example",
        "dan.bsky.social",
        "did:plc:dan",
        &key,
    )
    .unwrap();
    let resp = ctx
        .server
        .post("/wsapi/complete_handle_claim")
        .json(&json!({
            "email": "me@dan.bsky.social",
            "attestation": misdirected.encoded(),
        }))
        .await;
    assert_eq!(resp.status_code(), 400);

    // From an issuer this broker does not trust.
    let foreign = HandleAttestation::create(
        "someone-else.example",
        BROKER,
        "dan.bsky.social",
        "did:plc:dan",
        &key,
    )
    .unwrap();
    let resp = ctx
        .server
        .post("/wsapi/complete_handle_claim")
        .json(&json!({
            "email": "me@dan.bsky.social",
            "attestation": foreign.encoded(),
        }))
        .await;
    assert_eq!(resp.status_code(), 400);

    assert!(ctx.user_store.get_email("me@dan.bsky.social").unwrap().is_none());
}

#[tokio::test]
async fn an_attestation_redeems_exactly_once() {
    let key = KeyPair::generate();
    let ctx = context(&key);
    let attestation = attest(&key, "dan.bsky.social", "did:plc:dan");

    let first = ctx
        .server
        .post("/wsapi/complete_handle_claim")
        .json(&json!({ "email": "me@dan.bsky.social", "attestation": attestation }))
        .await;
    assert_eq!(first.status_code(), 200);

    let replay = ctx
        .server
        .post("/wsapi/complete_handle_claim")
        .json(&json!({ "email": "stolen@dan.bsky.social", "attestation": attestation }))
        .await;
    assert_eq!(replay.status_code(), 400);
    assert!(ctx.user_store.get_email("stolen@dan.bsky.social").unwrap().is_none());
}

/// A cold re-claim by the same DID is a sign-in to the owning account, not
/// a new account.
#[tokio::test]
async fn the_same_did_signs_back_into_its_account() {
    let key = KeyPair::generate();
    let ctx = context(&key);

    let claim = |email: &str| {
        let body = json!({
            "email": email,
            "attestation": attest(&key, "dan.bsky.social", "did:plc:dan"),
        });
        ctx.server.post("/wsapi/complete_handle_claim").json(&body)
    };
    claim("me@dan.bsky.social").await.assert_status_ok();
    let first_owner = ctx.user_store.get_email("me@dan.bsky.social").unwrap().unwrap().user_id;

    // New device, no cookies, fresh attestation, same DID.
    claim("me@dan.bsky.social").await.assert_status_ok();
    let second_owner = ctx.user_store.get_email("me@dan.bsky.social").unwrap().unwrap().user_id;
    assert_eq!(first_owner, second_owner);
}

/// A cold claim by a DIFFERENT DID means the handle changed hands: the
/// identity moves to a fresh account, and the previous owner's account —
/// with its other identities — is NOT handed over.
#[tokio::test]
async fn a_new_holder_gets_the_identity_but_not_the_old_account() {
    let key = KeyPair::generate();
    let ctx = context(&key);

    // Original holder: a password account with a second identity on it.
    let session = create_user(&ctx.server, &ctx.email_sender, "old@mail.test", "password123").await;
    let csrf = get_csrf(&ctx.server, &session).await;
    let resp = ctx
        .server
        .post("/wsapi/complete_handle_claim")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({
            "email": "me@dan.bsky.social",
            "attestation": attest(&key, "dan.bsky.social", "did:plc:old"),
            "csrf": csrf,
        }))
        .await;
    resp.assert_status_ok();
    let old_account = ctx.user_store.get_email("old@mail.test").unwrap().unwrap().user_id;
    assert_eq!(
        ctx.user_store.get_email("me@dan.bsky.social").unwrap().unwrap().user_id,
        old_account
    );

    // The handle moves to a new DID, which cold-claims it.
    let resp = ctx
        .server
        .post("/wsapi/complete_handle_claim")
        .json(&json!({
            "email": "me@dan.bsky.social",
            "attestation": attest(&key, "dan.bsky.social", "did:plc:new"),
        }))
        .await;
    resp.assert_status_ok();

    let rec = ctx.user_store.get_email("me@dan.bsky.social").unwrap().unwrap();
    assert_ne!(rec.user_id, old_account, "new holder must not inherit the old account");
    assert_eq!(rec.proof_subject.as_deref(), Some("did:plc:new"));
    // The old account keeps its other identity.
    assert_eq!(
        ctx.user_store.get_email("old@mail.test").unwrap().unwrap().user_id,
        old_account
    );
}

/// Signed-in claims require CSRF like every other state-changing wsapi.
#[tokio::test]
async fn a_signed_in_claim_requires_csrf() {
    let key = KeyPair::generate();
    let ctx = context(&key);
    let session = create_user(&ctx.server, &ctx.email_sender, "me@mail.test", "password123").await;

    let resp = ctx
        .server
        .post("/wsapi/complete_handle_claim")
        .add_cookie(cookie::Cookie::new("browserid_session", session))
        .json(&json!({
            "email": "me@dan.bsky.social",
            "attestation": attest(&key, "dan.bsky.social", "did:plc:dan"),
        }))
        .await;
    assert_eq!(resp.status_code(), 403);
}

#[tokio::test]
async fn the_route_refuses_when_no_attestor_is_configured() {
    let key = KeyPair::generate();
    let ctx = create_test_context_customized(|_| {});
    let resp = ctx
        .server
        .post("/wsapi/complete_handle_claim")
        .json(&json!({
            "email": "me@dan.bsky.social",
            "attestation": attest(&key, "dan.bsky.social", "did:plc:dan"),
        }))
        .await;
    assert_eq!(resp.status_code(), 400);
}

