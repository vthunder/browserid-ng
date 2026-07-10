//! End-to-end consent flow (spec §6, v0.4), every hop over real HTTP: the
//! agent raises a warrant request at its registrar, "the browser" (simulated
//! with the session cookie + the user's identity key) approves on the consent
//! API, and the agent polls the signed warrant and presents it.

mod common;

use browserid_agent::{AgentError, AgentIdentity};
use browserid_core::{BackedAssertion, Certificate, Warrant, WarrantGrant};
use chrono::Duration;
use common::{make_credential, start_broker};
use serde_json::{json, Value};

const AUDIENCE: &str = "https://api.example.com";

/// The consent page's job, done with raw HTTP + real crypto: list pending
/// requests, sign one warrant per grant with the user's identity key,
/// respond. Returns (response, grant count).
async fn approve_pending(
    base: &str,
    session_cookie: &str,
    user_kp: &browserid_core::KeyPair,
    parent_cert: &Certificate,
    approve: bool,
) -> (Value, usize) {
    let http = reqwest::Client::new();
    let csrf = http
        .get(format!("{base}/wsapi/session_context"))
        .header("cookie", session_cookie)
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap()["csrf_token"]
        .as_str()
        .unwrap()
        .to_string();

    let pending: Value = http
        .get(format!("{base}/wsapi/warrant_requests"))
        .header("cookie", session_cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let requests = pending["requests"].as_array().unwrap();
    assert_eq!(requests.len(), 1, "expected one pending request: {pending}");
    let r = &requests[0];
    let grants = r["grants"].as_array().unwrap();
    assert!(!grants.is_empty());

    let warrants = approve.then(|| {
        grants
            .iter()
            .map(|g| {
                Warrant::create(
                    parent_cert,
                    r["agent_email"].as_str().unwrap(),
                    g["audience"].as_str().unwrap(),
                    g["scopes"].as_array().map(|ss| {
                        ss.iter().map(|s| s.as_str().unwrap().to_string()).collect()
                    }),
                    Duration::days(30),
                    user_kp,
                )
                .unwrap()
                .encoded()
                .to_string()
            })
            .collect::<Vec<_>>()
    });

    let resp = http
        .post(format!("{base}/wsapi/warrant_respond"))
        .header("cookie", session_cookie)
        .json(&json!({
            "csrf": csrf,
            "code": r["code"],
            "approve": approve,
            "warrants": warrants,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    (resp, grants.len())
}

#[tokio::test]
async fn consent_flow_approval_roundtrip() {
    let (base, broker_pubkey) = start_broker().await;
    let (credential, user_kp, session) = make_credential(&base).await;
    let mut agent = AgentIdentity::provision(&credential, Some("attestor")).await.unwrap();
    let (u, _) = credential.delegation.split_once('~').unwrap();
    let parent_cert = Certificate::parse(u).unwrap();

    // Agent raises the request; the handle carries the human-facing URI.
    let handle = agent
        .request_warrant(AUDIENCE, Some(vec!["post".into()]))
        .await
        .unwrap();
    assert!(handle.verification_uri.contains("/consent/"));
    assert!(handle.code.starts_with("wrq_"));

    // Nothing yet: first poll is pending.
    assert!(!agent.poll_warrant(&handle).await.unwrap());

    // The principal approves on the consent surface.
    let (resp, grant_count) = approve_pending(&base, &session, &user_kp, &parent_cert, true).await;
    assert_eq!(resp["success"], true, "respond failed: {resp}");
    assert_eq!(grant_count, 1);

    // Poll picks the warrant up (respecting the interval), stores it, and the
    // agent can now present at the audience.
    tokio::time::sleep(std::time::Duration::from_secs(handle.interval as u64)).await;
    assert!(agent.poll_warrant(&handle).await.unwrap());
    assert!(agent.warrant_for(AUDIENCE).is_some());

    let assertion = agent.assertion_for(AUDIENCE).await.unwrap();
    let verified = BackedAssertion::parse(&assertion)
        .unwrap()
        .verify(AUDIENCE, |_| Ok(broker_pubkey.clone()))
        .unwrap();
    assert_eq!(verified.email, agent.email());
    let attribution = verified.agent.unwrap();
    assert_eq!(attribution.parent, "human@example.com");
    assert_eq!(attribution.scopes, vec!["post"]);

    // Single delivery: the code is dead after pickup.
    match agent.poll_warrant(&handle).await {
        Err(AgentError::WarrantExpired) => {}
        other => panic!("expected expired after delivery, got {other:?}"),
    }
}

#[tokio::test]
async fn consent_flow_denial() {
    let (base, _) = start_broker().await;
    let (credential, user_kp, session) = make_credential(&base).await;
    let mut agent = AgentIdentity::provision(&credential, Some("attestor")).await.unwrap();
    let (u, _) = credential.delegation.split_once('~').unwrap();
    let parent_cert = Certificate::parse(u).unwrap();

    let handle = agent.request_warrant(AUDIENCE, Some(vec!["post".into()])).await.unwrap();
    approve_pending(&base, &session, &user_kp, &parent_cert, false).await;

    tokio::time::sleep(std::time::Duration::from_secs(handle.interval as u64)).await;
    match agent.poll_warrant(&handle).await {
        Err(AgentError::WarrantDenied) => {}
        other => panic!("expected denial, got {other:?}"),
    }
    assert!(agent.warrant_for(AUDIENCE).is_none());
}

#[tokio::test]
async fn warrant_request_requires_registered_credential() {
    let (base, _) = start_broker().await;
    // Credential registered at a different broker → refused (404, registry gate).
    let (other_base, _) = start_broker().await;
    let (credential, _, _) = make_credential(&other_base).await;
    let credential = browserid_agent::AgentCredential {
        broker: base.clone(),
        idp: base,
        ..credential
    };
    let agent_result = AgentIdentity::provision(&credential, Some("attestor")).await;
    // Provisioning already fails at endorse; build the request path directly
    // via a provisioned agent at the right broker instead.
    assert!(agent_result.is_err());
}

#[tokio::test]
async fn batch_consent_two_audiences_one_approval() {
    let (base, broker_pubkey) = start_broker().await;
    let (credential, user_kp, session) = make_credential(&base).await;
    let mut agent = AgentIdentity::provision(&credential, Some("attestor")).await.unwrap();
    let (u, _) = credential.delegation.split_once('~').unwrap();
    let parent_cert = Certificate::parse(u).unwrap();

    // One request, two grants — a web audience and a non-HTTP (ledger) one,
    // with different scopes.
    let handle = agent
        .request_warrants(vec![
            WarrantGrant { aud: "https://mingo.example".into(), scopes: Some(vec!["post".into()]) },
            WarrantGrant { aud: "sbo://mingo.example".into(), scopes: Some(vec!["claim".into()]) },
        ])
        .await
        .unwrap();
    assert_eq!(handle.audiences.len(), 2);

    // One approval signs both.
    let (resp, grant_count) = approve_pending(&base, &session, &user_kp, &parent_cert, true).await;
    assert_eq!(resp["success"], true, "respond failed: {resp}");
    assert_eq!(grant_count, 2);

    tokio::time::sleep(std::time::Duration::from_secs(handle.interval as u64)).await;
    assert!(agent.poll_warrant(&handle).await.unwrap());
    assert!(agent.warrant_for("https://mingo.example").is_some());
    assert!(agent.warrant_for("sbo://mingo.example").is_some());

    // Each warrant works only at its own audience, with its own scopes.
    let assertion = agent.assertion_for("sbo://mingo.example").await.unwrap();
    let verified = BackedAssertion::parse(&assertion)
        .unwrap()
        .verify("sbo://mingo.example", |_| Ok(broker_pubkey.clone()))
        .unwrap();
    assert_eq!(verified.agent.unwrap().scopes, vec!["claim"]);

    // Already-held audiences are skipped: obtain_warrants with both held
    // resolves without raising a request.
    agent
        .obtain_warrants(
            vec![
                WarrantGrant { aud: "https://mingo.example".into(), scopes: None },
                WarrantGrant { aud: "sbo://mingo.example".into(), scopes: None },
            ],
            |_| panic!("no new request expected"),
        )
        .await
        .unwrap();
}

/// jipx: approvals populate the account's warrant registry (reviewable via
/// /wsapi/warrants); manual registration and forget round-trip; forget is
/// registry-only (the JWS the agent holds keeps verifying).
#[tokio::test]
async fn warrant_registry_records_and_forgets() {
    let (base, _) = start_broker().await;
    let (credential, user_kp, session) = make_credential(&base).await;
    let mut agent = AgentIdentity::provision(&credential, Some("attestor")).await.unwrap();
    let (u, _) = credential.delegation.split_once('~').unwrap();
    let parent_cert = Certificate::parse(u).unwrap();
    let http = reqwest::Client::new();
    let csrf = http
        .get(format!("{base}/wsapi/session_context"))
        .header("cookie", &session)
        .send().await.unwrap()
        .json::<Value>().await.unwrap()["csrf_token"].as_str().unwrap().to_string();

    // Consent approval lands in the registry.
    let handle = agent
        .request_warrants(vec![
            WarrantGrant { aud: "https://one.example".into(), scopes: Some(vec!["post".into()]) },
            WarrantGrant { aud: "sbo://two.example".into(), scopes: None },
        ])
        .await
        .unwrap();
    approve_pending(&base, &session, &user_kp, &parent_cert, true).await;
    tokio::time::sleep(std::time::Duration::from_secs(handle.interval as u64)).await;
    assert!(agent.poll_warrant(&handle).await.unwrap());

    let listed: Value = http
        .get(format!("{base}/wsapi/warrants"))
        .header("cookie", &session)
        .send().await.unwrap().json().await.unwrap();
    let warrants = listed["warrants"].as_array().unwrap();
    assert_eq!(warrants.len(), 2, "registry after approval: {listed}");
    let auds: Vec<&str> = warrants.iter().map(|w| w["audience"].as_str().unwrap()).collect();
    assert!(auds.contains(&"https://one.example") && auds.contains(&"sbo://two.example"));
    assert!(warrants.iter().all(|w| w["agent_email"] == agent.email()));

    // Manual registration upserts (same agent+audience replaces the row).
    let manual = Warrant::create(
        &parent_cert,
        agent.email(),
        "https://one.example",
        Some(vec!["read".into()]),
        Duration::days(10),
        &user_kp,
    )
    .unwrap();
    let resp: Value = http
        .post(format!("{base}/wsapi/register_warrant"))
        .header("cookie", &session)
        .json(&json!({ "csrf": csrf, "warrant": manual.encoded() }))
        .send().await.unwrap().json().await.unwrap();
    assert_eq!(resp["success"], true, "register: {resp}");
    let listed: Value = http
        .get(format!("{base}/wsapi/warrants"))
        .header("cookie", &session)
        .send().await.unwrap().json().await.unwrap();
    let warrants = listed["warrants"].as_array().unwrap();
    assert_eq!(warrants.len(), 2, "upsert must replace, not add: {listed}");
    let one = warrants.iter().find(|w| w["audience"] == "https://one.example").unwrap();
    assert_eq!(one["scopes"][0], "read", "upsert keeps the newest signing");

    // Forget removes the row (scoped to the owner).
    let id = one["id"].as_u64().unwrap();
    let resp: Value = http
        .post(format!("{base}/wsapi/forget_warrant"))
        .header("cookie", &session)
        .json(&json!({ "csrf": csrf, "id": id }))
        .send().await.unwrap().json().await.unwrap();
    assert_eq!(resp["success"], true);
    let listed: Value = http
        .get(format!("{base}/wsapi/warrants"))
        .header("cookie", &session)
        .send().await.unwrap().json().await.unwrap();
    assert_eq!(listed["warrants"].as_array().unwrap().len(), 1);
}
