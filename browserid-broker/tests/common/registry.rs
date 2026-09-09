//! Registry API (registry-api-v1) helpers for broker tests that drive an
//! axum-test `TestServer`: a session bound to a fresh login key, opened
//! through the broker's login page with the account password, and calls
//! under it with the `Proof` header that key signs.
#![allow(dead_code)]

use axum_test::{TestResponse, TestServer};
use browserid_core::KeyPair;
use serde_json::{json, Value};

/// A registry session: the token and the login key it is bound to.
pub struct ApiSession {
    pub token: String,
    pub key: KeyPair,
    pub account: String,
    origin: String,
}

fn rand_jti() -> String {
    use rand::RngCore;
    let mut b = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Log the account behind a cookie session in to the registry (§4.2
/// `login_page`): the account id from `session_context`, a one-time token
/// from the broker's login-page backend, then `login` with a fresh key.
pub async fn api_login(server: &TestServer, cookie: &str, password: &str) -> ApiSession {
    let ctx: Value = server
        .get("/wsapi/session_context")
        .add_cookie(cookie::Cookie::new("browserid_session", cookie.to_string()))
        .await
        .json();
    let account = ctx["account"].as_str().expect("session_context.account").to_string();
    let domain = ctx["domain"].as_str().expect("session_context.domain").to_string();
    let origin = browserid_registrar::consent::public_origin(&domain);
    let t: Value = server
        .post("/wsapi/registry_login")
        .json(&json!({ "account": account, "password": password }))
        .await
        .json();
    let token = t["login"].as_str().unwrap_or_else(|| panic!("registry_login: {t}")).to_string();
    let key = KeyPair::generate();
    let path = "/api/v1/login";
    let htu = format!("{origin}{path}");
    let jti = rand_jti();
    let now = chrono::Utc::now().timestamp();
    let body = json!({
        "account": account, "method": "login_page", "token": token,
        "login_key": {
            "pubkey": key.public_key().to_base64(), "label": "test device",
            "proof": browserid_registrar::session::build_proof("POST", &htu, None, &key, now, &jti),
        },
    })
    .to_string()
    .into_bytes();
    let header = browserid_registrar::session::build_proof("POST", &htu, Some(&body), &key, now, &jti);
    let r = server
        .post(path)
        .add_header("proof", header)
        .add_header("content-type", "application/json")
        .bytes(body.into())
        .await;
    assert_eq!(r.status_code(), 200, "login: {}", r.text());
    let session: Value = r.json();
    ApiSession { token: session["token"].as_str().unwrap().to_string(), key, account, origin }
}

fn proof_for(sess: &ApiSession, method: &str, path: &str, body: Option<&[u8]>) -> String {
    let htu = format!("{}{}", sess.origin, path.split('?').next().unwrap());
    browserid_registrar::session::build_proof_now(method, &htu, body, &sess.key)
}

/// `GET` under the session.
pub async fn api_get(server: &TestServer, sess: &ApiSession, path: &str) -> TestResponse {
    server
        .get(path)
        .add_header("authorization", format!("Bearer {}", sess.token))
        .add_header("proof", proof_for(sess, "GET", path, None))
        .await
}

/// `POST` under the session (`bh` binds the body).
pub async fn api_post(server: &TestServer, sess: &ApiSession, path: &str, body: Value) -> TestResponse {
    let bytes = body.to_string().into_bytes();
    server
        .post(path)
        .add_header("authorization", format!("Bearer {}", sess.token))
        .add_header("proof", proof_for(sess, "POST", path, Some(&bytes)))
        .add_header("content-type", "application/json")
        .bytes(bytes.into())
        .await
}
