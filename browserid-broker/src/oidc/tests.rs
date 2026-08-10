//! Unit tests for the OIDC bridge core. Uses a throwaway RSA test key (below)
//! to mint real RS256 ID tokens and a matching in-memory JWKS, so the full
//! verify path (signature by kid + claim checks) runs offline.

use super::*;
use jsonwebtoken::{encode, EncodingKey, Header};
use serde_json::json;

const TEST_KID: &str = "test-kid-1";
// n/e of TEST_PRIVATE_PEM's public key (base64url), for the JWKS.
const TEST_N: &str = "k9MkcSs6W_CoUQbpXsP1MXq_cx_TwdP8-gnaNl4kQnMzTRK4IJdvgD2u1aAXhKdbV1MtJKU0ZqyWwFxc2mbHEkmNVMsBTPUVVk6iZGhcchTNOpPlw2wFN_NWWt_rnEpGjtzagUaFr_UF5KfkbIUa5xJZaG661P3yGmUDMQhWDBBJ0EEmtB0xbfi9Xzss0B7RCYTf_ejQzut3w_tQcP1ax378Ki3qJFqJjJqfUHAvPWSyT9QqttS89hgayCOXl8qPVb9H_R8qZdbTj1-ZnBYz2ayUmKzKYErMmFgim97Ib-Mahpjqq_SIH9LTWQTqeT1bIVYsnfeqULnzWLraags60Q";
const TEST_E: &str = "AQAB";
const TEST_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCT0yRxKzpb8KhR
Bulew/Uxer9zH9PB0/z6Cdo2XiRCczNNErggl2+APa7VoBeEp1tXUy0kpTRmrJbA
XFzaZscSSY1UywFM9RVWTqJkaFxyFM06k+XDbAU381Za3+ucSkaO3NqBRoWv9QXk
p+RshRrnEllobrrU/fIaZQMxCFYMEEnQQSa0HTFt+L1fOyzQHtEJhN/96NDO63fD
+1Bw/VrHfvwqLeokWomMmp9QcC89ZLJP1Cq21Lz2GBrII5eXyo9Vv0f9Hypl1tOP
X5mcFjPZrJSYrMpgSsyYWCKb3shv4xqGmOqr9Igf0tNZBOp5PVshViyd96pQufNY
utpqCzrRAgMBAAECggEANefAeb48PUuwbT+6eTK3JnBvARHBnARsU1elab8BtPOi
aQAjAcuHPvn/V+pVuSt4LQtpQlw2FBzqqkHkIEZrYJlOvvV6R3B18++f20KNN5Kr
VimZlx48du829dOC7Q7O1Qjna03msUgF+qBYtVQCf/HahbEfU005bHOaatZx3lrC
TGyZTPGaE2KPQNrjD/XngeZwydJo18jujcccK2UgrG41CN6qk9bnvbbVGSU20W6K
om4c5QLqj4V2OYEXm6P9d8VSTobtShJCVCrZSEC3YjpFD6BcXVHjxnkBeLLOQ+iA
3S2ahE5KgiJbKXnEqZwKVvFiZ1zQPSdFgnzjoMFY4wKBgQDHWVqObBcx5/I60J3O
kxwdFxPN8TBmQz8QrGOeqkRr7PquWY7OFN3fNCOOOe1Wk9npCLKn1WYhrK5eoa+N
zkD2lK6C9iyZyMYmoLpexlblHtpZiQC/+OJIa5EZTt/zUQBTejdBtPL3uRZVrFdR
0oQ8fnKDsTs39y6m2JXOsoxHQwKBgQC91WXCdDNc9XXpuZhRfMNhI+eeK47aG9JM
Sz5xYDdkdwv3UKCdfj+5YkbHebuVKiKuZt4pYBpmJpUzlWunqGNkK/JJs6zvB2Li
tmJfIaGCv2jeuwLFK6jXNdC8kvfpt6xTX4tRGHYukde7z6SJsB2HY4lLmtMg0OQ0
2IOhl30iWwKBgBSFFBc49SJD9+Ep/DR5XBl6eKVoQE0meuVieVapvCVH3X345gQ8
jaIeIdLQD6gry/B63rj79Gle9wvypLl6E6HOKDB+2pRx4EO1o7mBvQwUovE4cwVP
vyspN2RdhBvtqJTvLaTr1V6+hJgJB2v6uXXopiz8H1ZhcUHnZXRDWME1AoGBALZ2
9H2pFWmnofPK6eaBZobrbQjyUzfAAC5HMLjnQ7b0WnMYc5mOLRAyr1ey4aPpwTYj
OC1K63T+ZvETEUwwpYA2YYeIBZQnZFwH9Jv+BnFXLCTSWkJMydg6KO3o0hQ68I+e
yZlkSsxOcK9cUYnq1yc4fFJIeeEUCBXnevaKVsP7AoGBAKNK6JaY9cLGDtopkAC7
59Nh5WHnxjm+V/DsxjK4a/fiZ5BXZM1BBGVVP+DZ5HVJV+a3a9zqwC0a3SF7m+YA
4jGU4+EOM1K43lsOWEyvcqGHdgtQrCsrcACETFGf1VTRVPRd93xG6KkyymVwV1vI
hsJX71r6EqXNoyjpb6m9XfTc
-----END PRIVATE KEY-----";

fn provider() -> OidcProvider {
    OidcProvider::google("test-client.apps.googleusercontent.com", "secret")
}

fn jwks() -> Jwks {
    Jwks {
        keys: vec![Jwk {
            kid: TEST_KID.into(),
            n: TEST_N.into(),
            e: TEST_E.into(),
            alg: Some("RS256".into()),
        }],
    }
}

/// Mint a signed RS256 ID token with the given claims overrides.
fn mint(claims: serde_json::Value) -> String {
    let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some(TEST_KID.into());
    let key = EncodingKey::from_rsa_pem(TEST_PRIVATE_PEM.as_bytes()).unwrap();
    encode(&header, &claims, &key).unwrap()
}

fn base_claims(email: &str, nonce: &str) -> serde_json::Value {
    json!({
        "iss": GOOGLE_ISSUER,
        "aud": "test-client.apps.googleusercontent.com",
        "exp": (chrono::Utc::now().timestamp() + 300),
        "iat": chrono::Utc::now().timestamp(),
        "sub": "1234567890",
        "email": email,
        "email_verified": true,
        "nonce": nonce,
    })
}

// --- domain detection -------------------------------------------------------

#[test]
fn google_domain_detection() {
    assert!(is_google_domain("gmail.com", None));
    assert!(is_google_domain("googlemail.com", None));
    assert!(is_google_domain("acme.com", Some("aspmx.l.google.com")));
    assert!(is_google_domain("acme.com", Some("ALT1.ASPMX.L.GOOGLE.COM.")));
    assert!(!is_google_domain("acme.com", Some("mx.acme.com")));
    assert!(!is_google_domain("acme.com", None));
    // Not a suffix trick.
    assert!(!is_google_domain("acme.com", Some("google.com.evil.com")));
}

#[test]
fn gmail_normalization() {
    assert_eq!(normalize_google_email("D.a.N+work@Gmail.com"), "dan@gmail.com");
    assert_eq!(normalize_google_email("dan@googlemail.com"), "dan@googlemail.com");
    // Workspace/other domains keep dots + tag (only lowercased).
    assert_eq!(normalize_google_email("D.an+x@Acme.com"), "d.an+x@acme.com");
}

// --- auth url + pkce --------------------------------------------------------

#[test]
fn auth_url_has_pkce_and_hint() {
    let pkce = Pkce::generate();
    let url = build_auth_url(&provider(), "https://b.me/oidc/callback", "foo@gmail.com", "st8", "nc9", &pkce.challenge);
    assert!(url.starts_with(GOOGLE_AUTH_ENDPOINT));
    for needle in [
        "response_type=code",
        "code_challenge_method=S256",
        "scope=openid+email",
        "state=st8",
        "nonce=nc9",
        "login_hint=foo%40gmail.com",
    ] {
        assert!(url.contains(needle), "missing {needle} in {url}");
    }
    assert!(url.contains(&format!("code_challenge={}", pkce.challenge)));
    // PKCE S256 relationship holds.
    let expect = URL_SAFE_NO_PAD.encode(Sha256::digest(pkce.verifier.as_bytes()));
    assert_eq!(pkce.challenge, expect);
}

// --- id-token verification --------------------------------------------------

#[test]
fn verifies_a_good_token() {
    let tok = mint(base_claims("dan@gmail.com", "nc9"));
    let v = verify_id_token(&tok, &jwks(), &provider(), "nc9", "d.a.n@gmail.com").unwrap();
    // Claimed with dots; verified normalizes to the canonical mailbox.
    assert_eq!(v.email, "dan@gmail.com");
    assert_eq!(v.proof_subject, format!("{}#1234567890", GOOGLE_ISSUER));
}

#[test]
fn rejects_nonce_mismatch() {
    let tok = mint(base_claims("dan@gmail.com", "WRONG"));
    let e = verify_id_token(&tok, &jwks(), &provider(), "nc9", "dan@gmail.com").unwrap_err();
    assert!(matches!(e, OidcError::NonceMismatch));
}

#[test]
fn rejects_unverified_email() {
    let mut c = base_claims("dan@gmail.com", "nc9");
    c["email_verified"] = json!(false);
    let e = verify_id_token(&mint(c), &jwks(), &provider(), "nc9", "dan@gmail.com").unwrap_err();
    assert!(matches!(e, OidcError::EmailUnverified));
}

#[test]
fn rejects_email_mismatch() {
    let tok = mint(base_claims("someone-else@gmail.com", "nc9"));
    let e = verify_id_token(&tok, &jwks(), &provider(), "nc9", "dan@gmail.com").unwrap_err();
    assert!(matches!(e, OidcError::EmailMismatch { .. }));
}

#[test]
fn rejects_wrong_audience() {
    let mut c = base_claims("dan@gmail.com", "nc9");
    c["aud"] = json!("some-other-client.apps.googleusercontent.com");
    let e = verify_id_token(&mint(c), &jwks(), &provider(), "nc9", "dan@gmail.com").unwrap_err();
    assert!(matches!(e, OidcError::TokenInvalid(_)));
}

#[test]
fn rejects_expired() {
    let mut c = base_claims("dan@gmail.com", "nc9");
    // Well past jsonwebtoken's default 60s leeway.
    c["exp"] = json!(chrono::Utc::now().timestamp() - 3600);
    let e = verify_id_token(&mint(c), &jwks(), &provider(), "nc9", "dan@gmail.com").unwrap_err();
    assert!(matches!(e, OidcError::TokenInvalid(_)));
}

#[test]
fn rejects_unknown_kid() {
    let tok = mint(base_claims("dan@gmail.com", "nc9"));
    let empty = Jwks { keys: vec![] };
    let e = verify_id_token(&tok, &empty, &provider(), "nc9", "dan@gmail.com").unwrap_err();
    assert!(matches!(e, OidcError::UnknownKid(_)));
}

#[test]
fn workspace_requires_matching_hd() {
    // A Workspace claim for acme.com: hd must equal the domain.
    let mut good = base_claims("dan@acme.com", "nc9");
    good["hd"] = json!("acme.com");
    let v = verify_id_token(&mint(good), &jwks(), &provider(), "nc9", "dan@acme.com").unwrap();
    assert_eq!(v.email, "dan@acme.com");

    // Missing/wrong hd on a non-consumer domain is rejected (a random Google
    // account can't claim a Workspace address).
    let no_hd = base_claims("dan@acme.com", "nc9");
    let e = verify_id_token(&mint(no_hd), &jwks(), &provider(), "nc9", "dan@acme.com").unwrap_err();
    assert!(matches!(e, OidcError::WorkspaceDomainMismatch));

    let mut wrong = base_claims("dan@acme.com", "nc9");
    wrong["hd"] = json!("evil.com");
    let e2 = verify_id_token(&mint(wrong), &jwks(), &provider(), "nc9", "dan@acme.com").unwrap_err();
    assert!(matches!(e2, OidcError::WorkspaceDomainMismatch));
}

// --- flow store -------------------------------------------------------------

#[test]
fn flow_store_is_single_use() {
    let flows = OidcFlows::new();
    flows.begin("st".into(), "nc".into(), "cv".into(), "a@gmail.com".into(), None);
    let taken = flows.take("st").unwrap();
    assert_eq!(taken.nonce, "nc");
    assert_eq!(taken.claimed_email, "a@gmail.com");
    assert!(flows.take("st").is_none()); // consumed
}
