//! WS8 PoC — D1: a base `user@example.com` identity speaks as `user+agent@`.
//! Local/in-process only. Demonstrates the CURRENT (vulnerable) behaviour:
//! the subaddress mint gate is purpose-blind, and a `*`-holder warrant for
//! the subaddress verifies. Reuses the WS6 fixture shape.
use browserid_core::device::{
    AccessCertClaims, AccessPresentation, Binding, DeviceCertClaims, HolderMatcher, Warrant,
    WarrantClaims, TYP_ACCESS_CERT, TYP_DEVICE_CERT, TYP_WARRANT_V2,
};
use browserid_core::{Assertion, Holder, KeyPair, PublicKey, Purpose, StatusRef};

const IAT: i64 = 1_800_000_000;
const DAY: i64 = 86_400;
const HOUR: i64 = 3_600;
const IDP: &str = "example.com";
const BASE: &str = "user@example.com";
const SUB: &str = "user+agent@example.com";
const AUD: &str = "https://rp.example";
const STATUS: &str = "https://example.com/.well-known/browserid-status";
const AT: i64 = IAT + 60;

fn key(s: u8) -> KeyPair { KeyPair::from_seed(&[s; 32]).unwrap() }
fn sref(i: u64) -> Option<StatusRef> { Some(StatusRef { uri: STATUS.into(), idx: i }) }

#[test]
fn d1_poc_base_auth_cert_no_longer_mints_as_subaddress() {
    let idp = key(1);
    let access = key(3);
    let config = key(4);
    let idp_pub: PublicKey = idp.public_key();

    // 1) The mint gate. A base `user@` AUTHENTICATION cert (the browser/login
    //    key) is what /access/mint checks via authorizes_identity. It
    //    authorizes `user@` only (D1 fixed, bean v8s0): it used to widen to
    //    the subaddress.
    let auth = {
        let c = DeviceCertClaims {
            typ: TYP_DEVICE_CERT.into(), iss: IDP.into(), iat: IAT, exp: IAT + 90 * DAY,
            purpose: Purpose::Authentication, holder: Holder::new("br.main").unwrap(),
            identities: vec![BASE.into()], public_key: access.public_key(),
            status: sref(2), managed: None, constraints: None, prov: None,
        };
        browserid_core::device::DeviceCert::from_claims(c, &idp).unwrap()
    };
    assert!(auth.authorizes_identity(BASE));
    let widens = auth.authorizes_identity(SUB);
    println!("[D1] base-auth cert authorizes_identity({SUB}) = {widens}  (true would let the mint gate issue an access cert for the subaddress)");
    assert!(!widens, "an auth cert for the base identity must not mint for a subaddress (spec §4.6)");
    assert!(!auth.authorizes_grantor(SUB), "an auth cert never vouches for a grantor");

    // 2) End-to-end accept STILL holds for a legitimately minted subaddress
    //    access cert (one issued for `user+agent@` itself): a config cert for
    //    the BASE identity signs the warrant for the subaddress (§4.6's
    //    authorization-only rule), presented under a `*`-holder warrant.
    let access_cert = {
        let c = AccessCertClaims {
            typ: TYP_ACCESS_CERT.into(), iss: IDP.into(), iat: IAT, exp: IAT + 24 * HOUR,
            identity: SUB.into(), holder: Holder::new("br.main").unwrap(),
            access_key: access.public_key(), status: sref(7), constraints: None,
        };
        browserid_core::device::AccessCert::from_claims(c, &idp).unwrap()
    };
    let warrant = {
        let c = WarrantClaims {
            typ: TYP_WARRANT_V2.into(), iat: IAT, exp: IAT + 90 * DAY,
            grantor: SUB.into(), grantee: SUB.into(), holder: None,
            binding: Some(Binding::Holder { matcher: HolderMatcher::new("*").unwrap() }.into()),
            audience: AUD.into(), scopes: vec![], status: sref(42), unknown: Default::default(),
        };
        Warrant::from_claims(c, &config).unwrap()
    };
    // config cert for the BASE identity signs the warrant for the subaddress
    let config_cert = {
        let c = DeviceCertClaims {
            typ: TYP_DEVICE_CERT.into(), iss: IDP.into(), iat: IAT, exp: IAT + 90 * DAY,
            purpose: Purpose::Authorization, holder: Holder::new("br.main").unwrap(),
            identities: vec![BASE.into()], public_key: config.public_key(),
            status: sref(2), managed: None, constraints: None, prov: None,
        };
        browserid_core::device::DeviceCert::from_claims(c, &idp).unwrap()
    };
    let p = AccessPresentation {
        access_cert,
        assertion: Assertion::create(AUD, chrono::Duration::days(3650), &access).unwrap(),
        warrant, config_cert,
    };
    let v = p.verify_at(AUD, AT, |_| Ok(idp_pub.clone())).expect("PoC: verifier accepts the subaddress presentation");
    println!("[D1] verifier ACCEPTED: email={} grantee={} holder={}", v.email, v.grantee, v.holder.as_str());
    assert_eq!(v.grantee, SUB);
}
