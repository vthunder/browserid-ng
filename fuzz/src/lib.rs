//! Shared fixtures for the WS3 fuzz targets: fixed keys and a valid as-you
//! bundle every target can mutate from. Deterministic so a crash reproduces.

use std::sync::OnceLock;

use browserid_core::device::{
    AccessCert, AccessCertClaims, AccessPresentation, Binding, DeviceCert, DeviceCertClaims,
    Warrant, WarrantClaims, TYP_ACCESS_CERT, TYP_DEVICE_CERT, TYP_WARRANT_V2,
};
use browserid_core::{Assertion, Holder, HolderMatcher, KeyPair, Purpose, StatusRef};

pub const IAT: i64 = 1_800_000_000;
pub const DAY: i64 = 86_400;
pub const AT: i64 = IAT + 60;
pub const AUD: &str = "https://rp.example";
pub const USER: &str = "user@example.com";
pub const STATUS: &str = "https://example.com/.well-known/browserid-status";

pub struct Keys {
    pub idp: KeyPair,
    pub access: KeyPair,
    pub config: KeyPair,
}

pub fn keys() -> &'static Keys {
    static K: OnceLock<Keys> = OnceLock::new();
    K.get_or_init(|| Keys {
        idp: KeyPair::from_seed(&[1u8; 32]).unwrap(),
        access: KeyPair::from_seed(&[3u8; 32]).unwrap(),
        config: KeyPair::from_seed(&[4u8; 32]).unwrap(),
    })
}

pub fn sref(idx: u64) -> Option<StatusRef> {
    Some(StatusRef { uri: STATUS.into(), idx })
}

pub fn access_cert() -> AccessCert {
    AccessCert::from_claims(
        AccessCertClaims {
            typ: TYP_ACCESS_CERT.into(),
            iss: "example.com".into(),
            iat: IAT,
            exp: IAT + DAY,
            identity: USER.into(),
            holder: Holder::new("br.main").unwrap(),
            access_key: keys().access.public_key(),
            status: sref(7),
            constraints: None,
        },
        &keys().idp,
    )
    .unwrap()
}

pub fn config_cert() -> DeviceCert {
    DeviceCert::from_claims(
        DeviceCertClaims {
            typ: TYP_DEVICE_CERT.into(),
            iss: "example.com".into(),
            iat: IAT,
            exp: IAT + 90 * DAY,
            purpose: Purpose::Authorization,
            holder: Holder::new("br.main").unwrap(),
            identities: vec![USER.into()],
            public_key: keys().config.public_key(),
            status: sref(2),
            managed: None,
            constraints: None,
            prov: None,
        },
        &keys().idp,
    )
    .unwrap()
}

pub fn warrant() -> Warrant {
    Warrant::from_claims(
        WarrantClaims {
            typ: TYP_WARRANT_V2.into(),
            iat: IAT,
            exp: IAT + 90 * DAY,
            grantor: USER.into(),
            grantee: USER.into(),
            holder: None,
            binding: Some(Binding::Holder { matcher: HolderMatcher::new("br.*").unwrap() }.into()),
            audience: AUD.into(),
            scopes: vec![],
            status: sref(42),
            unknown: Default::default(),
        },
        &keys().config,
    )
    .unwrap()
}

pub fn assertion() -> Assertion {
    Assertion::create_at(AUD, None, IAT, IAT + 3650 * DAY, &keys().access).unwrap()
}


pub fn bundle() -> AccessPresentation {
    AccessPresentation {
        access_cert: access_cert(),
        assertion: assertion(),
        warrant: warrant(),
        config_cert: config_cert(),
    }
}

/// Decode fuzz bytes as text: valid UTF-8 verbatim, otherwise lossy (the
/// DNSSEC path joins TXT chunks with `from_utf8_lossy` too).
pub fn text(data: &[u8]) -> std::borrow::Cow<'_, str> {
    String::from_utf8_lossy(data)
}
