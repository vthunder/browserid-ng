#![no_main]
//! WS3: `_browserid` TXT parsing is total on arbitrary bytes (joined lossy,
//! as the DNSSEC resolver does) and never upgrades a malformed record to a
//! key (July M5 class): `Ok` ⇒ exact version, exact algorithm, key bytes
//! equal to the last `public-key=` field.

use browserid_core::DnsRecord;
use browserid_fuzz::text;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let s = text(data);
    if let Ok(r) = DnsRecord::parse(&s) {
        assert_eq!(r.version, "browserid1");
        assert_eq!(r.algorithm, "Ed25519");
        let field = s
            .split(';')
            .map(str::trim)
            .filter_map(|p| p.split_once('='))
            .filter(|(k, _)| k.trim() == "public-key")
            .last()
            .map(|(_, v)| v.trim().to_string())
            .expect("Ok without a public-key field");
        assert_eq!(r.public_key.to_base64(), field, "key does not come from the public-key field");
        let _ = r.well_known_host("example.com");
    }
});
