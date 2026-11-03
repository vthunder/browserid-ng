#![no_main]
//! WS3: `_browserid` TXT parsing is total on arbitrary bytes (joined lossy,
//! as the DNSSEC resolver does) and never upgrades a malformed record to a
//! key (July M5 class): `Ok` ⇒ exact version, exact algorithm, exactly one
//! `public-key=` field (a repeat is ambiguous and rejects — W2-6, bean
//! zsi1) whose bytes are the key.

use browserid_core::DnsRecord;
use browserid_fuzz::text;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let s = text(data);
    if let Ok(r) = DnsRecord::parse(&s) {
        assert_eq!(r.version, "browserid1");
        assert_eq!(r.algorithm, "Ed25519");
        let fields: Vec<String> = s
            .split(';')
            .map(str::trim)
            .filter_map(|p| p.split_once('='))
            .filter(|(k, _)| k.trim() == "public-key")
            .map(|(_, v)| v.trim().to_string())
            .collect();
        assert_eq!(fields.len(), 1, "Ok with {} public-key fields", fields.len());
        assert_eq!(r.public_key.to_base64(), fields[0], "key does not come from the public-key field");
        let _ = r.well_known_host("example.com");
    }
});
