//! DNS record parsing tests

use browserid_core::{DnsRecord, Error, KeyPair};

mod parse_valid {
    use super::*;

    #[test]
    fn test_parse_minimal_record() {
        let key = KeyPair::generate();
        let txt = format!(
            "v=browserid1; public-key-algorithm=Ed25519; public-key={}",
            key.public_key().to_base64()
        );

        let record = DnsRecord::parse(&txt).unwrap();
        assert_eq!(record.version, "browserid1");
        assert_eq!(record.algorithm, "Ed25519");
        assert_eq!(record.public_key, key.public_key());
        assert_eq!(record.host, None);
    }

    #[test]
    fn test_parse_record_with_host() {
        let key = KeyPair::generate();
        let txt = format!(
            "v=browserid1; public-key-algorithm=Ed25519; public-key={}; host=idp.example.com",
            key.public_key().to_base64()
        );

        let record = DnsRecord::parse(&txt).unwrap();
        assert_eq!(record.host, Some("idp.example.com".to_string()));
    }

    #[test]
    fn test_parse_with_extra_whitespace() {
        let key = KeyPair::generate();
        let txt = format!(
            "  v=browserid1 ;  public-key-algorithm=Ed25519 ;  public-key={} ",
            key.public_key().to_base64()
        );

        let record = DnsRecord::parse(&txt).unwrap();
        assert_eq!(record.version, "browserid1");
    }

    #[test]
    fn test_parse_ignores_unknown_fields() {
        let key = KeyPair::generate();
        let txt = format!(
            "v=browserid1; public-key-algorithm=Ed25519; public-key={}; future-field=value",
            key.public_key().to_base64()
        );

        let record = DnsRecord::parse(&txt).unwrap();
        assert_eq!(record.version, "browserid1");
    }
}

mod parse_invalid {
    use super::*;

    #[test]
    fn test_missing_version() {
        let key = KeyPair::generate();
        let txt = format!(
            "public-key-algorithm=Ed25519; public-key={}",
            key.public_key().to_base64()
        );

        let result = DnsRecord::parse(&txt);
        assert!(matches!(result, Err(Error::InvalidDnsRecord(_))));
    }

    #[test]
    fn test_wrong_version() {
        let key = KeyPair::generate();
        let txt = format!(
            "v=browserid2; public-key-algorithm=Ed25519; public-key={}",
            key.public_key().to_base64()
        );

        let result = DnsRecord::parse(&txt);
        assert!(matches!(result, Err(Error::InvalidDnsRecord(msg)) if msg.contains("version")));
    }

    #[test]
    fn test_missing_algorithm() {
        let key = KeyPair::generate();
        let txt = format!(
            "v=browserid1; public-key={}",
            key.public_key().to_base64()
        );

        let result = DnsRecord::parse(&txt);
        assert!(matches!(result, Err(Error::InvalidDnsRecord(_))));
    }

    #[test]
    fn test_unsupported_algorithm() {
        let key = KeyPair::generate();
        let txt = format!(
            "v=browserid1; public-key-algorithm=RSA; public-key={}",
            key.public_key().to_base64()
        );

        let result = DnsRecord::parse(&txt);
        assert!(matches!(result, Err(Error::UnsupportedAlgorithm(_))));
    }

    #[test]
    fn test_missing_public_key() {
        let txt = "v=browserid1; public-key-algorithm=Ed25519";

        let result = DnsRecord::parse(txt);
        assert!(matches!(result, Err(Error::InvalidDnsRecord(_))));
    }

    #[test]
    fn test_invalid_public_key() {
        let txt = "v=browserid1; public-key-algorithm=Ed25519; public-key=not-valid-base64!!!";

        let result = DnsRecord::parse(txt);
        assert!(matches!(result, Err(Error::InvalidDnsRecord(_))));
    }
}

mod well_known_host {
    use super::*;

    #[test]
    fn test_returns_host_when_specified() {
        let key = KeyPair::generate();
        let txt = format!(
            "v=browserid1; public-key-algorithm=Ed25519; public-key={}; host=idp.example.com",
            key.public_key().to_base64()
        );

        let record = DnsRecord::parse(&txt).unwrap();
        assert_eq!(record.well_known_host("example.com"), "idp.example.com");
    }

    #[test]
    fn test_returns_default_when_no_host() {
        let key = KeyPair::generate();
        let txt = format!(
            "v=browserid1; public-key-algorithm=Ed25519; public-key={}",
            key.public_key().to_base64()
        );

        let record = DnsRecord::parse(&txt).unwrap();
        assert_eq!(record.well_known_host("example.com"), "example.com");
    }
}

mod dnssec_status {
    use browserid_core::{DnssecStatus, DnsLookupResult, KeyPair, DnsRecord};

    #[test]
    fn test_secure_is_secure() {
        assert!(DnssecStatus::Secure.is_secure());
        assert!(!DnssecStatus::Insecure.is_secure());
        assert!(!DnssecStatus::Bogus.is_secure());
    }

    #[test]
    fn test_insecure_allows_fallback() {
        assert!(!DnssecStatus::Secure.allows_fallback());
        assert!(DnssecStatus::Insecure.allows_fallback());
        assert!(!DnssecStatus::Bogus.allows_fallback());
    }

    #[test]
    fn test_bogus_is_bogus() {
        assert!(!DnssecStatus::Secure.is_bogus());
        assert!(!DnssecStatus::Insecure.is_bogus());
        assert!(DnssecStatus::Bogus.is_bogus());
    }

    #[test]
    fn test_lookup_result_constructors() {
        let key = KeyPair::generate();
        let txt = format!(
            "v=browserid1; public-key-algorithm=Ed25519; public-key={}",
            key.public_key().to_base64()
        );
        let record = DnsRecord::parse(&txt).unwrap();

        let secure = DnsLookupResult::secure(record);
        assert!(secure.record.is_some());
        assert_eq!(secure.dnssec_status, DnssecStatus::Secure);

        let nxdomain = DnsLookupResult::secure_nxdomain();
        assert!(nxdomain.record.is_none());
        assert_eq!(nxdomain.dnssec_status, DnssecStatus::Secure);

        let insecure = DnsLookupResult::insecure();
        assert!(insecure.record.is_none());
        assert_eq!(insecure.dnssec_status, DnssecStatus::Insecure);

        let bogus = DnsLookupResult::bogus();
        assert!(bogus.record.is_none());
        assert_eq!(bogus.dnssec_status, DnssecStatus::Bogus);
    }
}
