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
