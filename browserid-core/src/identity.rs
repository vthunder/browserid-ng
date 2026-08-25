//! Identity comparison (spec §5).
//!
//! Wherever the spec matches identities "exactly" (§6.1 step 6, §6.4 step 3),
//! the comparison is: domain part lowercased and in A-label (punycode) form,
//! local part byte-exact, no other normalization. Issuers and signing surfaces
//! MUST emit identity strings already in this form; the verifier-side
//! conversion here makes the comparison hold even for a U-label input.
//!
//! Grantee matchers (`*`, `*@<domain>`) are admission-only widenings of *who
//! matches* — permission, never attribution (§5, §6.6 invariant 6). A
//! `*@<domain>` matcher compares `<domain>` under the same rule against the
//! subject's entire domain part — subdomains do not match — and covers any
//! local part, subaddressed (§4.6) ones included.

/// The `(local, domain)` parts of a WELL-FORMED identity email: exactly one
/// `@`, non-empty on both sides (audit L1). This is THE canonical split —
/// identity call sites must not hand-roll `split('@')`/`rsplit_once`, whose
/// differing multi-`@` behaviors were the L1 parser differential. A malformed
/// address yields `None`, which every consumer treats fail-closed.
pub fn email_parts(email: &str) -> Option<(&str, &str)> {
    let (local, domain) = email.split_once('@')?;
    if local.is_empty() || domain.is_empty() || domain.contains('@') {
        return None;
    }
    Some((local, domain))
}

/// The domain part of a well-formed identity email (audit L1).
pub fn email_domain(email: &str) -> Option<&str> {
    email_parts(email).map(|(_, d)| d)
}

/// Lowercase + A-label (punycode) form of a domain, or `None` if the domain is
/// empty or not convertible. A `None` never compares equal to anything —
/// fail-closed.
pub fn normalize_domain(domain: &str) -> Option<String> {
    if domain.is_empty() {
        return None;
    }
    idna::domain_to_ascii(domain).ok().filter(|d| !d.is_empty())
}

/// Domain comparison under the §5 rule.
pub fn domain_eq(a: &str, b: &str) -> bool {
    match (normalize_domain(a), normalize_domain(b)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

/// Exact identity comparison under the §5 rule. Identities are always email
/// strings; a non-email (or malformed, e.g. multi-`@`) operand never compares
/// equal — fail-closed (audit L1).
pub fn identity_eq(a: &str, b: &str) -> bool {
    match (email_parts(a), email_parts(b)) {
        (Some((a_local, a_domain)), Some((b_local, b_domain))) => {
            a_local == b_local && domain_eq(a_domain, b_domain)
        }
        _ => false,
    }
}

/// Whether a grantee string is a matcher (`*` or `*@<domain>`) rather than an
/// exact email. Matchers are legal only on admission-consumed records; a
/// grantor is never a matcher.
pub fn is_grantee_matcher(s: &str) -> bool {
    s == "*" || s.starts_with("*@")
}

/// Does a record's `grantee` (exact email or matcher) cover an authenticated
/// subject identity? (§6.4 step 3.) `*` means any *authenticated* email —
/// callers only invoke this with a subject their binding's method actually
/// authenticated; the matcher never admits anonymous access.
pub fn grantee_covers(grantee: &str, subject: &str) -> bool {
    if grantee == "*" {
        return email_parts(subject).is_some();
    }
    if let Some(domain) = grantee.strip_prefix("*@") {
        return email_parts(subject)
            .is_some_and(|(_, subject_domain)| domain_eq(domain, subject_domain));
    }
    identity_eq(grantee, subject)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_parts_is_strict() {
        // The canonical exactly-one-@ parse (audit L1).
        assert_eq!(email_parts("dan@sandmill.org"), Some(("dan", "sandmill.org")));
        assert_eq!(email_parts("dan+tag@sandmill.org"), Some(("dan+tag", "sandmill.org")));
        for bad in ["", "dan", "@sandmill.org", "dan@", "a@b@c.com", "@", "dan@@x.com"] {
            assert_eq!(email_parts(bad), None, "'{bad}' must be malformed");
        }
    }

    #[test]
    fn malformed_emails_never_compare_or_cover() {
        assert!(!identity_eq("a@b@c.com", "a@b@c.com"));
        assert!(!grantee_covers("*", "a@b@c.com"));
        assert!(!grantee_covers("*@c.com", "a@b@c.com"));
    }

    #[test]
    fn exact_comparison_is_local_byte_exact_domain_case_insensitive() {
        assert!(identity_eq("alice@example.com", "alice@Example.COM"));
        // Local part is byte-exact — case matters.
        assert!(!identity_eq("Alice@example.com", "alice@example.com"));
        // Subaddresses are distinct exact identities.
        assert!(!identity_eq("alice+tag@example.com", "alice@example.com"));
        // Non-emails never compare equal, even to themselves.
        assert!(!identity_eq("not-an-email", "not-an-email"));
        assert!(!identity_eq("*", "*"));
    }

    #[test]
    fn domain_comparison_is_a_label() {
        // U-label vs A-label twin of the same IDN.
        assert!(domain_eq("bücher.example", "xn--bcher-kva.example"));
        assert!(identity_eq("a@bücher.example", "a@xn--bcher-kva.example"));
        assert!(!domain_eq("", ""));
    }

    #[test]
    fn domain_matcher_covers_locals_and_subaddresses_not_subdomains() {
        assert!(grantee_covers("*@example.com", "anyone@example.com"));
        assert!(grantee_covers("*@example.com", "anyone+tag@Example.com"));
        assert!(!grantee_covers("*@example.com", "anyone@sub.example.com"));
        assert!(!grantee_covers("*@example.com", "anyone@examplexcom"));
        assert!(!grantee_covers("*@", "anyone@example.com"));
    }

    #[test]
    fn star_matcher_covers_any_email_never_non_emails() {
        assert!(grantee_covers("*", "anyone@anywhere.example"));
        assert!(!grantee_covers("*", "not-an-email"));
    }

    #[test]
    fn exact_grantee_covers_only_itself() {
        assert!(grantee_covers("e@example.com", "e@example.com"));
        assert!(!grantee_covers("e@example.com", "f@example.com"));
    }

    #[test]
    fn matcher_detection() {
        assert!(is_grantee_matcher("*"));
        assert!(is_grantee_matcher("*@example.com"));
        assert!(!is_grantee_matcher("alice@example.com"));
        assert!(!is_grantee_matcher("a*@example.com"));
    }
}
