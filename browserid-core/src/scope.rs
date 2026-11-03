//! The one scope grammar (registry-api-v1 §3; audit 2026-11 W3-3 / W5-11,
//! decision Q27): every scope STRING — a bare `scopes` entry or the `scope`
//! field of a parameterized entry — matches
//! `^[a-z0-9_:.\-/*@+]{1,128}$`. The wallet enforces it at request time;
//! every Rust signer and filer (the registrar's grant-shape check, the
//! admission authoring path, any surface that mints a warrant) MUST call
//! [`validate_scope_string`] too, so a string outside the grammar (empty,
//! uppercase, whitespace, control or bidi characters, non-ASCII) is never
//! signed into a warrant or rendered on a consent card.
//!
//! The check is a byte-level predicate: no regex engine, total on any input.

/// Longest scope string (bytes) the grammar admits.
pub const SCOPE_MAX_BYTES: usize = 128;

/// The grammar as the regex the specs quote, for error messages and
/// cross-language conformance tests.
pub const SCOPE_GRAMMAR_REGEX: &str = r"^[a-z0-9_:.\-/*@+]{1,128}$";

/// Does `s` match the one scope grammar `^[a-z0-9_:.\-/*@+]{1,128}$`?
/// Byte-exact: 1–128 bytes, each one of `a-z`, `0-9`, `_`, `:`, `.`, `-`,
/// `/`, `*`, `@`, `+`. Everything else — including an empty string, any
/// uppercase letter, whitespace, and every non-ASCII byte — is rejected.
pub fn validate_scope_string(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= SCOPE_MAX_BYTES
        && s.bytes().all(|b| {
            matches!(
                b,
                b'a'..=b'z' | b'0'..=b'9' | b'_' | b':' | b'.' | b'-' | b'/' | b'*' | b'@' | b'+'
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_the_grammar() {
        for s in [
            "login",
            "tool:read_file",
            "sign:sbo:post",
            "pay:usd",
            "as:dan@sandmill.org",
            "path:/notes/*",
            "a+b",
            "x",
            &"a".repeat(128),
        ] {
            assert!(validate_scope_string(s), "{s:?} must be accepted");
        }
    }

    #[test]
    fn rejects_everything_else() {
        for s in [
            "",
            "Login",
            "tool read",
            " login",
            "login\n",
            "tool:\u{202e}read",
            "tool:r\u{0000}ead",
            "löschen",
            "tool,read",
            "tool#read",
            &"a".repeat(129),
        ] {
            assert!(!validate_scope_string(s), "{s:?} must be rejected");
        }
    }

    #[test]
    fn regex_constant_matches_the_spec() {
        assert_eq!(SCOPE_GRAMMAR_REGEX, r"^[a-z0-9_:.\-/*@+]{1,128}$");
    }
}
