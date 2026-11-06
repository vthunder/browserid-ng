//! The one clock rule (spec §6.1 "Time bounds"; audit 2026-11 Q28 / D16 /
//! S6 / W3-1 / W3-2).
//!
//! For every signed object a verifier checks — both certs, the warrant, the
//! assertion, each status list — reject unless `iat ≤ exp`, `iat ≤ now +
//! skew`, and the object is unexpired at `now`. Without the lower bound a
//! signer can post-date an object so that it stays "fresh" (a status list's
//! `ttl`, a `max-ttl` constraint computed as `exp − iat`) for as long as it
//! likes. Every comparison here is checked arithmetic: an overflow is a
//! violation, never a wrap (fail-closed).

use crate::jws::invalid;
use crate::Result;

/// The reference clock-skew allowance (seconds): how far in the future an
/// `iat` may sit before it is a clock lie rather than drift. A verifier MUST
/// NOT accept more (§6.1).
pub const CLOCK_SKEW_SECONDS: i64 = 300;

/// Check an object's `iat`/`exp` window at the instant `now`:
/// `iat ≤ exp`, `iat ≤ now + skew`, and not expired (`now ≤ exp` — the same
/// strict `at > exp ⇒ expired` rule `is_expired_at` has always used). `what`
/// names the object in the error. Checked arithmetic throughout: if
/// `now + skew` overflows the object is rejected.
pub fn check_window(what: &str, iat: i64, exp: i64, now: i64, skew: i64) -> Result<()> {
    if iat > exp {
        return Err(invalid(what, "issued after its expiry (iat > exp)"));
    }
    let Some(latest_iat) = now.checked_add(skew) else {
        return Err(invalid(what, "verification instant out of range"));
    };
    if iat > latest_iat {
        return Err(invalid(what, "issued in the future (iat > now + skew)"));
    }
    if now > exp {
        return Err(invalid(what, "expired"));
    }
    Ok(())
}

/// `exp − iat`, the validity width `max-ttl` constrains: `None` when the
/// window is inverted (`iat > exp`) or the subtraction overflows — both are
/// violations for the caller to reject (W3-1).
pub fn validity_width(iat: i64, exp: i64) -> Option<i64> {
    exp.checked_sub(iat).filter(|w| *w >= 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_rule() {
        let now = 1_000;
        assert!(check_window("x", 900, 2_000, now, 300).is_ok());
        // iat up to now + skew is drift; one past it is a lie.
        assert!(check_window("x", now + 300, 2_000, now, 300).is_ok());
        assert!(check_window("x", now + 301, 2_000, now, 300).is_err());
        // iat > exp never verifies, even when both are in the past.
        assert!(check_window("x", 500, 499, now, 300).is_err());
        // Expiry is strict `now > exp`.
        assert!(check_window("x", 900, now, now, 300).is_ok());
        assert!(check_window("x", 900, now - 1, now, 300).is_err());
    }

    #[test]
    fn arithmetic_is_checked() {
        assert!(check_window("x", 0, i64::MAX, i64::MAX, 1).is_err());
        assert!(check_window("x", i64::MIN, i64::MAX, 0, 300).is_ok());
        assert_eq!(validity_width(i64::MIN, 1), None);
        assert_eq!(validity_width(10, 5), None);
        assert_eq!(validity_width(5, 10), Some(5));
        assert_eq!(validity_width(5, 5), Some(0));
    }
}
