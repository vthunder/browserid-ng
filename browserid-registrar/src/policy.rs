//! Account authentication policy (registry-api-v1 §4.2, bean noqd): which
//! combinations of proofs let a device into an account, and what an
//! enrolled device may then mint. Requirements are data — a list of
//! alternatives, each a set of conditions — evaluated at two chokepoints:
//! the registry when it enrols a login key, and the issuer (when it is the
//! same entity) when it decides whether to mint on a login key.
//!
//! Three layers: the [`baseline`], an account's stored override (edited on
//! the account page, within [`AccountPolicy::validate`]'s floors), and,
//! later, signal-driven tightening. Design: docs/plans/2026-09-14-account-
//! authentication-policy-draft.md.

use serde::{Deserialize, Serialize};

/// How a login key was enrolled (§4.2 `enrolled_by`).
pub const ENROLLED_BY_PASSWORD: &str = "password";
pub const ENROLLED_BY_PROOFS: &str = "proofs";
pub const ENROLLED_BY_APPROVAL: &str = "approval";

/// The proof count the baseline asks for, capped by the account's
/// identity count.
pub const BASELINE_PROOFS: u32 = 2;

/// One condition a ceremony can satisfy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Condition {
    /// The account password was presented in this ceremony.
    Password,
    /// At least `k` distinct identities of the account were proven at
    /// their issuers in this ceremony (capped by the identity count).
    Proofs { k: u32 },
    /// A device already enrolled approved this one.
    Approval,
    /// The calling device's login key is enrolled and live.
    Enrolled,
    /// The calling device has itself proven at least `k` identities.
    Proven { k: u32 },
    /// The calling device has itself proven this identity.
    ProvenIdentity { identity: String },
    /// The calling device's key was enrolled by one of these methods.
    EnrolledBy { methods: Vec<String> },
}

/// A requirement: any one alternative (a set of conditions) satisfies it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Requirement {
    pub alternatives: Vec<Vec<Condition>>,
}

/// What the ceremony (or the calling device) brought.
#[derive(Debug, Clone, Default)]
pub struct Facts {
    pub password: bool,
    /// Identities proven at their issuers in this ceremony, lowercase.
    pub proofs: Vec<String>,
    pub approval: bool,
    /// The calling device's key, when enrolled and live.
    pub enrolled: bool,
    /// Identities the calling device has proven itself (certs recorded
    /// under sessions on its key), lowercase.
    pub proven: Vec<String>,
    pub enrolled_by: Option<String>,
    /// How many identities the account has: caps every `k`.
    pub identities: u32,
}

fn distinct(v: &[String]) -> u32 {
    let mut seen: Vec<&str> = Vec::new();
    for s in v {
        if !seen.iter().any(|x| x.eq_ignore_ascii_case(s)) {
            seen.push(s);
        }
    }
    seen.len() as u32
}

impl Condition {
    pub fn holds(&self, f: &Facts) -> bool {
        match self {
            Condition::Password => f.password,
            Condition::Proofs { k } => {
                let need = (*k).min(f.identities.max(1));
                distinct(&f.proofs) >= need
            }
            Condition::Approval => f.approval,
            Condition::Enrolled => f.enrolled,
            Condition::Proven { k } => f.enrolled && distinct(&f.proven) >= (*k).min(f.identities.max(1)),
            Condition::ProvenIdentity { identity } => {
                f.enrolled && f.proven.iter().any(|p| p.eq_ignore_ascii_case(identity))
            }
            Condition::EnrolledBy { methods } => {
                f.enrolled && f.enrolled_by.as_deref().is_some_and(|m| methods.iter().any(|x| x == m))
            }
        }
    }
}

impl Requirement {
    pub fn met(&self, f: &Facts) -> bool {
        self.alternatives.iter().any(|alt| !alt.is_empty() && alt.iter().all(|c| c.holds(f)))
    }

    /// Which alternative is met, as the `enrolled_by` method it implies:
    /// password beats proofs beats approval when several hold.
    pub fn enrolled_by(&self, f: &Facts) -> Option<&'static str> {
        if !self.met(f) {
            return None;
        }
        if f.password {
            Some(ENROLLED_BY_PASSWORD)
        } else if !f.proofs.is_empty() {
            Some(ENROLLED_BY_PROOFS)
        } else if f.approval {
            Some(ENROLLED_BY_APPROVAL)
        } else {
            None
        }
    }
}

/// An account's stored policy: the knobs a user may turn, applied on top
/// of the baseline. Every field is optional on the wire; absent means
/// baseline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AccountPolicy {
    /// Proofs needed to enrol by identity proofs (baseline 2; floor 1;
    /// capped by the identity count at evaluation).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proofs: Option<u32>,
    /// The password must be part of every way in (baseline false).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_required: Option<bool>,
    /// Whether approval from an enrolled device may enrol a new one
    /// (baseline true).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<bool>,
    /// Identities a device must have proven itself before the issuer
    /// mints broker-vouched certs on its login key (baseline 0).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mint_proven: Option<u32>,
    /// Specific identities a device must have proven itself before it
    /// mints (baseline none).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mint_proven_identities: Option<Vec<String>>,
}

impl AccountPolicy {
    /// The floors: nothing here can make enrolment satisfiable by nothing,
    /// or ask for more proofs than the account can give. `identities` is
    /// the account's identity count, `has_password` whether it has one.
    pub fn validate(&self, identities: u32, has_password: bool) -> Result<(), String> {
        if let Some(k) = self.proofs {
            if k < 1 {
                return Err("proofs must be at least 1".into());
            }
            if k > identities.max(1) {
                return Err(format!("proofs cannot exceed the account's {identities} identities"));
            }
        }
        if self.password_required == Some(true) && !has_password {
            return Err("the account has no password to require".into());
        }
        if let Some(k) = self.mint_proven {
            if k > identities.max(1) {
                return Err(format!("mint_proven cannot exceed the account's {identities} identities"));
            }
        }
        if let Some(ids) = &self.mint_proven_identities {
            if ids.iter().any(|i| i.trim().is_empty() || !i.contains('@')) {
                return Err("mint_proven_identities must be addresses".into());
            }
        }
        Ok(())
    }

    /// The enrol requirement (draft: `password | proofs >= k | approval`),
    /// with `password_required` folding the password into every
    /// alternative and `approval: false` dropping that alternative.
    pub fn enrol(&self) -> Requirement {
        let k = self.proofs.unwrap_or(BASELINE_PROOFS).max(1);
        let pinned = self.password_required.unwrap_or(false);
        let mut alts: Vec<Vec<Condition>> = vec![vec![Condition::Password]];
        let mut proofs = vec![Condition::Proofs { k }];
        let mut approval = vec![Condition::Approval];
        if pinned {
            proofs.push(Condition::Password);
            approval.push(Condition::Password);
        }
        alts.push(proofs);
        if self.approval.unwrap_or(true) {
            alts.push(approval);
        }
        Requirement { alternatives: alts }
    }

    /// The mint requirement for a broker-vouched identity on a login key
    /// (baseline: `enrolled`).
    pub fn mint(&self, identity: &str) -> Requirement {
        let mut alt = vec![Condition::Enrolled];
        if let Some(k) = self.mint_proven.filter(|k| *k > 0) {
            alt.push(Condition::Proven { k });
        }
        // Every listed identity must have been proven by this device,
        // whichever identity it is minting.
        let _ = identity;
        for i in self.mint_proven_identities.iter().flatten() {
            alt.push(Condition::ProvenIdentity { identity: i.to_lowercase() });
        }
        Requirement { alternatives: vec![alt] }
    }

    /// The reset requirement (draft): `proofs >= k`, approval never.
    pub fn reset(&self) -> Requirement {
        let k = self.proofs.unwrap_or(BASELINE_PROOFS).max(1);
        Requirement { alternatives: vec![vec![Condition::Proofs { k }]] }
    }
}

/// The baseline policy: every knob at its default.
pub fn baseline() -> AccountPolicy {
    AccountPolicy::default()
}

/// Parse a stored policy; `None` or unparsable rows fall back to the
/// baseline (a bad row can never loosen anything below it).
pub fn parse(stored: Option<&str>) -> AccountPolicy {
    stored.and_then(|s| serde_json::from_str(s).ok()).unwrap_or_default()
}

/// The policy as the account page sees it: stored knobs plus the
/// resolved values.
pub fn describe(p: &AccountPolicy, identities: u32, has_password: bool) -> serde_json::Value {
    serde_json::json!({
        "policy": p,
        "effective": {
            "proofs": p.proofs.unwrap_or(BASELINE_PROOFS).min(identities.max(1)),
            "password_required": p.password_required.unwrap_or(false),
            "approval": p.approval.unwrap_or(true),
            "mint_proven": p.mint_proven.unwrap_or(0),
            "mint_proven_identities": p.mint_proven_identities.clone().unwrap_or_default(),
        },
        "identities": identities,
        "has_password": has_password,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts() -> Facts {
        Facts { identities: 2, ..Default::default() }
    }

    #[test]
    fn baseline_enrol_takes_password_two_proofs_or_approval() {
        let r = baseline().enrol();
        assert!(!r.met(&facts()));
        assert!(r.met(&Facts { password: true, ..facts() }));
        assert!(r.met(&Facts { approval: true, ..facts() }));
        assert!(!r.met(&Facts { proofs: vec!["a@x.org".into()], ..facts() }));
        assert!(r.met(&Facts { proofs: vec!["a@x.org".into(), "b@y.org".into()], ..facts() }));
        // Two proofs of the same identity are one.
        assert!(!r.met(&Facts { proofs: vec!["a@x.org".into(), "A@X.org".into()], ..facts() }));
    }

    #[test]
    fn proof_count_is_capped_by_the_identity_count() {
        let r = baseline().enrol();
        let single = Facts { identities: 1, proofs: vec!["a@x.org".into()], ..Default::default() };
        assert!(r.met(&single), "a single-identity account can only ever give one proof");
        assert_eq!(r.enrolled_by(&single), Some(ENROLLED_BY_PROOFS));
    }

    #[test]
    fn password_required_folds_into_every_alternative() {
        let p = AccountPolicy { password_required: Some(true), ..Default::default() };
        let r = p.enrol();
        assert!(!r.met(&Facts { approval: true, ..facts() }));
        assert!(r.met(&Facts { approval: true, password: true, ..facts() }));
        assert_eq!(r.enrolled_by(&Facts { approval: true, password: true, ..facts() }), Some(ENROLLED_BY_PASSWORD));
    }

    #[test]
    fn approval_can_be_disabled_and_reset_never_takes_it() {
        let p = AccountPolicy { approval: Some(false), ..Default::default() };
        assert!(!p.enrol().met(&Facts { approval: true, ..facts() }));
        assert!(!baseline().reset().met(&Facts { approval: true, password: true, ..facts() }));
        assert!(baseline().reset().met(&Facts { proofs: vec!["a@x.org".into(), "b@y.org".into()], ..facts() }));
    }

    #[test]
    fn mint_rule_baseline_is_enrolled_and_overrides_add_proven() {
        let dev = Facts { enrolled: true, proven: vec![], ..facts() };
        assert!(baseline().mint("a@x.org").met(&dev));
        assert!(!baseline().mint("a@x.org").met(&Facts { enrolled: false, ..dev.clone() }));
        let p = AccountPolicy { mint_proven: Some(2), ..Default::default() };
        assert!(!p.mint("a@x.org").met(&dev));
        assert!(p.mint("a@x.org").met(&Facts { proven: vec!["a@x.org".into(), "b@y.org".into()], ..dev.clone() }));
        let p = AccountPolicy { mint_proven_identities: Some(vec!["b@y.org".into()]), ..Default::default() };
        assert!(!p.mint("a@x.org").met(&dev));
        assert!(p.mint("a@x.org").met(&Facts { proven: vec!["B@y.org".into()], ..dev }));
    }

    #[test]
    fn floors() {
        assert!(AccountPolicy { proofs: Some(0), ..Default::default() }.validate(2, true).is_err());
        assert!(AccountPolicy { proofs: Some(3), ..Default::default() }.validate(2, true).is_err());
        assert!(AccountPolicy { proofs: Some(2), ..Default::default() }.validate(2, true).is_ok());
        assert!(AccountPolicy { password_required: Some(true), ..Default::default() }.validate(2, false).is_err());
        assert!(AccountPolicy { mint_proven_identities: Some(vec!["nope".into()]), ..Default::default() }.validate(2, true).is_err());
    }

    #[test]
    fn bad_rows_fall_back_to_baseline() {
        assert_eq!(parse(Some("{\"nope\":1}")), baseline());
        assert_eq!(parse(None), baseline());
        let p = AccountPolicy { proofs: Some(1), ..Default::default() };
        assert_eq!(parse(Some(&serde_json::to_string(&p).unwrap())), p);
    }
}
