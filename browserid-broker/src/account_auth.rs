//! Account authentication (bean noqd; docs/plans/2026-09-14-account-
//! authentication-policy-draft.md): the one place that decides whether
//! what a ceremony collected lets a device into the account, and mints
//! the login-page token that carries that decision to the registry.
//!
//! Both of the broker's doors call in here: the registry login page's
//! backend (`/wsapi/registry_login`) today, and the fallback IdP's
//! ceremony page once issuer and registry share the check (bean 73ok).
//! The policy itself lives in `browserid_registrar::policy`; this module
//! only gathers the facts the broker knows (the account's identity count,
//! its stored policy) and applies them.

use chrono::{Duration, Utc};

use browserid_registrar::policy::{self, AccountPolicy, Facts};

use crate::error::BrokerError;
use crate::store::{LoginToken, UserId, UserStore};

/// Login-page tokens live this long.
pub const LOGIN_TOKEN_SECONDS: i64 = 300;

/// One thing a ceremony established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Proof {
    /// The account password was verified.
    Password,
    /// This identity of the account was proven at its issuer.
    Identity(String),
    /// A device already enrolled approved, by the login key with this kid.
    Approval { kid: String },
}

/// What the ceremony amounts to, once the policy is applied.
#[derive(Debug, Clone)]
pub struct Outcome {
    /// The enrol rule is met.
    pub met: bool,
    /// `password` | `proofs` | `approval` — what the enrolled key records.
    pub method: String,
    /// The identities proven (JSON array) or the approving kid.
    pub detail: Option<String>,
}

/// The account's policy as stored (baseline when none).
pub fn account_policy<U: UserStore>(store: &U, user_id: UserId) -> Result<AccountPolicy, BrokerError> {
    Ok(policy::parse(store.get_account_policy(user_id)?.as_deref()))
}

/// How many identities the account holds (active, verified addresses that
/// are identities of their own — the roster the registry sees).
pub fn identity_count<U: UserStore>(store: &U, user_id: UserId) -> Result<u32, BrokerError> {
    Ok(crate::membership::roster(store, user_id)?
        .iter()
        .filter(|(_, s)| *s == "active")
        .count() as u32)
}

fn facts_of(proofs: &[Proof], identities: u32) -> Facts {
    let mut f = Facts { identities, ..Default::default() };
    for p in proofs {
        match p {
            Proof::Password => f.password = true,
            Proof::Identity(i) => f.proofs.push(i.to_lowercase()),
            Proof::Approval { .. } => f.approval = true,
        }
    }
    f
}

/// Apply the account's enrol rule to what the ceremony collected.
pub fn evaluate<U: UserStore>(store: &U, user_id: UserId, proofs: &[Proof]) -> Result<Outcome, BrokerError> {
    let p = account_policy(store, user_id)?;
    let f = facts_of(proofs, identity_count(store, user_id)?);
    let req = p.enrol();
    let met = req.met(&f);
    let method = req.enrolled_by(&f).unwrap_or(policy::ENROLLED_BY_PASSWORD).to_string();
    let detail = match method.as_str() {
        policy::ENROLLED_BY_PROOFS => Some(serde_json::to_string(&f.proofs).unwrap_or_else(|_| "[]".into())),
        policy::ENROLLED_BY_APPROVAL => proofs.iter().find_map(|p| match p {
            Proof::Approval { kid } => Some(kid.clone()),
            _ => None,
        }),
        _ => None,
    };
    Ok(Outcome { met, method, detail })
}

/// Mint the one-time login-page token for an outcome that met the rule.
/// The token remembers the method so the registry records it on the key
/// it enrols (§4.2 `enrolled_by`).
pub fn mint_login_token<U: UserStore>(store: &U, user_id: UserId, outcome: &Outcome) -> Result<String, BrokerError> {
    if !outcome.met {
        return Err(BrokerError::PolicyRefused("login_rejected".into()));
    }
    let token = crate::crypto::generate_salt_b64() + &crate::crypto::generate_salt_b64();
    store.create_login_token(LoginToken {
        token_hash: browserid_registrar::session::b64url_sha256_pub(token.as_bytes()),
        user_id,
        expires_at: Utc::now() + Duration::seconds(LOGIN_TOKEN_SECONDS),
        method: outcome.method.clone(),
        detail: outcome.detail.clone(),
    })?;
    Ok(token)
}

/// What a device that holds `key` has proven itself: the identities of
/// the active certs recorded under it (registry-api-v1 §4.2).
pub fn proven_by_key<U: UserStore>(store: &U, user_id: UserId, key_id: u64) -> Result<Vec<String>, BrokerError> {
    let mut out: Vec<String> = Vec::new();
    for c in store.list_device_certs(user_id)? {
        if c.login_key_id == Some(key_id) && c.revoked_at.is_none() && c.expires_at > Utc::now() {
            for i in &c.identities {
                if !i.contains('*') && !out.iter().any(|x| x.eq_ignore_ascii_case(i)) {
                    out.push(i.to_lowercase());
                }
            }
        }
    }
    Ok(out)
}

/// Whether the account's mint rule (§5.2.7) holds for a device asking on
/// its login key to mint `identity` (bean 73ok).
pub fn mint_rule_met<U: UserStore>(
    store: &U,
    user_id: UserId,
    key: &browserid_registrar::models::LoginCertRecord,
    identity: &str,
) -> Result<bool, BrokerError> {
    let p = account_policy(store, user_id)?;
    let f = Facts {
        enrolled: key.is_live(),
        proven: proven_by_key(store, user_id, key.id)?,
        enrolled_by: Some(key.enrolled_by.clone()),
        identities: identity_count(store, user_id)?,
        ..Default::default()
    };
    Ok(p.mint(identity).met(&f))
}

/// The proofs a cookie session amounts to for the identity it just had
/// issued: the password when the session is Full, the identity itself
/// (the ceremony proved it at this issuer). What the ceremony page hands
/// the account-authentication check when the issuer is also the registry.
pub fn proofs_of_session(level: crate::store::SessionLevel, identity: &str) -> Vec<Proof> {
    let mut v = vec![Proof::Identity(identity.to_lowercase())];
    if level == crate::store::SessionLevel::Full {
        v.push(Proof::Password);
    }
    v
}

/// Evaluate and mint in one step: the token, or `login_rejected`.
pub fn login_token_for<U: UserStore>(store: &U, user_id: UserId, proofs: &[Proof]) -> Result<String, BrokerError> {
    let outcome = evaluate(store, user_id, proofs)?;
    mint_login_token(store, user_id, &outcome)
}
