//! The central mint-authorization chokepoint (browserid-ng-u4xz, epic shyj).
//!
//! Every path that issues a broker-signed credential for an email — certs,
//! presentations, assertions — must call [`authorize_mint`] and obey its
//! decision. The match on `(EmailType, ProofMethod)` is EXHAUSTIVE on purpose:
//! adding a new email type or proof method fails compilation until someone
//! decides its mint policy, so a new route or provenance can never silently
//! skip the check the way the pre-epic `verified == true` gates did.
//!
//! The provenance classes (epic browserid-ng-shyj):
//! - E1 — domain-vouched by a primary IdP (`EmailType::Primary`). The broker
//!   NEVER signs for these; the primary issues its own certs.
//! - E2 — broker-signed but bridge-vouched (`Secondary` + `Oidc`/`Atproto`).
//!   The broker session alone never suffices: issuance requires a live bridge
//!   proof (which may silently reuse the bridge's own session — its choice).
//! - E3 — broker-vouched via the SMTP loop (`Secondary` + `Smtp`). Password
//!   territory: minting requires a Full session. A fresh SMTP proof does NOT
//!   silently mint; for a password-backed account the inbox's channel is the
//!   reset flow.
//! - Agent identities (`EmailType::Agent`) are broker-native, minted via the
//!   delegation chain and controlled by their parent. The broker itself is
//!   their voucher, so — like E3 — signing in AS one requires the account
//!   password (Full session).
//!
//! Paths deliberately OUTSIDE the chokepoint:
//! - `/access/mint` — authed by a broker-issued device cert, i.e. by a
//!   credential this chokepoint already authorized at issuance; revocation is
//!   the recourse, not a second provenance decision.
//! - `/idp/device_cert` / `/idp/access_cert` — the hosted-primary TENANT's own
//!   issuance (roster-password-authed, tenant keys). That is the E1 voucher
//!   itself, not the broker deciding off its session.

use crate::store::{Email, EmailType, ProofMethod, SessionLevel};

/// Which voucher a delegated mint must come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Voucher {
    /// The email's own primary IdP (E1).
    Primary,
    /// The OIDC (Google) bridge (E2).
    Oidc,
    /// The atproto/Bluesky bridge (E2).
    Atproto,
}

/// The chokepoint's verdict for one (email, session-level) pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MintDecision {
    /// The broker session suffices — mint broker-signed credentials.
    Allow,
    /// Step-up required: the account password (a Full session) must be
    /// presented first. HTTP surfaces map this to 401.
    NeedPassword,
    /// The broker session alone must NEVER mint this email; issuance is
    /// delegated to the named voucher, which runs its own live proof and
    /// decides the cert TTL (browserid-ng-pr3a).
    Delegate(Voucher),
}

/// Decide whether a mint for `email` is authorized under a session of
/// `level`. Callers must have already established that the session's account
/// OWNS the (verified) email — this function decides provenance policy only.
pub fn authorize_mint(email: &Email, level: SessionLevel) -> MintDecision {
    match (email.email_type, email.proof) {
        // E1: the primary vouches; the broker never signs off its own session.
        (EmailType::Primary, _) => MintDecision::Delegate(Voucher::Primary),

        // E2: broker-signed, but only against a live bridge proof.
        (EmailType::Secondary, ProofMethod::Oidc) => MintDecision::Delegate(Voucher::Oidc),
        (EmailType::Secondary, ProofMethod::Atproto) => MintDecision::Delegate(Voucher::Atproto),

        // E3: password territory.
        (EmailType::Secondary, ProofMethod::Smtp) => match level {
            SessionLevel::Full => MintDecision::Allow,
            SessionLevel::Lightweight => MintDecision::NeedPassword,
        },

        // Agent identities: broker-native, the broker is the voucher — same
        // password rule as E3 regardless of how the identity was proven.
        (EmailType::Agent, _) => match level {
            SessionLevel::Full => MintDecision::Allow,
            SessionLevel::Lightweight => MintDecision::NeedPassword,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use crate::store::UserId;

    fn email(email_type: EmailType, proof: ProofMethod) -> Email {
        Email {
            email: "x@example.com".to_string(),
            user_id: UserId(1),
            verified: true,
            verified_at: Some(Utc::now()),
            email_type,
            last_used_as: email_type,
            parent_email: None,
            display_name: None,
            public_name: None,
            proof,
            proof_subject: None,
        }
    }

    /// The full (EmailType × ProofMethod × SessionLevel) matrix. This is the
    /// epic's regression table: every combination has an expected decision,
    /// and a new enum variant fails compilation in `authorize_mint` before it
    /// can silently pass here.
    #[test]
    fn decision_matrix() {
        use EmailType::*;
        use MintDecision::*;
        use ProofMethod::*;
        use SessionLevel::*;

        let cases: &[(EmailType, ProofMethod, SessionLevel, MintDecision)] = &[
            // E1: always the primary's call, session level irrelevant.
            (Primary, Smtp, Full, Delegate(Voucher::Primary)),
            (Primary, Smtp, Lightweight, Delegate(Voucher::Primary)),
            (Primary, Oidc, Full, Delegate(Voucher::Primary)),
            (Primary, Oidc, Lightweight, Delegate(Voucher::Primary)),
            (Primary, Atproto, Full, Delegate(Voucher::Primary)),
            (Primary, Atproto, Lightweight, Delegate(Voucher::Primary)),
            // E2: always the bridge's call, session level irrelevant.
            (Secondary, Oidc, Full, Delegate(Voucher::Oidc)),
            (Secondary, Oidc, Lightweight, Delegate(Voucher::Oidc)),
            (Secondary, Atproto, Full, Delegate(Voucher::Atproto)),
            (Secondary, Atproto, Lightweight, Delegate(Voucher::Atproto)),
            // E3: the password gate.
            (Secondary, Smtp, Full, Allow),
            (Secondary, Smtp, Lightweight, NeedPassword),
            // Agent identities: broker-vouched ⇒ same password gate as E3.
            (Agent, Smtp, Full, Allow),
            (Agent, Smtp, Lightweight, NeedPassword),
            (Agent, Oidc, Full, Allow),
            (Agent, Oidc, Lightweight, NeedPassword),
            (Agent, Atproto, Full, Allow),
            (Agent, Atproto, Lightweight, NeedPassword),
        ];

        for (email_type, proof, level, expected) in cases {
            let rec = email(*email_type, *proof);
            assert_eq!(
                authorize_mint(&rec, *level),
                *expected,
                "({email_type:?}, {proof:?}, {level:?})"
            );
        }
    }
}
