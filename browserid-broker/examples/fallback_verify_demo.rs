//! Milestone-1 proof for apgv: a cert issued by fallback.sandmill.org's key
//! verifies through its DNSSEC `_browserid` record — browserid.me not in the
//! trust chain. Signs a cert+assertion with the fallback's real key (the same
//! seed set as BROKER_KEY_SECRET on the deployed app) and prints the backed
//! assertion to verify.
//!
//! Usage: cargo run -p browserid-broker --example fallback_verify_demo -- <seed> <audience>

use browserid_core::{Assertion, Certificate, KeyPair};
use chrono::Duration;

fn main() {
    let seed_b64 = std::env::args().nth(1).expect("arg1: fallback key seed (base64url)");
    let audience = std::env::args().nth(2).unwrap_or_else(|| "https://demo-rp.example".into());

    let seed = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        seed_b64.trim(),
    )
    .expect("decode seed");
    let fallback_key = KeyPair::from_seed(&seed).expect("keypair from seed");

    // A user keypair the fallback vouches for (the RP-facing subject key).
    let user_key = KeyPair::generate();
    let cert = Certificate::create(
        "fallback.sandmill.org",       // iss = the fallback's domain
        "demo-user@example.com",       // an email the fallback verified (any domain)
        &user_key.public_key(),
        Duration::hours(24),
        &fallback_key,                 // signed by the fallback's DNSSEC-published key
    )
    .expect("create cert");
    let assertion = Assertion::create(&audience, Duration::minutes(5), &user_key).expect("assertion");

    // Backed assertion wire format: <cert>~<assertion>
    println!("{}~{}", cert.encoded(), assertion.encoded());
}
