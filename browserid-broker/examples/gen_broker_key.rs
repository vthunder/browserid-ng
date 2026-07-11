//! Generate a broker/fallback signing keypair and print (a) the base64url
//! secret seed for `BROKER_KEY_SECRET` (keep secret) and (b) the exact
//! `_browserid` DNS TXT record to publish (public).
//!
//! Usage: cargo run -p browserid-broker --example gen_broker_key -- <domain>

use base64::Engine;
use browserid_core::KeyPair;

fn main() {
    let domain = std::env::args().nth(1).unwrap_or_else(|| "example.com".into());
    let kp = KeyPair::generate();
    let secret = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(kp.secret_bytes());
    let pubkey = kp.public_key().to_base64();

    println!("domain: {domain}");
    println!();
    println!("--- server secret (set as BROKER_KEY_SECRET; keep private) ---");
    println!("{secret}");
    println!();
    println!("--- DNS: TXT record at _browserid.{domain} (public) ---");
    println!("v=browserid1; public-key-algorithm=Ed25519; public-key={pubkey}; host={domain}");
}
