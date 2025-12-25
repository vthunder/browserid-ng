//! Broker state management

use browserid_core::KeyPair;

/// Broker application state
pub struct BrokerState {
    /// The broker's signing keypair
    pub signing_key: KeyPair,
    // TODO: Add pending email verification state storage
}

impl BrokerState {
    pub fn new() -> Self {
        Self {
            signing_key: KeyPair::generate(),
        }
    }
}
