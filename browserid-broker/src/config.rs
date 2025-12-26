//! Configuration for the broker

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use browserid_core::KeyPair;
use serde::{Deserialize, Serialize};

/// Broker configuration
#[derive(Debug, Clone)]
pub struct Config {
    /// HTTP port to listen on
    pub port: u16,
    /// Broker domain (e.g., "localhost:3000")
    pub domain: String,
    /// Path to keypair file
    pub key_file: String,
    /// Path to SQLite database file
    pub database_path: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            port: 3000,
            domain: "localhost:3000".to_string(),
            key_file: "broker-key.json".to_string(),
            database_path: "browserid.db".to_string(),
        }
    }
}

impl Config {
    /// Create config from environment variables
    pub fn from_env() -> Self {
        let port = std::env::var("BROKER_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(3000);

        let domain = std::env::var("BROKER_DOMAIN")
            .unwrap_or_else(|_| format!("localhost:{}", port));

        let key_file = std::env::var("BROKER_KEY_FILE")
            .unwrap_or_else(|_| "broker-key.json".to_string());

        let database_path = std::env::var("DATABASE_PATH")
            .unwrap_or_else(|_| "browserid.db".to_string());

        Self {
            port,
            domain,
            key_file,
            database_path,
        }
    }
}

/// Serializable keypair for storage
#[derive(Serialize, Deserialize)]
struct StoredKeypair {
    secret_key: String,
}

/// Load or generate a keypair
pub fn load_or_generate_keypair(path: &str) -> Result<KeyPair> {
    if Path::new(path).exists() {
        load_keypair(path)
    } else {
        let keypair = KeyPair::generate();
        save_keypair(path, &keypair)?;
        tracing::info!("Generated new keypair and saved to {}", path);
        Ok(keypair)
    }
}

fn load_keypair(path: &str) -> Result<KeyPair> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("Failed to read keypair from {}", path))?;

    let stored: StoredKeypair = serde_json::from_str(&contents)
        .with_context(|| "Failed to parse keypair JSON")?;

    let secret_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        &stored.secret_key,
    )
    .with_context(|| "Failed to decode secret key")?;

    KeyPair::from_seed(&secret_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to create keypair: {}", e))
}

fn save_keypair(path: &str, keypair: &KeyPair) -> Result<()> {
    let secret_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        keypair.secret_bytes(),
    );

    let stored = StoredKeypair {
        secret_key: secret_b64,
    };

    let json = serde_json::to_string_pretty(&stored)?;
    fs::write(path, json)
        .with_context(|| format!("Failed to write keypair to {}", path))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_keypair_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test-key.json");
        let path_str = path.to_str().unwrap();

        // Generate and save
        let kp1 = load_or_generate_keypair(path_str).unwrap();

        // Load again
        let kp2 = load_or_generate_keypair(path_str).unwrap();

        // Should be the same key
        assert_eq!(kp1.public_key(), kp2.public_key());
    }
}
