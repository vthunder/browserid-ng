//! Broker configuration

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Port to listen on
    pub port: u16,

    /// Domain this broker is hosted at
    pub domain: String,

    /// SMTP configuration for sending verification emails
    pub smtp: Option<SmtpConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub from_address: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            port: 3000,
            domain: "localhost".to_string(),
            smtp: None,
        }
    }
}
