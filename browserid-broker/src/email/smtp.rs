//! SMTP-based email sender for production

use lettre::{
    message::header::ContentType,
    transport::smtp::authentication::Credentials,
    Message, SmtpTransport, Transport,
};

use super::EmailSender;

/// Configuration for SMTP email sending
#[derive(Debug, Clone)]
pub struct SmtpConfig {
    /// SMTP server host (e.g., "smtp.resend.com")
    pub host: String,
    /// SMTP server port (typically 465 for TLS, 587 for STARTTLS)
    pub port: u16,
    /// SMTP username
    pub username: String,
    /// SMTP password (or API key for services like Resend)
    pub password: String,
    /// From email address
    pub from_email: String,
    /// From name (optional)
    pub from_name: Option<String>,
}

impl SmtpConfig {
    /// Create config from environment variables
    ///
    /// Required:
    /// - SMTP_HOST
    /// - SMTP_USERNAME
    /// - SMTP_PASSWORD
    /// - SMTP_FROM_EMAIL
    ///
    /// Optional:
    /// - SMTP_PORT (default: 465)
    /// - SMTP_FROM_NAME
    pub fn from_env() -> Option<Self> {
        // Helper to get non-empty env var
        fn get_env(key: &str) -> Option<String> {
            std::env::var(key).ok().filter(|s| !s.is_empty())
        }

        let host = get_env("SMTP_HOST")?;
        let username = get_env("SMTP_USERNAME")?;
        let password = get_env("SMTP_PASSWORD")?;
        let from_email = get_env("SMTP_FROM_EMAIL")?;

        let port = std::env::var("SMTP_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(465);

        let from_name = std::env::var("SMTP_FROM_NAME").ok();

        Some(Self {
            host,
            port,
            username,
            password,
            from_email,
            from_name,
        })
    }
}

/// SMTP email sender for production use
pub struct SmtpEmailSender {
    transport: SmtpTransport,
    from_email: String,
    from_name: Option<String>,
}

impl SmtpEmailSender {
    /// Create a new SMTP email sender
    pub fn new(config: SmtpConfig) -> Result<Self, String> {
        let creds = Credentials::new(config.username, config.password);

        let transport = SmtpTransport::relay(&config.host)
            .map_err(|e| format!("Failed to create SMTP transport: {}", e))?
            .port(config.port)
            .credentials(creds)
            .build();

        // Test the connection
        transport
            .test_connection()
            .map_err(|e| format!("SMTP connection test failed: {}", e))?;

        tracing::info!(host = %config.host, port = config.port, "SMTP connection established");

        Ok(Self {
            transport,
            from_email: config.from_email,
            from_name: config.from_name,
        })
    }

    fn from_address(&self) -> String {
        match &self.from_name {
            Some(name) => format!("{} <{}>", name, self.from_email),
            None => self.from_email.clone(),
        }
    }

    fn send_email(&self, to: &str, subject: &str, body: &str) -> Result<(), String> {
        let from = self
            .from_address()
            .parse()
            .map_err(|e| format!("Invalid from address: {}", e))?;

        let to_addr = to
            .parse()
            .map_err(|e| format!("Invalid to address: {}", e))?;

        let email = Message::builder()
            .from(from)
            .to(to_addr)
            .subject(subject)
            .header(ContentType::TEXT_PLAIN)
            .body(body.to_string())
            .map_err(|e| format!("Failed to build email: {}", e))?;

        self.transport
            .send(&email)
            .map_err(|e| format!("Failed to send email: {}", e))?;

        Ok(())
    }
}

impl EmailSender for SmtpEmailSender {
    fn send_verification(&self, email: &str, code: &str) -> Result<(), String> {
        let subject = "Your verification code";
        let body = format!(
            "Your verification code is: {}\n\n\
             Enter this code to verify your email address.\n\n\
             If you didn't request this, you can safely ignore this email.",
            code
        );

        self.send_email(email, subject, &body)?;
        tracing::info!(email = %email, "Verification email sent");
        Ok(())
    }

    fn send_password_reset(&self, email: &str, code: &str) -> Result<(), String> {
        let subject = "Password reset code";
        let body = format!(
            "Your password reset code is: {}\n\n\
             Enter this code to reset your password.\n\n\
             If you didn't request this, you can safely ignore this email.",
            code
        );

        self.send_email(email, subject, &body)?;
        tracing::info!(email = %email, "Password reset email sent");
        Ok(())
    }
}
