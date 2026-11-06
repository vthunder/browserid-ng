//! Email sending abstractions

pub mod console;
pub mod smtp;

pub use console::ConsoleEmailSender;
pub use smtp::{SmtpConfig, SmtpEmailSender};

/// Trait for sending verification emails
pub trait EmailSender: Send + Sync {
    /// Send a verification code to an email address
    fn send_verification(&self, email: &str, code: &str) -> Result<(), String>;

    /// Send a password reset code to an email address
    fn send_password_reset(&self, email: &str, code: &str) -> Result<(), String>;
}

/// Allow using Box<dyn EmailSender> as an EmailSender
impl EmailSender for Box<dyn EmailSender> {
    fn send_verification(&self, email: &str, code: &str) -> Result<(), String> {
        (**self).send_verification(email, code)
    }

    fn send_password_reset(&self, email: &str, code: &str) -> Result<(), String> {
        (**self).send_password_reset(email, code)
    }
}

/// Which sender the broker starts with (audit 2026-11 W7-12).
#[derive(Debug, PartialEq, Eq)]
pub enum SenderChoice {
    Smtp,
    Console,
}

/// Is this a production deployment, as far as the sender choice goes? A
/// `BROKER_DOMAIN` that is not loopback: there the console sender would
/// print every verification and reset code, with the address, into the
/// host's log.
pub fn is_production_domain(domain: &str) -> bool {
    let host = domain.split(':').next().unwrap_or(domain).to_ascii_lowercase();
    !(host == "localhost" || host.starts_with("127.") || host == "[::1]" || host == "::1")
}

/// Decide the sender, or refuse to start. SMTP wins when configured.
/// Without it, the console sender is allowed only in dev: a loopback
/// domain, `DISABLE_SMTP` (the e2e/test switch), or an explicit
/// `EMAIL_SENDER=console`. A production domain with none of those is a
/// misconfiguration that must not boot silently.
pub fn choose_sender(
    domain: &str,
    smtp_configured: bool,
    email_sender_env: Option<&str>,
    disable_smtp: bool,
) -> Result<SenderChoice, String> {
    let explicit_console = email_sender_env.map(|v| v.trim().eq_ignore_ascii_case("console")).unwrap_or(false);
    if smtp_configured && !explicit_console {
        return Ok(SenderChoice::Smtp);
    }
    if explicit_console || disable_smtp || !is_production_domain(domain) {
        return Ok(SenderChoice::Console);
    }
    Err(format!(
        "refusing to start: BROKER_DOMAIN={domain} looks like production but SMTP is not configured \
         (SMTP_HOST, SMTP_USERNAME, SMTP_PASSWORD, SMTP_FROM_EMAIL). The console sender would print \
         every verification code into the log. Set EMAIL_SENDER=console to allow that on purpose (dev only)."
    ))
}

#[cfg(test)]
mod sender_choice_tests {
    use super::*;

    #[test]
    fn production_without_smtp_refuses_to_start() {
        let r = choose_sender("browserid.me", false, None, false);
        assert!(r.is_err(), "{r:?}");
        assert!(r.unwrap_err().contains("SMTP"));
        assert!(choose_sender("id.example.org:8443", false, None, false).is_err());
    }

    #[test]
    fn smtp_configured_is_used_anywhere() {
        assert_eq!(choose_sender("browserid.me", true, None, false), Ok(SenderChoice::Smtp));
        assert_eq!(choose_sender("localhost:3000", true, None, false), Ok(SenderChoice::Smtp));
    }

    #[test]
    fn console_only_in_dev_or_when_asked_for() {
        assert_eq!(choose_sender("localhost:3000", false, None, false), Ok(SenderChoice::Console));
        assert_eq!(choose_sender("127.0.0.1:3000", false, None, false), Ok(SenderChoice::Console));
        assert_eq!(choose_sender("browserid.me", false, None, true), Ok(SenderChoice::Console));
        assert_eq!(choose_sender("browserid.me", false, Some("console"), false), Ok(SenderChoice::Console));
        assert_eq!(choose_sender("browserid.me", true, Some("console"), false), Ok(SenderChoice::Console));
        assert!(choose_sender("browserid.me", false, Some("smtp"), false).is_err());
    }
}
