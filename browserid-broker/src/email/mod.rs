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
