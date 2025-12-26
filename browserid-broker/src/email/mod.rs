//! Email sending abstractions

pub mod console;

pub use console::ConsoleEmailSender;

/// Trait for sending verification emails
pub trait EmailSender: Send + Sync {
    /// Send a verification code to an email address
    fn send_verification(&self, email: &str, code: &str) -> Result<(), String>;

    /// Send a password reset code to an email address
    fn send_password_reset(&self, email: &str, code: &str) -> Result<(), String>;
}
