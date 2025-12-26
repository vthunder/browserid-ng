//! Console-based email sender for development

use super::EmailSender;

/// Email sender that logs to console (for development)
pub struct ConsoleEmailSender;

impl ConsoleEmailSender {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ConsoleEmailSender {
    fn default() -> Self {
        Self::new()
    }
}

impl EmailSender for ConsoleEmailSender {
    fn send_verification(&self, email: &str, code: &str) -> Result<(), String> {
        println!();
        println!("========================================");
        println!("  VERIFICATION CODE FOR: {}", email);
        println!("  CODE: {}", code);
        println!("========================================");
        println!();

        tracing::info!(email = %email, code = %code, "Verification code sent");

        Ok(())
    }

    fn send_password_reset(&self, email: &str, code: &str) -> Result<(), String> {
        println!();
        println!("========================================");
        println!("  PASSWORD RESET CODE FOR: {}", email);
        println!("  CODE: {}", code);
        println!("========================================");
        println!();

        tracing::info!(email = %email, code = %code, "Password reset code sent");

        Ok(())
    }
}
