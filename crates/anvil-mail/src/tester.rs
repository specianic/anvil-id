//! Synchronous SMTP test send ([`LettreSmtpTester`]), used by the admin "send test email"
//! action. It does not go through the outbox: the administrator sees the SMTP outcome directly.
//!
//! A fresh transport is built per call from the connection parameters (STARTTLS, implicit TLS
//! or plain, per the settings) and closed afterwards. The whole send is bounded by a timeout
//! (default [`TEST_SEND_TIMEOUT`]). Error texts come from lettre (including the server's
//! reply, e.g. `535 …`) with the username and password, and their base64 forms as used by
//! `AUTH PLAIN`/`AUTH LOGIN`, replaced by `[redacted]`.

use std::time::Duration;

use anvil_core::ports::{SmtpConnection, SmtpTester};
use secrecy::ExposeSecret as _;

use crate::transport::{MailTransport, OutgoingMail, SmtpTransport};

/// Upper bound of one test send.
pub const TEST_SEND_TIMEOUT: Duration = Duration::from_secs(10);

/// Subject of the test email.
pub const TEST_SUBJECT: &str = "AnvilID SMTP test email";

const REDACTED: &str = "[redacted]";

/// The production [`SmtpTester`].
#[derive(Debug, Clone, Copy)]
pub struct LettreSmtpTester {
    /// Upper bound of the whole send (connect, TLS, AUTH, DATA).
    pub timeout: Duration,
}

impl Default for LettreSmtpTester {
    fn default() -> Self {
        Self {
            timeout: TEST_SEND_TIMEOUT,
        }
    }
}

#[async_trait::async_trait]
impl SmtpTester for LettreSmtpTester {
    async fn send_test(&self, conn: &SmtpConnection, to: &str) -> Result<(), String> {
        let transport = SmtpTransport::from_settings_with_timeout(conn, self.timeout)
            .map_err(|e| redact(&e.to_string(), conn))?;
        let mail = OutgoingMail {
            to: to.to_owned(),
            from: String::new(),
            subject: TEST_SUBJECT.to_owned(),
            text: "This is a test email from AnvilID. Your SMTP settings work.\n".to_owned(),
            html: "<p>This is a test email from AnvilID. Your SMTP settings work.</p>".to_owned(),
        };
        let outcome = tokio::time::timeout(self.timeout, transport.send(mail)).await;
        // Closing the pooled connection is best effort and bounded as well.
        let _ = tokio::time::timeout(Duration::from_secs(1), transport.shutdown()).await;
        match outcome {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(redact(&e.to_string(), conn)),
            Err(_) => Err(format!(
                "timed out after {} ms without completing the SMTP exchange",
                self.timeout.as_millis()
            )),
        }
    }
}

/// Replaces every credential (plain and base64) in `message`.
fn redact(message: &str, conn: &SmtpConnection) -> String {
    let user = conn.username.as_deref().unwrap_or_default();
    let password = conn
        .password
        .as_ref()
        .map(|p| p.expose_secret().to_owned())
        .unwrap_or_default();
    let mut needles = Vec::new();
    if !password.is_empty() {
        needles.push(base64(format!("\0{user}\0{password}").as_bytes()));
        needles.push(base64(password.as_bytes()));
        needles.push(password.clone());
    }
    if !user.is_empty() {
        needles.push(base64(user.as_bytes()));
        needles.push(user.to_owned());
    }
    // Longest first, so a credential contained in another is not partially replaced.
    needles.sort_by_key(|n| std::cmp::Reverse(n.len()));
    let mut out = message.to_owned();
    for needle in needles {
        if !needle.is_empty() {
            out = out.replace(&needle, REDACTED);
        }
    }
    out
}

/// Standard base64 with padding (the encoding of SMTP AUTH arguments).
fn base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use anvil_core::model::SmtpTls;
    use secrecy::SecretString;

    #[test]
    fn base64_matches_rfc4648_vectors() {
        for (input, expected) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(input.as_bytes()), expected, "{input:?}");
        }
    }

    #[test]
    fn redact_removes_plain_and_base64_credentials() {
        let conn = SmtpConnection {
            host: "h".into(),
            port: 25,
            username: Some("mailer".into()),
            password: Some(SecretString::from("pw-123".to_owned())),
            from: "a@b.test".into(),
            tls: SmtpTls::None,
        };
        let plain = base64(b"\0mailer\0pw-123");
        let msg = format!("535 bad pw-123 for mailer ({plain}) {}", base64(b"pw-123"));
        let out = redact(&msg, &conn);
        assert!(!out.contains("pw-123") && !out.contains("mailer"), "{out}");
        assert!(!out.contains(&plain), "{out}");
        assert!(out.starts_with("535 bad [redacted]"), "{out}");
    }
}
