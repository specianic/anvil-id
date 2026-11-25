//! The mail transport port and the SMTP implementation.

use std::time::Duration;

use lettre::message::{Mailbox, MultiPart};
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

use crate::MailError;

/// SMTP command timeout.
const SMTP_TIMEOUT: Duration = Duration::from_secs(30);

/// Longest transport error text kept (it ends up in the outbox `last_error`).
const MAX_ERROR_LEN: usize = 300;

/// A rendered email ready to send.
#[derive(Clone, PartialEq, Eq)]
pub struct OutgoingMail {
    pub to: String,
    /// Sender (`From`). Empty means the transport's default sender.
    pub from: String,
    pub subject: String,
    pub text: String,
    pub html: String,
}

/// Bodies contain single-use links; only the recipient and subject are shown.
impl std::fmt::Debug for OutgoingMail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutgoingMail")
            .field("to", &self.to)
            .field("subject", &self.subject)
            .finish_non_exhaustive()
    }
}

/// Delivers rendered emails.
#[async_trait::async_trait]
pub trait MailTransport: Send + Sync {
    /// Sends one email. Errors never contain the message body.
    async fn send(&self, mail: OutgoingMail) -> Result<(), MailError>;
}

/// SMTP delivery with lettre over rustls (aws-lc-rs provider).
pub struct SmtpTransport {
    inner: AsyncSmtpTransport<Tokio1Executor>,
    default_from: Mailbox,
}

impl std::fmt::Debug for SmtpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The connection URL may carry credentials: never printed.
        f.debug_struct("SmtpTransport")
            .field("default_from", &self.default_from.to_string())
            .finish_non_exhaustive()
    }
}

impl SmtpTransport {
    /// Builds a transport from an `smtp://` (plain, or STARTTLS with `?tls=required`) or
    /// `smtps://` (implicit TLS) URL, in lettre's connection-URL format. `from` is the default
    /// sender used when an [`OutgoingMail`] has an empty `from`.
    ///
    /// Errors never echo the URL, which may contain credentials. Must be called inside a Tokio
    /// runtime (the connection pool spawns its maintenance task).
    pub fn from_url(url: &str, from: &str) -> Result<Self, MailError> {
        let scheme = url.split_once("://").map(|(s, _)| s.to_ascii_lowercase());
        if !matches!(scheme.as_deref(), Some("smtp" | "smtps")) {
            return Err(MailError::Config(
                "SMTP URL must use the smtp:// or smtps:// scheme".into(),
            ));
        }
        let default_from: Mailbox = from
            .parse()
            .map_err(|_| MailError::Config("invalid sender address".into()))?;
        let inner = AsyncSmtpTransport::<Tokio1Executor>::from_url(url)
            .map_err(|_| MailError::Config("invalid SMTP URL".into()))?
            .timeout(Some(SMTP_TIMEOUT))
            .build();
        Ok(Self {
            inner,
            default_from,
        })
    }

    fn build_message(&self, mail: OutgoingMail) -> Result<Message, MailError> {
        let from = if mail.from.is_empty() {
            self.default_from.clone()
        } else {
            mail.from
                .parse()
                .map_err(|_| MailError::Message("invalid sender address".into()))?
        };
        let to: Mailbox = mail
            .to
            .parse()
            .map_err(|_| MailError::Message("invalid recipient address".into()))?;
        Message::builder()
            .from(from)
            .to(to)
            .subject(mail.subject)
            .multipart(MultiPart::alternative_plain_html(mail.text, mail.html))
            .map_err(|e| MailError::Message(truncate(e.to_string())))
    }
}

#[async_trait::async_trait]
impl MailTransport for SmtpTransport {
    async fn send(&self, mail: OutgoingMail) -> Result<(), MailError> {
        let message = self.build_message(mail)?;
        self.inner
            .send(message)
            .await
            .map(|_| ())
            .map_err(|e| MailError::Send(truncate(e.to_string())))
    }
}

fn truncate(mut s: String) -> String {
    if s.len() > MAX_ERROR_LEN {
        let mut end = MAX_ERROR_LEN;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_smtp_schemes() {
        for url in [
            "http://x",
            "https://mail.example.test",
            "smtpx://h:25",
            "localhost:25",
            "",
        ] {
            assert!(
                matches!(
                    SmtpTransport::from_url(url, "AnvilID <noreply@example.test>"),
                    Err(MailError::Config(_))
                ),
                "{url:?}"
            );
        }
    }

    #[tokio::test]
    async fn accepts_smtp_and_smtps_urls() {
        SmtpTransport::from_url("smtp://localhost:1025", "noreply@example.test").unwrap();
        SmtpTransport::from_url(
            "smtps://user:pw@mail.example.test:465",
            "noreply@example.test",
        )
        .unwrap();
    }

    #[tokio::test]
    async fn config_errors_do_not_echo_the_url() {
        let err = SmtpTransport::from_url("http://user:hunter2@h", "a@b.test").unwrap_err();
        assert!(!err.to_string().contains("hunter2"));
        let err =
            SmtpTransport::from_url("smtp://user:hunter2@h:25", "not an address").unwrap_err();
        assert!(!err.to_string().contains("hunter2"));
        let t = SmtpTransport::from_url("smtp://user:hunter2@h:25", "a@b.test").unwrap();
        assert!(!format!("{t:?}").contains("hunter2"));
    }

    #[test]
    fn debug_hides_bodies() {
        let mail = OutgoingMail {
            to: "alice@example.test".into(),
            from: String::new(),
            subject: "Hello".into(),
            text: "token-in-text".into(),
            html: "token-in-html".into(),
        };
        let dbg = format!("{mail:?}");
        assert!(dbg.contains("alice@example.test") && dbg.contains("Hello"));
        assert!(!dbg.contains("token-in-text") && !dbg.contains("token-in-html"));
    }

    #[tokio::test]
    async fn builds_multipart_alternative_message() {
        let t = SmtpTransport::from_url("smtp://localhost:1025", "AnvilID <noreply@example.test>")
            .unwrap();
        let msg = t
            .build_message(OutgoingMail {
                to: "alice@example.test".into(),
                from: String::new(),
                subject: "Hi".into(),
                text: "plain".into(),
                html: "<p>html</p>".into(),
            })
            .unwrap();
        let raw = String::from_utf8(msg.formatted()).unwrap();
        assert!(raw.contains("multipart/alternative"));
        assert!(raw.contains("From: AnvilID <noreply@example.test>"));
        assert!(
            t.build_message(OutgoingMail {
                to: "not an address".into(),
                from: String::new(),
                subject: "Hi".into(),
                text: String::new(),
                html: String::new(),
            })
            .is_err()
        );
    }
}
