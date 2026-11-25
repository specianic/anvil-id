//! Outbound email delivery and templates (ARCHITECTURE.md §4).
//!
//! - [`render`]: renders the `themes/default/emails` templates (text + HTML), with an optional
//!   operator theme directory that overrides individual files.
//! - [`transport`]: the [`transport::MailTransport`] port and its production implementation,
//!   [`transport::SmtpTransport`] (lettre over rustls with aws-lc-rs).
//! - [`worker`]: the [`worker::OutboxWorker`] that drains the storage outbox with retries and
//!   exponential backoff.
//!
//! Message bodies and links contain single-use tokens. Nothing in this crate logs them, and
//! [`transport::OutgoingMail`]'s `Debug` output shows only the recipient and subject.

pub mod render;
pub mod transport;
pub mod worker;

pub use render::EmailRenderer;
pub use transport::{MailTransport, OutgoingMail, SmtpTransport};
pub use worker::{OutboxAccess, OutboxWorker, StorageOutbox};

/// Errors of the mail subsystem. Messages never contain message bodies, links or SMTP
/// credentials.
#[derive(Debug, thiserror::Error)]
pub enum MailError {
    /// A template is unknown, could not be loaded, or failed to render.
    #[error("template error: {0}")]
    Template(String),
    /// Invalid configuration (SMTP URL, sender address).
    #[error("invalid mail configuration: {0}")]
    Config(String),
    /// An address could not be parsed or the message could not be built.
    #[error("invalid message: {0}")]
    Message(String),
    /// The transport failed to deliver the message.
    #[error("send failed: {0}")]
    Send(String),
    /// The outbox storage failed.
    #[error("outbox storage error: {0}")]
    Storage(#[from] anvil_core::ports::StorageError),
}
