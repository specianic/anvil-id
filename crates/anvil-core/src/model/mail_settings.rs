//! Per-tenant email templates and SMTP settings (overrides of the theme defaults and the
//! installation SMTP URL).

use time::OffsetDateTime;

use super::ids::str_enum;

/// KEK purpose for a sealed per-tenant SMTP password.
pub const SMTP_PASSWORD_PURPOSE: &str = "anvilid/smtp-password/v1";

/// Kind of a transactional email. The names are the theme email file stems
/// (`themes/default/emails/{name}.txt|.html`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EmailKind {
    Verification,
    Recovery,
    Invitation,
    PasswordChanged,
    RecoveryCodeUsed,
}

str_enum!(EmailKind {
    Verification => "verification",
    Recovery => "recovery",
    Invitation => "invitation",
    PasswordChanged => "password_changed",
    RecoveryCodeUsed => "recovery_code_used",
});

/// A tenant override of one email template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailTemplate {
    pub kind: EmailKind,
    pub subject: String,
    pub body_html: String,
    pub body_text: String,
    pub updated_at: OffsetDateTime,
}

/// Transport security for SMTP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SmtpTls {
    Starttls,
    Implicit,
    None,
}

str_enum!(SmtpTls {
    Starttls => "starttls",
    Implicit => "implicit",
    None => "none",
});

/// Per-tenant SMTP settings. `password_enc` is the password sealed with the KEK
/// ([`SMTP_PASSWORD_PURPOSE`], AAD = tenant id bytes).
#[derive(Clone, PartialEq, Eq)]
pub struct SmtpSettings {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password_enc: Option<Vec<u8>>,
    pub from: String,
    pub tls: SmtpTls,
    pub updated_at: OffsetDateTime,
}

impl std::fmt::Debug for SmtpSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmtpSettings")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field(
                "password_enc",
                &self.password_enc.as_ref().map(|_| "<redacted>"),
            )
            .field("from", &self.from)
            .field("tls", &self.tls)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enum_names_round_trip() {
        for v in EmailKind::ALL {
            assert_eq!(EmailKind::parse(v.as_str()), Some(*v));
        }
        for v in SmtpTls::ALL {
            assert_eq!(SmtpTls::parse(v.as_str()), Some(*v));
        }
    }

    #[test]
    fn smtp_debug_redacts_password() {
        let s = SmtpSettings {
            host: "smtp.example.test".into(),
            port: 587,
            username: Some("mailer".into()),
            password_enc: Some(vec![0xCD; 4]),
            from: "noreply@example.test".into(),
            tls: SmtpTls::Starttls,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        };
        let dbg = format!("{s:?}");
        assert!(dbg.contains("<redacted>") && !dbg.contains("205"), "{dbg}");
    }
}
