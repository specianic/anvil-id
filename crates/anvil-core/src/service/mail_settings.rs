//! Per-tenant email templates and SMTP settings (UI-07).
//!
//! The SMTP password is stored sealed with the KEK ([`SMTP_PASSWORD_PURPOSE`], AAD = tenant id
//! bytes). [`seal_smtp_password`] and [`smtp_connection`] are the only places that seal and open
//! it; the outbox worker and the test send both go through [`smtp_connection`].
//!
//! [`MailSettingsService`] is the management API's entry point: template overrides are checked
//! by an [`EmailTemplateCheck`] (production: `anvil_mail::TemplateChecker`) before they are
//! stored, SMTP settings are validated and sealed, reads never return the password, and test
//! sends go through an [`SmtpTester`] (production: `anvil_mail::LettreSmtpTester`).

use std::sync::Arc;

use anvil_jose::Kek;
use secrecy::{ExposeSecret as _, SecretString};
use time::OffsetDateTime;

use crate::error::CoreError;
use crate::model::{
    AuditAction, AuditActor, AuditDetails, AuditOutcome, EmailKind, EmailTemplate, RequestContext,
    SMTP_PASSWORD_PURPOSE, SmtpSettings, SmtpTls, TenantId, normalize_email, truncate_to_ms,
};
use crate::ports::{
    Clock, EmailTemplateCheck, SmtpConnection, SmtpTester, Storage, StorageError, TemplateIssue,
};
use crate::service::audit::AuditService;

/// Seals an SMTP password for `tenant`.
pub fn seal_smtp_password(
    kek: &Kek,
    tenant: TenantId,
    password: &SecretString,
) -> Result<Vec<u8>, CoreError> {
    kek.seal(
        SMTP_PASSWORD_PURPOSE,
        tenant.0.as_bytes(),
        password.expose_secret().as_bytes(),
    )
    .map_err(|_| CoreError::Internal("SMTP password could not be sealed".into()))
}

/// The connection parameters of stored settings, with the password opened. The error is
/// generic: it never contains the sealed or opened value.
pub fn smtp_connection(
    kek: &Kek,
    tenant: TenantId,
    settings: &SmtpSettings,
) -> Result<SmtpConnection, CoreError> {
    let password = match &settings.password_enc {
        None => None,
        Some(sealed) => {
            let undecryptable =
                || CoreError::Internal("SMTP password could not be decrypted".into());
            let raw = kek
                .open(SMTP_PASSWORD_PURPOSE, tenant.0.as_bytes(), sealed)
                .map_err(|_| undecryptable())?;
            let text = std::str::from_utf8(&raw).map_err(|_| undecryptable())?;
            Some(SecretString::from(text.to_owned()))
        }
    };
    Ok(SmtpConnection {
        host: settings.host.clone(),
        port: settings.port,
        username: settings.username.clone(),
        password,
        from: settings.from.clone(),
        tls: settings.tls,
    })
}

/// Longest accepted template subject source, in bytes.
pub const MAX_SUBJECT_LEN: usize = 1_000;
/// Longest accepted template body source (each of HTML and text), in bytes.
pub const MAX_BODY_LEN: usize = 64 * 1024;
/// Longest accepted SMTP password, in bytes.
pub const MAX_SMTP_PASSWORD_LEN: usize = 1_024;

/// A template override as submitted by an administrator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemplateInput {
    pub subject: String,
    pub body_html: String,
    pub body_text: String,
}

/// Why a template could not be saved.
#[derive(Debug)]
pub enum TemplateError {
    /// The template does not compile, uses an unknown variable, fails the sample render or is
    /// too long. `field` is `subject`, `body_html` or `body_text`.
    Invalid {
        field: &'static str,
        line: Option<u32>,
        message: String,
    },
    /// Any other failure.
    Core(CoreError),
}

impl From<CoreError> for TemplateError {
    fn from(e: CoreError) -> Self {
        Self::Core(e)
    }
}

impl From<StorageError> for TemplateError {
    fn from(e: StorageError) -> Self {
        Self::Core(e.into())
    }
}

impl From<TemplateError> for CoreError {
    fn from(e: TemplateError) -> Self {
        match e {
            TemplateError::Invalid {
                field,
                line,
                message,
            } => CoreError::Validation {
                field,
                message: match line {
                    Some(line) => format!("line {line}: {message}"),
                    None => message,
                },
            },
            TemplateError::Core(e) => e,
        }
    }
}

/// SMTP settings as submitted by an administrator.
///
/// `password`: `Some` non-empty sets a new password; `None` or empty keeps the stored one.
/// Without a `username` no password is stored.
#[derive(Debug, Clone)]
pub struct SmtpInput {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<SecretString>,
    pub from: String,
    pub tls: SmtpTls,
}

/// Stored SMTP settings without the password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmtpView {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password_set: bool,
    pub from: String,
    pub tls: SmtpTls,
    pub updated_at: OffsetDateTime,
}

impl From<&SmtpSettings> for SmtpView {
    fn from(s: &SmtpSettings) -> Self {
        Self {
            host: s.host.clone(),
            port: s.port,
            username: s.username.clone(),
            password_set: s.password_enc.is_some(),
            from: s.from.clone(),
            tls: s.tls,
            updated_at: s.updated_at,
        }
    }
}

/// Outcome of a test send. `error` is the SMTP error text (never the password).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestSendResult {
    pub delivered: bool,
    pub error: Option<String>,
}

/// Tenant email templates and SMTP settings (UI-07). Every mutating call is audited
/// (`email_template_updated`, `email_template_reset`, `smtp_settings_updated`,
/// `smtp_test_sent`) right after the change.
#[derive(Clone)]
pub struct MailSettingsService {
    pub storage: Arc<dyn Storage>,
    pub clock: Arc<dyn Clock>,
    /// Seals and opens SMTP passwords; must be the KEK the outbox worker uses.
    pub kek: Arc<Kek>,
    pub checker: Arc<dyn EmailTemplateCheck>,
    pub tester: Arc<dyn SmtpTester>,
}

impl MailSettingsService {
    fn audit(&self) -> AuditService {
        AuditService {
            storage: Arc::clone(&self.storage),
            clock: Arc::clone(&self.clock),
        }
    }

    /// Every override of the tenant, in kind-name order.
    pub async fn list_templates(&self, tenant: TenantId) -> Result<Vec<EmailTemplate>, CoreError> {
        Ok(self.storage.mail_settings().list_templates(tenant).await?)
    }

    /// The tenant's override of `kind`; `None` means the theme default is used.
    pub async fn get_template(
        &self,
        tenant: TenantId,
        kind: EmailKind,
    ) -> Result<Option<EmailTemplate>, CoreError> {
        Ok(self.storage.mail_settings().template(tenant, kind).await?)
    }

    /// Checks and stores an override of `kind`, then audits `email_template_updated`.
    pub async fn put_template(
        &self,
        tenant: TenantId,
        kind: EmailKind,
        input: TemplateInput,
        actor: AuditActor,
        ctx: &RequestContext,
    ) -> Result<EmailTemplate, TemplateError> {
        let template = plan_template(
            self.checker.as_ref(),
            kind,
            input,
            truncate_to_ms(self.clock.now()),
        )?;
        self.storage
            .mail_settings()
            .put_template(tenant, &template)
            .await?;
        self.audit()
            .record(
                tenant,
                actor,
                AuditAction::EmailTemplateUpdated,
                Some(kind.as_str().to_owned()),
                AuditOutcome::Success,
                ctx,
                AuditDetails::template(kind),
            )
            .await?;
        Ok(template)
    }

    /// Removes the override of `kind` (back to the theme default) and audits
    /// `email_template_reset`. `false` (and no event) if there was none.
    pub async fn reset_template(
        &self,
        tenant: TenantId,
        kind: EmailKind,
        actor: AuditActor,
        ctx: &RequestContext,
    ) -> Result<bool, CoreError> {
        let deleted = self
            .storage
            .mail_settings()
            .delete_template(tenant, kind)
            .await?;
        if deleted {
            self.audit()
                .record(
                    tenant,
                    actor,
                    AuditAction::EmailTemplateReset,
                    Some(kind.as_str().to_owned()),
                    AuditOutcome::Success,
                    ctx,
                    AuditDetails::template(kind),
                )
                .await?;
        }
        Ok(deleted)
    }

    /// The tenant's SMTP settings without the password; `None` = installation SMTP.
    pub async fn get_smtp(&self, tenant: TenantId) -> Result<Option<SmtpView>, CoreError> {
        Ok(self
            .storage
            .mail_settings()
            .smtp(tenant)
            .await?
            .as_ref()
            .map(SmtpView::from))
    }

    /// Validates and stores the tenant's SMTP settings (password sealed with the KEK), then
    /// audits `smtp_settings_updated` with the names of the changed fields.
    pub async fn put_smtp(
        &self,
        tenant: TenantId,
        input: SmtpInput,
        actor: AuditActor,
        ctx: &RequestContext,
    ) -> Result<SmtpView, CoreError> {
        let current = self.storage.mail_settings().smtp(tenant).await?;
        let settings = plan_smtp(
            &self.kek,
            tenant,
            input,
            current.as_ref(),
            truncate_to_ms(self.clock.now()),
        )?;
        self.storage
            .mail_settings()
            .put_smtp(tenant, &settings)
            .await?;
        let changed = changed_fields(current.as_ref(), &settings);
        self.audit()
            .record(
                tenant,
                actor,
                AuditAction::SmtpSettingsUpdated,
                None,
                AuditOutcome::Success,
                ctx,
                AuditDetails::fields(&changed),
            )
            .await?;
        Ok(SmtpView::from(&settings))
    }

    /// Removes the tenant's SMTP settings (back to the installation SMTP) and audits
    /// `smtp_settings_updated` (reason `deleted`). `false` (and no event) if there were none.
    pub async fn delete_smtp(
        &self,
        tenant: TenantId,
        actor: AuditActor,
        ctx: &RequestContext,
    ) -> Result<bool, CoreError> {
        let deleted = self.storage.mail_settings().delete_smtp(tenant).await?;
        if deleted {
            self.audit()
                .record(
                    tenant,
                    actor,
                    AuditAction::SmtpSettingsUpdated,
                    None,
                    AuditOutcome::Success,
                    ctx,
                    AuditDetails::reason("deleted"),
                )
                .await?;
        }
        Ok(deleted)
    }

    /// Sends a test email synchronously (not through the outbox) with the tenant's stored SMTP
    /// settings and audits `smtp_test_sent` with outcome success or failure. An SMTP failure
    /// is a successful call with `delivered: false` and the error text.
    ///
    /// The SMTP host is administrator-supplied, so this can reach internal networks; it is
    /// bounded by the tester's timeout and reserved to administrators.
    pub async fn test_send(
        &self,
        tenant: TenantId,
        to: &str,
        actor: AuditActor,
        ctx: &RequestContext,
    ) -> Result<TestSendResult, CoreError> {
        let to = normalize_email(to)?;
        let settings = self
            .storage
            .mail_settings()
            .smtp(tenant)
            .await?
            .ok_or_else(|| CoreError::Validation {
                field: "smtp",
                message: "the tenant has no SMTP settings".into(),
            })?;
        let conn = smtp_connection(&self.kek, tenant, &settings)?;
        let result = match self.tester.send_test(&conn, &to).await {
            Ok(()) => TestSendResult {
                delivered: true,
                error: None,
            },
            Err(error) => TestSendResult {
                delivered: false,
                error: Some(error),
            },
        };
        let (outcome, details) = test_send_audit(&result);
        self.audit()
            .record(
                tenant,
                actor,
                AuditAction::SmtpTestSent,
                None,
                outcome,
                ctx,
                details,
            )
            .await?;
        Ok(result)
    }
}

/// Audit outcome and details of a test send (the SMTP error text is not stored).
fn test_send_audit(result: &TestSendResult) -> (AuditOutcome, AuditDetails) {
    if result.delivered {
        (AuditOutcome::Success, AuditDetails::empty())
    } else {
        (AuditOutcome::Failure, AuditDetails::reason("smtp_error"))
    }
}

/// Validates a template override (length limits, then the checker) and builds the stored
/// value.
fn plan_template(
    checker: &dyn EmailTemplateCheck,
    kind: EmailKind,
    input: TemplateInput,
    now: OffsetDateTime,
) -> Result<EmailTemplate, TemplateError> {
    let too_long = |field: &'static str, max: usize| TemplateError::Invalid {
        field,
        line: None,
        message: format!("must be at most {max} bytes"),
    };
    if input.subject.len() > MAX_SUBJECT_LEN {
        return Err(too_long("subject", MAX_SUBJECT_LEN));
    }
    if input.body_html.len() > MAX_BODY_LEN {
        return Err(too_long("body_html", MAX_BODY_LEN));
    }
    if input.body_text.len() > MAX_BODY_LEN {
        return Err(too_long("body_text", MAX_BODY_LEN));
    }
    checker
        .check(kind, &input.subject, &input.body_html, &input.body_text)
        .map_err(issue_to_error)?;
    Ok(EmailTemplate {
        kind,
        subject: input.subject,
        body_html: input.body_html,
        body_text: input.body_text,
        updated_at: now,
    })
}

/// Maps a checker issue to a field error. The checker prefixes messages with the part name
/// (`subject: `, `body_html: `, `body_text: `); without a prefix the field is `template`.
fn issue_to_error(issue: TemplateIssue) -> TemplateError {
    for field in ["subject", "body_html", "body_text"] {
        if let Some(rest) = issue.message.strip_prefix(field)
            && let Some(message) = rest.strip_prefix(": ")
        {
            return TemplateError::Invalid {
                field,
                line: issue.line,
                message: message.to_owned(),
            };
        }
    }
    TemplateError::Invalid {
        field: "template",
        line: issue.line,
        message: issue.message,
    }
}

/// Validates SMTP input and builds the stored settings, sealing a new password or keeping the
/// current one.
fn plan_smtp(
    kek: &Kek,
    tenant: TenantId,
    input: SmtpInput,
    current: Option<&SmtpSettings>,
    now: OffsetDateTime,
) -> Result<SmtpSettings, CoreError> {
    let invalid = |field: &'static str, message: &str| CoreError::Validation {
        field,
        message: message.to_owned(),
    };
    let host = input.host.trim().to_ascii_lowercase();
    if host.is_empty()
        || host.len() > 253
        || host
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '/' | '@' | '?' | '#'))
    {
        return Err(invalid("host", "host must be a host name or IP address"));
    }
    if input.port == 0 {
        return Err(invalid("port", "port must be between 1 and 65535"));
    }
    let username = input
        .username
        .map(|u| u.trim().to_owned())
        .filter(|u| !u.is_empty());
    if username
        .as_ref()
        .is_some_and(|u| u.len() > 256 || u.chars().any(char::is_control))
    {
        return Err(invalid("username", "username is invalid"));
    }
    let from = input.from.trim().to_owned();
    validate_sender(&from).map_err(|_| invalid("from", "from must be an email address"))?;

    let new_password = input.password.filter(|p| !p.expose_secret().is_empty());
    let password_enc = match (&username, new_password) {
        (None, _) => None,
        (Some(_), Some(p)) => {
            if p.expose_secret().len() > MAX_SMTP_PASSWORD_LEN {
                return Err(invalid("password", "password is too long"));
            }
            Some(seal_smtp_password(kek, tenant, &p)?)
        }
        (Some(_), None) => current.and_then(|c| c.password_enc.clone()),
    };
    Ok(SmtpSettings {
        host,
        port: input.port,
        username,
        password_enc,
        from,
        tls: input.tls,
        updated_at: now,
    })
}

/// Accepts `addr@domain` or `Display Name <addr@domain>`.
fn validate_sender(from: &str) -> Result<(), CoreError> {
    let addr = match (from.rfind('<'), from.strip_suffix('>')) {
        (Some(start), Some(inner)) => &inner[start + 1..],
        (None, None) => from,
        _ => {
            return Err(CoreError::Validation {
                field: "from",
                message: "unbalanced angle brackets".into(),
            });
        }
    };
    if from.chars().any(char::is_control) {
        return Err(CoreError::Validation {
            field: "from",
            message: "control characters".into(),
        });
    }
    normalize_email(addr).map(|_| ())
}

/// Names of the settings fields that differ from `current` (all of them for new settings).
fn changed_fields(current: Option<&SmtpSettings>, new: &SmtpSettings) -> Vec<&'static str> {
    let Some(c) = current else {
        return vec!["host", "port", "username", "password", "from", "tls"];
    };
    let mut changed = Vec::new();
    if c.host != new.host {
        changed.push("host");
    }
    if c.port != new.port {
        changed.push("port");
    }
    if c.username != new.username {
        changed.push("username");
    }
    if c.password_enc != new.password_enc {
        changed.push("password");
    }
    if c.from != new.from {
        changed.push("from");
    }
    if c.tls != new.tls {
        changed.push("tls");
    }
    changed
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Rejects templates whose text body contains `BAD` (line 2), like the real checker would.
    struct FakeChecker;

    impl EmailTemplateCheck for FakeChecker {
        fn check(
            &self,
            _kind: EmailKind,
            subject: &str,
            _html: &str,
            text: &str,
        ) -> Result<(), TemplateIssue> {
            if subject.is_empty() {
                return Err(TemplateIssue {
                    line: None,
                    message: "subject: the subject renders empty".into(),
                });
            }
            if text.contains("BAD") {
                return Err(TemplateIssue {
                    line: Some(2),
                    message: "body_text: unknown variable `BAD`".into(),
                });
            }
            Ok(())
        }
    }

    fn input(subject: &str, text: &str) -> TemplateInput {
        TemplateInput {
            subject: subject.into(),
            body_html: "<p>{{ email }}</p>".into(),
            body_text: text.into(),
        }
    }

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
    }

    fn smtp_input(password: Option<&str>) -> SmtpInput {
        SmtpInput {
            host: " Smtp.Example.TEST ".into(),
            port: 587,
            username: Some("mailer".into()),
            password: password.map(|p| SecretString::from(p.to_owned())),
            from: "Acme <noreply@acme.example>".into(),
            tls: SmtpTls::Starttls,
        }
    }

    #[test]
    fn invalid_template_is_rejected_with_field_and_line() {
        let err = plan_template(
            &FakeChecker,
            EmailKind::Verification,
            input("S", "a\nBAD"),
            now(),
        )
        .unwrap_err();
        match err {
            TemplateError::Invalid {
                field,
                line,
                ref message,
            } => {
                assert_eq!(field, "body_text");
                assert_eq!(line, Some(2));
                assert!(message.starts_with("unknown variable"), "{message}");
            }
            TemplateError::Core(e) => panic!("{e}"),
        }
        let core = CoreError::from(err);
        assert!(matches!(
            core,
            CoreError::Validation {
                field: "body_text",
                ..
            }
        ));
        assert!(core.to_string().contains("line 2"), "{core}");

        let err = plan_template(&FakeChecker, EmailKind::Verification, input("", "x"), now())
            .unwrap_err();
        assert!(matches!(
            err,
            TemplateError::Invalid {
                field: "subject",
                line: None,
                ..
            }
        ));
    }

    #[test]
    fn oversized_templates_are_rejected_before_the_checker() {
        let big = "x".repeat(MAX_BODY_LEN + 1);
        let err =
            plan_template(&FakeChecker, EmailKind::Recovery, input("S", &big), now()).unwrap_err();
        assert!(matches!(
            err,
            TemplateError::Invalid {
                field: "body_text",
                ..
            }
        ));
        let err = plan_template(
            &FakeChecker,
            EmailKind::Recovery,
            input(&"s".repeat(MAX_SUBJECT_LEN + 1), "x"),
            now(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            TemplateError::Invalid {
                field: "subject",
                ..
            }
        ));
    }

    #[test]
    fn valid_template_is_stored_as_submitted() {
        let t = plan_template(
            &FakeChecker,
            EmailKind::Invitation,
            input("S {{ x }}", "t"),
            now(),
        )
        .unwrap();
        assert_eq!(t.kind, EmailKind::Invitation);
        assert_eq!(t.subject, "S {{ x }}");
        assert_eq!(t.body_text, "t");
        assert_eq!(t.updated_at, now());
    }

    #[test]
    fn unprefixed_checker_messages_map_to_the_template_field() {
        let err = issue_to_error(TemplateIssue {
            line: Some(1),
            message: "something".into(),
        });
        assert!(matches!(
            err,
            TemplateError::Invalid {
                field: "template",
                ..
            }
        ));
    }

    #[test]
    fn put_smtp_seals_the_password_and_it_opens_only_for_the_tenant() {
        let kek = Kek::generate();
        let tenant = TenantId::new_v7();
        let s = plan_smtp(&kek, tenant, smtp_input(Some("smtp-s3cret")), None, now()).unwrap();
        assert_eq!(s.host, "smtp.example.test");
        let sealed = s.password_enc.clone().unwrap();
        assert!(
            !sealed
                .windows(b"smtp-s3cret".len())
                .any(|w| w == b"smtp-s3cret"),
            "stored sealed"
        );
        let conn = smtp_connection(&kek, tenant, &s).unwrap();
        assert_eq!(conn.password.unwrap().expose_secret(), "smtp-s3cret");
        assert_eq!(conn.host, "smtp.example.test");
        assert_eq!(conn.from, "Acme <noreply@acme.example>");

        let err = smtp_connection(&kek, TenantId::new_v7(), &s).unwrap_err();
        assert!(!err.to_string().contains("smtp-s3cret"));
        assert!(smtp_connection(&Kek::generate(), tenant, &s).is_err());
    }

    #[test]
    fn empty_or_missing_password_keeps_the_stored_one() {
        let kek = Kek::generate();
        let tenant = TenantId::new_v7();
        let first = plan_smtp(&kek, tenant, smtp_input(Some("pw-1")), None, now()).unwrap();
        for keep in [None, Some("")] {
            let next = plan_smtp(&kek, tenant, smtp_input(keep), Some(&first), now()).unwrap();
            assert_eq!(next.password_enc, first.password_enc, "{keep:?}");
        }
        let changed =
            plan_smtp(&kek, tenant, smtp_input(Some("pw-2")), Some(&first), now()).unwrap();
        let conn = smtp_connection(&kek, tenant, &changed).unwrap();
        assert_eq!(conn.password.unwrap().expose_secret(), "pw-2");
        assert_eq!(changed_fields(Some(&first), &changed), ["password"]);

        // No username: no password is stored.
        let mut anonymous = smtp_input(Some("pw-3"));
        anonymous.username = Some("  ".into());
        let s = plan_smtp(&kek, tenant, anonymous, Some(&first), now()).unwrap();
        assert_eq!(s.username, None);
        assert_eq!(s.password_enc, None);
    }

    #[test]
    fn invalid_smtp_input_is_rejected_per_field() {
        let kek = Kek::generate();
        let tenant = TenantId::new_v7();
        let field = |mutate: &dyn Fn(&mut SmtpInput)| {
            let mut i = smtp_input(Some("pw"));
            mutate(&mut i);
            match plan_smtp(&kek, tenant, i, None, now()) {
                Err(CoreError::Validation { field, .. }) => field,
                other => panic!("{other:?}"),
            }
        };
        assert_eq!(field(&|i| i.host = String::new()), "host");
        assert_eq!(field(&|i| i.host = "smtp://h".into()), "host");
        assert_eq!(field(&|i| i.host = "a b".into()), "host");
        assert_eq!(field(&|i| i.port = 0), "port");
        assert_eq!(field(&|i| i.from = "nope".into()), "from");
        assert_eq!(field(&|i| i.from = "Acme <a@b".into()), "from");
        assert_eq!(field(&|i| i.from = "a@b\r\nBcc: x@y".into()), "from");
        assert_eq!(
            field(&|i| i.password = Some(SecretString::from("p".repeat(2000)))),
            "password"
        );
        assert_eq!(field(&|i| i.username = Some("a\nb".into())), "username");
        validate_sender("noreply@acme.example").unwrap();
        validate_sender("Acme Mail <noreply@acme.example>").unwrap();
    }

    #[test]
    fn view_never_contains_the_password() {
        let kek = Kek::generate();
        let tenant = TenantId::new_v7();
        let s = plan_smtp(&kek, tenant, smtp_input(Some("view-pw")), None, now()).unwrap();
        let view = SmtpView::from(&s);
        assert!(view.password_set);
        assert!(!format!("{view:?}").contains("view-pw"));
        assert_eq!(view.username.as_deref(), Some("mailer"));
        let mut no_pw = s.clone();
        no_pw.password_enc = None;
        assert!(!SmtpView::from(&no_pw).password_set);
        assert_eq!(
            changed_fields(None, &s),
            ["host", "port", "username", "password", "from", "tls"]
        );
    }

    #[test]
    fn test_send_audit_outcome_follows_delivery() {
        let (outcome, details) = test_send_audit(&TestSendResult {
            delivered: true,
            error: None,
        });
        assert_eq!(outcome, AuditOutcome::Success);
        assert!(details.is_empty());
        let (outcome, details) = test_send_audit(&TestSendResult {
            delivered: false,
            error: Some("535 auth failed for mailer".into()),
        });
        assert_eq!(outcome, AuditOutcome::Failure);
        let json = serde_json::to_string(details.as_map()).unwrap();
        assert!(!json.contains("535") && !json.contains("mailer"), "{json}");
    }
}
