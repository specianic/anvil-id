//! Email template rendering.
//!
//! Every email exists as `emails/{name}.txt` and `emails/{name}.html` (themes/default/README.md).
//! The first line of the text template is the subject (an optional `Subject:` prefix is
//! stripped); it is removed from the text body. HTML templates are auto-escaped, text templates
//! are not. Undefined variables are an error (strict mode), so a missing payload key never
//! silently produces an email with a blank link.
//!
//! Template lookup follows ARCHITECTURE §10.4: a tenant override stored through
//! `MailSettingsRepo` first ([`EmailRenderer::render_with`]), then an operator theme directory,
//! then the defaults embedded in the binary.
//!
//! Every environment comes from one factory ([`environment`]): strict undefined, HTML
//! autoescape for `.html` templates only, and a fuel limit ([`RENDER_FUEL`]) so a runaway loop in
//! a tenant-edited template fails with an error instead of hanging the worker. Tenant overrides
//! are rendered in an environment without a loader, so they cannot include theme files.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anvil_core::model::{EmailKind, EmailTemplate};
use minijinja::{AutoEscape, Environment, ErrorKind, UndefinedBehavior, Value};

use crate::MailError;

/// Fuel available to one template render. The default templates use well under 10% of it
/// (tested); a runaway loop exhausts it in a few milliseconds.
pub const RENDER_FUEL: u64 = 50_000;

/// The one minijinja environment factory: strict undefined, `.html` autoescaped, bounded by
/// [`RENDER_FUEL`]. No loader is set.
pub fn environment<'s>() -> Environment<'s> {
    environment_with_fuel(RENDER_FUEL)
}

pub(crate) fn environment_with_fuel<'s>(fuel: u64) -> Environment<'s> {
    let mut env = Environment::new();
    env.set_undefined_behavior(UndefinedBehavior::Strict);
    env.set_fuel(Some(fuel));
    env.set_auto_escape_callback(|name| {
        if name.ends_with(".html") {
            AutoEscape::Html
        } else {
            AutoEscape::None
        }
    });
    env
}

/// The default email templates, embedded at compile time.
#[derive(rust_embed::Embed)]
#[folder = "../../themes/default/emails/"]
struct DefaultEmails;

/// Renders emails from tenant overrides and the theme templates.
pub struct EmailRenderer {
    env: Environment<'static>,
    overrides: Environment<'static>,
}

impl std::fmt::Debug for EmailRenderer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailRenderer").finish_non_exhaustive()
    }
}

impl EmailRenderer {
    /// A renderer that uses only the embedded default templates.
    pub fn embedded() -> Self {
        Self::build(None, RENDER_FUEL)
    }

    /// A renderer that looks in `dir/emails/` first and falls back to the embedded defaults for
    /// any file the directory does not contain. `dir` is the theme root (the directory that
    /// holds `templates/`, `emails/` and `static/`).
    pub fn with_theme_dir(dir: &Path) -> Self {
        Self::build(Some(dir.join("emails")), RENDER_FUEL)
    }

    fn build(theme_emails: Option<PathBuf>, fuel: u64) -> Self {
        let mut env = environment_with_fuel(fuel);
        env.set_loader(move |name: &str| load(theme_emails.as_deref(), name));
        Self {
            env,
            overrides: environment_with_fuel(fuel),
        }
    }

    /// Renders email `kind` from the tenant `override_` when present, otherwise from the theme
    /// (see [`render`](Self::render)). Returns `(subject, text, html)`.
    ///
    /// An override's subject is its own (single-line) template; its text body is rendered as
    /// is (no subject line is stripped).
    pub fn render_with(
        &self,
        override_: Option<&EmailTemplate>,
        kind: EmailKind,
        payload: &BTreeMap<String, String>,
    ) -> Result<(String, String, String), MailError> {
        if !crate::check::has_contract(kind) {
            return Err(MailError::Template(crate::check::no_contract_message(kind)));
        }
        let Some(t) = override_ else {
            return self.render(kind.as_str(), payload);
        };
        let ctx = context(payload);
        let name = kind.as_str();
        let render = |file: String, source: &str| {
            self.overrides
                .render_named_str(&file, source, &ctx)
                .map_err(|e| template_error(&file, &e))
        };
        let subject = render(format!("{name}.subject"), &t.subject)?;
        let subject = clean_subject(&subject)
            .ok_or_else(|| MailError::Template(format!("{name}.subject: subject is empty")))?;
        let text = render(format!("{name}.txt"), &t.body_text)?;
        let html = render(format!("{name}.html"), &t.body_html)?;
        Ok((subject, text, html))
    }

    /// Renders `template` with the payload map flattened into template variables.
    ///
    /// Returns `(subject, text, html)`. Unknown templates, invalid template names, undefined
    /// variables and an empty subject are errors. Error messages name the template and the
    /// failing line but never contain payload values.
    pub fn render(
        &self,
        template: &str,
        payload: &BTreeMap<String, String>,
    ) -> Result<(String, String, String), MailError> {
        if !valid_template_name(template) {
            return Err(MailError::Template("invalid template name".into()));
        }
        let ctx = context(payload);
        let text = self.render_file(&format!("{template}.txt"), &ctx)?;
        let html = self.render_file(&format!("{template}.html"), &ctx)?;

        let (first, rest) = text.split_once('\n').unwrap_or((text.as_str(), ""));
        let first = first.trim();
        let first = first.strip_prefix("Subject:").unwrap_or(first);
        let subject = clean_subject(first).ok_or_else(|| {
            MailError::Template(format!("{template}.txt: first line (subject) is empty"))
        })?;
        let body = rest.trim_start_matches(['\r', '\n']).to_owned();
        Ok((subject, body, html))
    }

    fn render_file(&self, name: &str, ctx: &Value) -> Result<String, MailError> {
        let tmpl = self
            .env
            .get_template(name)
            .map_err(|e| template_error(name, &e))?;
        tmpl.render(ctx).map_err(|e| template_error(name, &e))
    }
}

/// The payload map as template variables.
pub(crate) fn context(payload: &BTreeMap<String, String>) -> Value {
    Value::from_pairs(payload.iter().map(|(k, v)| (k.as_str(), v.as_str())))
}

/// A rendered subject as a header value: control characters become spaces, surrounding
/// whitespace is trimmed. `None` if nothing is left.
pub(crate) fn clean_subject(raw: &str) -> Option<String> {
    let subject = raw
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .trim()
        .to_owned();
    (!subject.is_empty()).then_some(subject)
}

/// Describes a minijinja error by kind and line only: its full display can include template
/// source, which after rendering may be adjacent to payload values.
fn template_error(name: &str, err: &minijinja::Error) -> MailError {
    let kind = match err.kind() {
        ErrorKind::TemplateNotFound => "unknown template".to_owned(),
        ErrorKind::UndefinedError => "undefined variable".to_owned(),
        ErrorKind::OutOfFuel => "template ran out of fuel (runaway loop)".to_owned(),
        other => format!("{other:?}"),
    };
    match err.line() {
        Some(line) => MailError::Template(format!("{name}:{line}: {kind}")),
        None => MailError::Template(format!("{name}: {kind}")),
    }
}

/// Template stems are plain identifiers (`verification`, `password_changed`); this also keeps
/// theme-directory lookups confined to the `emails/` directory.
fn valid_template_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

fn load(theme_emails: Option<&Path>, name: &str) -> Result<Option<String>, minijinja::Error> {
    let Some((stem, ext)) = name.rsplit_once('.') else {
        return Ok(None);
    };
    if !valid_template_name(stem) || !matches!(ext, "txt" | "html") {
        return Ok(None);
    }
    if let Some(dir) = theme_emails {
        match std::fs::read_to_string(dir.join(name)) {
            Ok(src) => return Ok(Some(src)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(minijinja::Error::new(
                    ErrorKind::InvalidOperation,
                    "could not read theme email template",
                )
                .with_source(e));
            }
        }
    }
    match DefaultEmails::get(name) {
        Some(file) => String::from_utf8(file.data.into_owned())
            .map(Some)
            .map_err(|_| {
                minijinja::Error::new(ErrorKind::InvalidOperation, "template is not UTF-8")
            }),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(link: &str) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("tenant_name".to_owned(), "Acme".to_owned()),
            ("email".to_owned(), "alice@example.com".to_owned()),
            ("link".to_owned(), link.to_owned()),
            ("expires_in".to_owned(), "1 hour".to_owned()),
        ])
    }

    #[test]
    fn kinds_without_contract_are_explicit_errors() {
        use anvil_core::ports::EmailTemplateCheck as _;
        let r = EmailRenderer::embedded();
        let t = EmailTemplate {
            kind: EmailKind::LoginCode,
            subject: "Code".into(),
            body_html: "<p>hi</p>".into(),
            body_text: "hi".into(),
            updated_at: time::OffsetDateTime::UNIX_EPOCH,
        };
        for kind in [
            EmailKind::LoginCode,
            EmailKind::EmailChange,
            EmailKind::EmailChanged,
        ] {
            let err = r.render_with(None, kind, &payload("x")).unwrap_err();
            assert!(err.to_string().contains("no template contract"), "{err}");
            let err = r.render_with(Some(&t), kind, &payload("x")).unwrap_err();
            assert!(err.to_string().contains("no template contract"), "{err}");
            let issue = crate::check::TemplateChecker
                .check(kind, "Subject", "<p>x</p>", "x")
                .unwrap_err();
            assert!(issue.message.contains("no template contract"), "{issue:?}");
        }
    }

    #[test]
    fn renders_every_default_email() {
        let r = EmailRenderer::embedded();
        let link = "https://id.example.test/verify?token=abc123";
        for name in ["verification", "recovery", "invitation", "password_changed"] {
            let (subject, text, html) = r.render(name, &payload(link)).unwrap();
            assert!(!subject.is_empty(), "{name}: empty subject");
            assert!(subject.contains("Acme"), "{name}: {subject}");
            assert!(!text.starts_with(&subject), "{name}: subject left in body");
            assert!(text.contains("alice@example.com"), "{name}");
            assert!(html.contains("alice@example.com"), "{name}");
            if name != "password_changed" {
                assert!(text.contains(link), "{name}: link missing from text");
                assert!(
                    html.contains("token=abc123"),
                    "{name}: link missing from html"
                );
            }
        }
    }

    #[test]
    fn html_escapes_payload_values_and_text_does_not() {
        let r = EmailRenderer::embedded();
        let mut p = payload("https://x.test/?a=1");
        p.insert("email".into(), "<b>bob</b>@example.com".into());
        let (_, text, html) = r.render("verification", &p).unwrap();
        assert!(!html.contains("<b>bob</b>"));
        assert!(html.contains("&lt;b&gt;bob&lt;&#x2f;b&gt;") || html.contains("&lt;b&gt;bob"));
        assert!(text.contains("<b>bob</b>@example.com"));
    }

    #[test]
    fn unknown_template_is_an_error() {
        let r = EmailRenderer::embedded();
        let err = r.render("no_such_email", &payload("x")).unwrap_err();
        assert!(matches!(err, MailError::Template(_)));
    }

    #[test]
    fn invalid_template_names_are_rejected() {
        let r = EmailRenderer::embedded();
        for name in [
            "",
            "../templates/login",
            "Verification",
            "a/b",
            "verification.txt",
        ] {
            assert!(r.render(name, &payload("x")).is_err(), "{name:?}");
        }
    }

    #[test]
    fn missing_payload_key_is_a_strict_error() {
        let r = EmailRenderer::embedded();
        let mut p = payload("https://x.test/secret-link");
        p.remove("link");
        let err = r.render("verification", &p).unwrap_err();
        let msg = err.to_string();
        assert!(matches!(err, MailError::Template(_)));
        assert!(msg.contains("undefined"), "{msg}");
        assert!(!msg.contains("alice@example.com"), "{msg}");
    }

    #[test]
    fn theme_dir_overrides_individual_files_and_falls_back() {
        let dir = std::env::temp_dir().join(format!("anvil-mail-theme-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(dir.join("emails")).unwrap();
        std::fs::write(
            dir.join("emails/verification.txt"),
            "Subject: Custom {{ tenant_name }}\n\nGo: {{ link }}\n",
        )
        .unwrap();
        let r = EmailRenderer::with_theme_dir(&dir);
        let (subject, text, html) = r
            .render("verification", &payload("https://l.test/"))
            .unwrap();
        assert_eq!(subject, "Custom Acme");
        assert_eq!(text.trim_end(), "Go: https://l.test/");
        // HTML not overridden: embedded default.
        assert!(html.contains("Confirm your email address"));
        // Other emails entirely from the embedded defaults.
        let (subject, _, _) = r.render("recovery", &payload("https://l.test/")).unwrap();
        assert!(subject.starts_with("Reset your"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn empty_subject_is_an_error() {
        let dir = std::env::temp_dir().join(format!("anvil-mail-theme-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(dir.join("emails")).unwrap();
        std::fs::write(dir.join("emails/recovery.txt"), "\nbody {{ link }}\n").unwrap();
        let r = EmailRenderer::with_theme_dir(&dir);
        assert!(r.render("recovery", &payload("x")).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn default_templates_use_under_ten_percent_of_the_fuel() {
        let r = EmailRenderer::build(None, RENDER_FUEL / 10);
        for name in ["verification", "recovery", "invitation", "password_changed"] {
            r.render(name, &payload("https://id.example.test/l?token=abc"))
                .unwrap_or_else(|e| panic!("{name}: {e}"));
        }
    }

    #[test]
    fn subject_cleaning_strips_control_characters() {
        assert_eq!(clean_subject(" a\r\nBcc: x ").as_deref(), Some("a  Bcc: x"));
        assert_eq!(clean_subject(" \t "), None);
    }
}
