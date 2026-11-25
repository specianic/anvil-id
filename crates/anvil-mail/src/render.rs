//! Email template rendering.
//!
//! Every email exists as `emails/{name}.txt` and `emails/{name}.html` (themes/default/README.md).
//! The first line of the text template is the subject (an optional `Subject:` prefix is
//! stripped); it is removed from the text body. HTML templates are auto-escaped, text templates
//! are not. Undefined variables are an error (strict mode), so a missing payload key never
//! silently produces an email with a blank link.
//!
//! Template lookup follows ARCHITECTURE §10.4: an operator theme directory first, then the
//! defaults embedded in the binary.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use minijinja::{Environment, ErrorKind, UndefinedBehavior, Value};

use crate::MailError;

/// The default email templates, embedded at compile time.
#[derive(rust_embed::Embed)]
#[folder = "../../themes/default/emails/"]
struct DefaultEmails;

/// Renders emails from the theme templates.
pub struct EmailRenderer {
    env: Environment<'static>,
}

impl std::fmt::Debug for EmailRenderer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailRenderer").finish_non_exhaustive()
    }
}

impl EmailRenderer {
    /// A renderer that uses only the embedded default templates.
    pub fn embedded() -> Self {
        Self::build(None)
    }

    /// A renderer that looks in `dir/emails/` first and falls back to the embedded defaults for
    /// any file the directory does not contain. `dir` is the theme root (the directory that
    /// holds `templates/`, `emails/` and `static/`).
    pub fn with_theme_dir(dir: &Path) -> Self {
        Self::build(Some(dir.join("emails")))
    }

    fn build(theme_emails: Option<PathBuf>) -> Self {
        let mut env = Environment::new();
        env.set_undefined_behavior(UndefinedBehavior::Strict);
        env.set_loader(move |name: &str| load(theme_emails.as_deref(), name));
        Self { env }
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
        let ctx = Value::from_pairs(payload.iter().map(|(k, v)| (k.as_str(), v.as_str())));
        let text = self.render_file(&format!("{template}.txt"), &ctx)?;
        let html = self.render_file(&format!("{template}.html"), &ctx)?;

        let (first, rest) = text.split_once('\n').unwrap_or((text.as_str(), ""));
        let first = first.trim();
        let first = first.strip_prefix("Subject:").unwrap_or(first);
        let subject: String = first
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect::<String>()
            .trim()
            .to_owned();
        if subject.is_empty() {
            return Err(MailError::Template(format!(
                "{template}.txt: first line (subject) is empty"
            )));
        }
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

/// Describes a minijinja error by kind and line only: its full display can include template
/// source, which after rendering may be adjacent to payload values.
fn template_error(name: &str, err: &minijinja::Error) -> MailError {
    let kind = match err.kind() {
        ErrorKind::TemplateNotFound => "unknown template".to_owned(),
        ErrorKind::UndefinedError => "undefined variable".to_owned(),
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
}
