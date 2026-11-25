//! Compile-and-test-render check for tenant email template overrides ([`TemplateChecker`]).
//!
//! # Variable contract
//!
//! A template can use exactly the payload keys the core services seal for its kind
//! ([`variables`]); any other variable is rejected when the template is saved. This list is the
//! public contract shown to administrators by the management API:
//!
//! | Kind                 | Variables                                   |
//! |----------------------|---------------------------------------------|
//! | `verification`       | `tenant_name`, `email`, `link`, `expires_in` |
//! | `recovery`           | `tenant_name`, `email`, `link`, `expires_in` |
//! | `invitation`         | `tenant_name`, `email`, `link`, `expires_in` |
//! | `password_changed`   | `tenant_name`, `email`                      |
//! | `recovery_code_used` | `tenant_name`, `remaining`                  |
//!
//! # What is checked
//!
//! For each part (`subject`, `body_text`, `body_html`, in that order):
//!
//! 1. it compiles (syntax errors carry the line);
//! 2. it references no variable outside the contract (static analysis, so variables in branches
//!    the sample does not take are caught too; minijinja globals such as `range` are allowed);
//! 3. it renders against the sample context ([`sample_context`]) in the production environment
//!    (strict undefined, HTML autoescape, fuel limit), so runaway loops fail here;
//! 4. the subject is a single line that renders to a non-empty value.
//!
//! The first problem is returned as a [`TemplateIssue`] whose message starts with the part name
//! followed by `": "` (`subject: …`, `body_text: …`, `body_html: …`); the management API uses
//! that prefix as the error field. Messages describe the template only: the sample values are
//! fixed strings, not tenant data.

use std::collections::{BTreeMap, BTreeSet};

use anvil_core::model::EmailKind;
use anvil_core::ports::{EmailTemplateCheck, TemplateIssue};
use minijinja::{Environment, ErrorKind};

use crate::render::{clean_subject, environment};

/// The variables a template of `kind` may use (see the module docs).
pub fn variables(kind: EmailKind) -> &'static [&'static str] {
    match kind {
        EmailKind::Verification | EmailKind::Recovery | EmailKind::Invitation => {
            &["tenant_name", "email", "link", "expires_in"]
        }
        EmailKind::PasswordChanged => &["tenant_name", "email"],
        EmailKind::RecoveryCodeUsed => &["tenant_name", "remaining"],
    }
}

/// Sample values for every variable of `kind`, used for the test render.
pub fn sample_context(kind: EmailKind) -> BTreeMap<String, String> {
    variables(kind)
        .iter()
        .map(|&name| {
            let value = match name {
                "tenant_name" => "Example Organisation",
                "email" => "user@example.com",
                "link" => "https://id.example.com/t/default/ui/verification?token=sample-token",
                "expires_in" => "1 hour",
                "remaining" => "7",
                _ => "sample",
            };
            (name.to_owned(), value.to_owned())
        })
        .collect()
}

/// The production [`EmailTemplateCheck`].
#[derive(Debug, Default, Clone, Copy)]
pub struct TemplateChecker;

impl EmailTemplateCheck for TemplateChecker {
    fn check(
        &self,
        kind: EmailKind,
        subject: &str,
        html: &str,
        text: &str,
    ) -> Result<(), TemplateIssue> {
        if subject.contains(['\r', '\n']) {
            return Err(issue("subject", None, "the subject must be a single line"));
        }
        let name = kind.as_str();
        let files = [
            format!("{name}.subject"),
            format!("{name}.txt"),
            format!("{name}.html"),
        ];
        let env = environment();
        let sample = sample_context(kind);
        let rendered = check_part(&env, kind, &sample, "subject", &files[0], subject)?;
        if clean_subject(&rendered).is_none() {
            return Err(issue("subject", None, "the subject renders empty"));
        }
        check_part(&env, kind, &sample, "body_text", &files[1], text)?;
        check_part(&env, kind, &sample, "body_html", &files[2], html)?;
        Ok(())
    }
}

fn check_part<'s>(
    env: &Environment<'s>,
    kind: EmailKind,
    sample: &BTreeMap<String, String>,
    part: &'static str,
    file: &'s str,
    source: &'s str,
) -> Result<String, TemplateIssue> {
    let tmpl = env
        .template_from_named_str(file, source)
        .map_err(|e| from_error(part, &e))?;

    let allowed: BTreeSet<&str> = variables(kind)
        .iter()
        .copied()
        .chain(env.globals().map(|(name, _)| name))
        .collect();
    let mut unknown: Vec<String> = tmpl
        .undeclared_variables(false)
        .into_iter()
        .filter(|v| !allowed.contains(v.as_str()))
        .collect();
    unknown.sort();
    if let Some(var) = unknown.first() {
        return Err(issue(
            part,
            line_of(source, var),
            &format!(
                "unknown variable `{var}` (available: {})",
                variables(kind).join(", ")
            ),
        ));
    }

    tmpl.render(crate::render::context(sample))
        .map_err(|e| from_error(part, &e))
}

fn from_error(part: &'static str, err: &minijinja::Error) -> TemplateIssue {
    let message = match err.kind() {
        ErrorKind::OutOfFuel => "the template runs too long (fuel limit exceeded)".to_owned(),
        ErrorKind::UndefinedError => "undefined variable or attribute".to_owned(),
        ErrorKind::TemplateNotFound => "templates cannot include other templates".to_owned(),
        _ => match err.detail() {
            Some(detail) => format!("{}: {detail}", err.kind()),
            None => err.kind().to_string(),
        },
    };
    issue(
        part,
        err.line().and_then(|l| u32::try_from(l).ok()),
        &message,
    )
}

fn issue(part: &'static str, line: Option<u32>, message: &str) -> TemplateIssue {
    TemplateIssue {
        line,
        message: format!("{part}: {message}"),
    }
}

/// The first line on which `var` appears as a whole word (1-based).
fn line_of(source: &str, var: &str) -> Option<u32> {
    let is_ident = |c: char| c.is_alphanumeric() || c == '_';
    source.lines().enumerate().find_map(|(i, line)| {
        line.match_indices(var)
            .any(|(at, _)| {
                let before = line[..at].chars().next_back();
                let after = line[at + var.len()..].chars().next();
                !before.is_some_and(is_ident) && !after.is_some_and(is_ident)
            })
            .then(|| u32::try_from(i + 1).unwrap_or(u32::MAX))
    })
}
