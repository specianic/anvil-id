//! Tenant template overrides: compile check with line numbers, unknown variables, fuel limit,
//! autoescape, and override rendering.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use anvil_core::model::{EmailKind, EmailTemplate};
use anvil_core::ports::EmailTemplateCheck;
use anvil_mail::check::{sample_context, variables};
use anvil_mail::{EmailRenderer, MailError, TemplateChecker};
use time::OffsetDateTime;

const SUBJECT: &str = "Confirm your {{ tenant_name }} address";
const TEXT: &str = "Hello {{ email }},\n\nOpen {{ link }} within {{ expires_in }}.\n";
const HTML: &str = "<p>Hello {{ email }}</p>\n<a href=\"{{ link }}\">Confirm</a>\n";

fn check(subject: &str, html: &str, text: &str) -> Result<(), anvil_core::ports::TemplateIssue> {
    TemplateChecker.check(EmailKind::Verification, subject, html, text)
}

#[test]
fn valid_template_passes() {
    check(SUBJECT, HTML, TEXT).unwrap();
    // Control flow and globals are allowed.
    check(
        SUBJECT,
        "{% for i in range(3) %}<b>{{ i }}</b>{% endfor %}{% if link %}{{ link }}{% endif %}",
        "{% set greeting = 'Hi' %}{{ greeting }} {{ email | upper }}",
    )
    .unwrap();
}

#[test]
fn every_kind_accepts_a_template_using_all_its_variables() {
    for kind in EmailKind::ALL {
        let body: String = variables(*kind)
            .iter()
            .map(|v| format!("{{{{ {v} }}}}\n"))
            .collect();
        TemplateChecker
            .check(*kind, "Subject {{ tenant_name }}", &body, &body)
            .unwrap_or_else(|e| panic!("{kind:?}: {e:?}"));
        assert_eq!(sample_context(*kind).len(), variables(*kind).len());
    }
}

#[test]
fn unclosed_block_is_rejected_with_its_line() {
    let err = check(SUBJECT, HTML, "line one\nline two\n{% if link %}\nopen\n").unwrap_err();
    assert!(err.message.starts_with("body_text: "), "{err:?}");
    assert!(err.line.is_some(), "{err:?}");
    assert!(err.line.unwrap() >= 3, "{err:?}");

    let err = check(SUBJECT, "<p>\n{{ email }\n</p>", TEXT).unwrap_err();
    assert!(err.message.starts_with("body_html: "), "{err:?}");
    assert_eq!(err.line, Some(2), "{err:?}");
}

#[test]
fn unknown_variable_is_rejected_with_its_line() {
    let err = check(SUBJECT, HTML, "Hello\n\n{{ unknown_var }}\n").unwrap_err();
    assert!(err.message.starts_with("body_text: "), "{err:?}");
    assert!(err.message.contains("unknown_var"), "{err:?}");
    assert_eq!(err.line, Some(3));

    // Even in a branch the sample never takes.
    let err = check(
        SUBJECT,
        "{% if false %}\n{{ secret_thing }}\n{% endif %}",
        TEXT,
    )
    .unwrap_err();
    assert!(err.message.starts_with("body_html: "), "{err:?}");
    assert!(err.message.contains("secret_thing"), "{err:?}");
    assert_eq!(err.line, Some(2));

    // `link` is not part of the password_changed contract.
    let err = TemplateChecker
        .check(EmailKind::PasswordChanged, "Hi {{ link }}", "x", "x")
        .unwrap_err();
    assert!(err.message.starts_with("subject: "), "{err:?}");
}

#[test]
fn includes_are_not_possible() {
    let err = check(SUBJECT, "{% include 'verification.html' %}", TEXT).unwrap_err();
    assert!(err.message.starts_with("body_html: "), "{err:?}");
}

#[test]
fn subject_must_be_one_non_empty_line() {
    assert!(check("Hello\nBcc: x@example.com", HTML, TEXT).is_err());
    let err = check("{% if false %}x{% endif %}", HTML, TEXT).unwrap_err();
    assert!(err.message.starts_with("subject: "), "{err:?}");
}

#[test]
fn runaway_loops_fail_quickly() {
    let started = Instant::now();
    let err = check(
        SUBJECT,
        HTML,
        "{% for i in range(100000) %}{% for j in range(100000) %}x{% endfor %}{% endfor %}",
    )
    .unwrap_err();
    assert!(err.message.contains("fuel"), "{err:?}");
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "{:?}",
        started.elapsed()
    );

    let started = Instant::now();
    assert!(
        check(
            SUBJECT,
            HTML,
            "{% for i in range(100000000) %}x{% endfor %}"
        )
        .is_err()
    );
    assert!(started.elapsed() < Duration::from_millis(500));

    // Huge values are charged before they are allocated.
    let err = check(SUBJECT, HTML, "{{ 'x' * 1000000000 }}").unwrap_err();
    assert!(err.message.contains("fuel"), "{err:?}");
}

fn payload() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("tenant_name".to_owned(), "Acme".to_owned()),
        (
            "email".to_owned(),
            "<script>alert(1)</script>@example.com".to_owned(),
        ),
        (
            "link".to_owned(),
            "https://id.test/v?token=t&x=1".to_owned(),
        ),
        ("expires_in".to_owned(), "1 hour".to_owned()),
    ])
}

fn override_template() -> EmailTemplate {
    EmailTemplate {
        kind: EmailKind::Verification,
        subject: SUBJECT.to_owned(),
        body_html: HTML.to_owned(),
        body_text: TEXT.to_owned(),
        updated_at: OffsetDateTime::UNIX_EPOCH,
    }
}

#[test]
fn override_renders_with_html_autoescape_and_plain_text() {
    let r = EmailRenderer::embedded();
    let t = override_template();
    let (subject, text, html) = r
        .render_with(Some(&t), EmailKind::Verification, &payload())
        .unwrap();
    assert_eq!(subject, "Confirm your Acme address");
    assert!(text.starts_with("Hello <script>alert(1)</script>@example.com,"));
    assert!(text.contains("https://id.test/v?token=t&x=1"));
    assert!(!html.contains("<script>"), "{html}");
    assert!(html.contains("&lt;script&gt;"), "{html}");
}

#[test]
fn without_override_the_theme_default_is_used() {
    let r = EmailRenderer::embedded();
    let (subject, _, html) = r
        .render_with(None, EmailKind::Verification, &payload())
        .unwrap();
    assert!(subject.starts_with("Confirm your email address for Acme"));
    assert!(html.contains("Confirm email address"));
    assert!(!html.contains("<script>"));
}

#[test]
fn override_render_errors_do_not_leak_payload_values() {
    let r = EmailRenderer::embedded();
    let mut t = override_template();
    t.body_text = "{{ link }}\n{{ not_in_payload }}".to_owned();
    let err = r
        .render_with(Some(&t), EmailKind::Verification, &payload())
        .unwrap_err();
    let msg = err.to_string();
    assert!(matches!(err, MailError::Template(_)));
    assert!(msg.contains("verification.txt:2"), "{msg}");
    assert!(!msg.contains("token=t"), "{msg}");

    t.body_text =
        "{% for i in range(100000) %}{% for j in range(100000) %}x{% endfor %}{% endfor %}"
            .to_owned();
    let msg = r
        .render_with(Some(&t), EmailKind::Verification, &payload())
        .unwrap_err()
        .to_string();
    assert!(msg.contains("fuel"), "{msg}");
}

// ---------------------------------------------------------------------------------------------
// Phase 4 kinds: login_code, email_change, email_changed
// ---------------------------------------------------------------------------------------------

const PHASE4_KINDS: [EmailKind; 3] = [
    EmailKind::LoginCode,
    EmailKind::EmailChange,
    EmailKind::EmailChanged,
];

fn phase4_payload(kind: EmailKind) -> BTreeMap<String, String> {
    let mut p = BTreeMap::new();
    for v in variables(kind) {
        let value = match *v {
            "tenant_name" => "Acme",
            "code" => "482913",
            "link" => "https://id.test/t/default/ui/account/email/confirm?token=tok-123",
            "new_email" => "<b>new</b>@example.com",
            "expires_minutes" => "15",
            other => panic!("unexpected contract variable {other}"),
        };
        p.insert((*v).to_owned(), value.to_owned());
    }
    p
}

#[test]
fn phase4_contracts_are_exact() {
    assert_eq!(
        variables(EmailKind::LoginCode),
        ["tenant_name", "code", "link", "expires_minutes"]
    );
    assert_eq!(
        variables(EmailKind::EmailChange),
        ["tenant_name", "link", "new_email", "expires_minutes"]
    );
    assert_eq!(
        variables(EmailKind::EmailChanged),
        ["tenant_name", "new_email"]
    );
}

#[test]
fn phase4_defaults_render_with_their_contract_variables() {
    let r = EmailRenderer::embedded();
    for kind in PHASE4_KINDS {
        let p = phase4_payload(kind);
        let (subject, text, html) = r
            .render_with(None, kind, &p)
            .unwrap_or_else(|e| panic!("{kind:?}: {e}"));
        assert!(subject.contains("Acme"), "{kind:?}: {subject}");
        assert!(!subject.contains("482913"), "{kind:?}: code in subject");
        assert!(!text.starts_with(&subject), "{kind:?}: subject left in body");
        if p.contains_key("link") {
            assert!(text.contains(&p["link"]), "{kind:?}: link missing from text");
            assert!(html.contains("token=tok-123"), "{kind:?}: link missing from html");
        }
        if p.contains_key("new_email") {
            // Text is plain, HTML is escaped.
            assert!(text.contains("<b>new</b>@example.com"), "{kind:?}");
            assert!(!html.contains("<b>new</b>"), "{kind:?}: {html}");
            assert!(html.contains("&lt;b&gt;new"), "{kind:?}");
        }
        if p.contains_key("expires_minutes") {
            assert!(text.contains("15 minutes"), "{kind:?}");
        }
    }
    let (_, text, html) = r
        .render_with(None, EmailKind::LoginCode, &phase4_payload(EmailKind::LoginCode))
        .unwrap();
    assert!(text.contains("482913") && html.contains("<b>482913</b>"));
    assert!(text.contains("If you did not try to sign in, ignore this email"));
}

#[test]
fn phase4_defaults_pass_their_own_check() {
    // The admin API shows the defaults as editable overrides; saving them unchanged must work.
    for kind in PHASE4_KINDS {
        let name = kind.as_str();
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../themes/default/emails/");
        let text = std::fs::read_to_string(format!("{root}{name}.txt")).unwrap();
        let html = std::fs::read_to_string(format!("{root}{name}.html")).unwrap();
        let (subject, body) = text.split_once('\n').unwrap();
        TemplateChecker
            .check(kind, subject.trim(), &html, body.trim_start())
            .unwrap_or_else(|e| panic!("{kind:?}: {e:?}"));
    }
}

#[test]
fn phase4_override_with_unknown_variable_is_rejected() {
    for kind in PHASE4_KINDS {
        // `email` is in no Phase 4 contract (the worker may add it, templates may not use it).
        let err = TemplateChecker
            .check(kind, "Hi {{ tenant_name }}", "<p>x</p>", "Hello\n{{ email }}\n")
            .unwrap_err();
        assert!(err.message.starts_with("body_text: "), "{kind:?}: {err:?}");
        assert!(err.message.contains("email"), "{kind:?}: {err:?}");
        assert_eq!(err.line, Some(2), "{kind:?}");
    }
    // `code` belongs to login_code only.
    let err = TemplateChecker
        .check(EmailKind::EmailChange, "{{ code }}", "x", "x")
        .unwrap_err();
    assert!(err.message.starts_with("subject: "), "{err:?}");
}

#[test]
fn phase4_missing_variable_fails_rendering() {
    let r = EmailRenderer::embedded();
    for kind in PHASE4_KINDS {
        for var in variables(kind) {
            let mut p = phase4_payload(kind);
            p.remove(*var);
            let err = r.render_with(None, kind, &p).unwrap_err();
            let msg = err.to_string();
            assert!(matches!(err, MailError::Template(_)), "{kind:?}/{var}");
            assert!(msg.contains("undefined"), "{kind:?}/{var}: {msg}");
            assert!(!msg.contains("tok-123"), "{kind:?}/{var}: {msg}");
        }
    }
}
