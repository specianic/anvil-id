//! Tenant template overrides: compile check with line numbers, unknown variables, fuel limit,
//! autoescape, and override rendering.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use anvil_core::model::{EmailKind, EmailTemplate};
use anvil_core::ports::EmailTemplateCheck;
use anvil_mail::check::{optional_variables, sample_context, sample_variants, variables};
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
        // Optional variables need a guard (they are absent from some emails).
        let body: String = variables(*kind)
            .iter()
            .map(|v| {
                if optional_variables(*kind).contains(v) {
                    format!("{{% if {v} is defined %}}{{{{ {v} }}}}{{% endif %}}\n")
                } else {
                    format!("{{{{ {v} }}}}\n")
                }
            })
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
        assert!(
            !text.starts_with(&subject),
            "{kind:?}: subject left in body"
        );
        if p.contains_key("link") {
            assert!(
                text.contains(&p["link"]),
                "{kind:?}: link missing from text"
            );
            assert!(
                html.contains("token=tok-123"),
                "{kind:?}: link missing from html"
            );
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
        .render_with(
            None,
            EmailKind::LoginCode,
            &phase4_payload(EmailKind::LoginCode),
        )
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
            .check(
                kind,
                "Hi {{ tenant_name }}",
                "<p>x</p>",
                "Hello\n{{ email }}\n",
            )
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
            if optional_variables(kind).contains(var) {
                continue;
            }
            let mut p = phase4_payload(kind);
            p.remove(*var);
            let err = r.render_with(None, kind, &p).unwrap_err();
            let msg = err.to_string();
            assert!(matches!(err, MailError::Template(_)), "{kind:?}/{var}");
            assert!(msg.contains("undefined"), "{kind:?}/{var}: {msg}");
            assert!(!msg.contains("tok-123"), "{kind:?}/{var}: {msg}");
        }
    }
    // A login_code payload without both the code and the link is an error, not a blank email.
    let mut p = phase4_payload(EmailKind::LoginCode);
    p.remove("code");
    p.remove("link");
    let err = r.render_with(None, EmailKind::LoginCode, &p).unwrap_err();
    assert!(matches!(err, MailError::Template(_)), "{err}");
    assert!(err.to_string().contains("none of code, link"), "{err}");
}

// ---------------------------------------------------------------------------------------------
// login_code: `code` and `link` are optional (email_otp / magic_link)
// ---------------------------------------------------------------------------------------------

fn login_code_check(text: &str, html: &str) -> Result<(), anvil_core::ports::TemplateIssue> {
    TemplateChecker.check(
        EmailKind::LoginCode,
        "Sign in to {{ tenant_name }}",
        html,
        text,
    )
}

#[test]
fn login_code_optional_variables_and_variants() {
    assert_eq!(optional_variables(EmailKind::LoginCode), ["code", "link"]);
    for kind in EmailKind::ALL {
        if *kind != EmailKind::LoginCode {
            assert!(optional_variables(*kind).is_empty(), "{kind:?}");
            assert_eq!(sample_variants(*kind).len(), 1, "{kind:?}");
        }
    }
    let variants = sample_variants(EmailKind::LoginCode);
    assert_eq!(variants.len(), 3);
    assert!(variants[0].0.contains_key("code") && variants[0].0.contains_key("link"));
    assert!(variants[1].0.contains_key("code") && !variants[1].0.contains_key("link"));
    assert!(!variants[2].0.contains_key("code") && variants[2].0.contains_key("link"));
}

#[test]
fn login_code_unguarded_code_is_rejected() {
    // The link-only sample has no `code`.
    let err = login_code_check("Code: {{ code }}", "<p>x</p>").unwrap_err();
    assert!(err.message.starts_with("body_text: "), "{err:?}");
    assert!(err.message.contains("`code`"), "{err:?}");
    assert!(err.message.contains("is defined"), "{err:?}");
    let err = login_code_check("x", "<p>\n{{ code }}</p>").unwrap_err();
    assert!(err.message.starts_with("body_html: "), "{err:?}");
    assert!(err.message.contains("`code`"), "{err:?}");
    assert_eq!(err.line, Some(2), "{err:?}");
    let err = TemplateChecker
        .check(EmailKind::LoginCode, "Code {{ code }}", "x", "x")
        .unwrap_err();
    assert!(err.message.starts_with("subject: "), "{err:?}");
}

#[test]
fn login_code_unguarded_link_is_rejected() {
    // The code-only sample has no `link`.
    let err = login_code_check("Open {{ link }}", "<p>x</p>").unwrap_err();
    assert!(err.message.starts_with("body_text: "), "{err:?}");
    assert!(err.message.contains("`link`"), "{err:?}");
    let err = login_code_check("x", "<a href=\"{{ link }}\">Sign in</a>").unwrap_err();
    assert!(err.message.starts_with("body_html: "), "{err:?}");
    assert!(err.message.contains("`link`"), "{err:?}");
}

#[test]
fn login_code_bare_if_is_rejected_because_rendering_is_strict() {
    // Strict undefined: `{% if code %}` on an absent value fails too; `is defined` is required.
    let err = login_code_check("{% if code %}{{ code }}{% endif %}", "x").unwrap_err();
    assert!(err.message.starts_with("body_text: "), "{err:?}");
    assert!(err.message.contains("`code`"), "{err:?}");
}

#[test]
fn login_code_guarded_template_passes() {
    login_code_check(
        "{% if code is defined %}Code: {{ code }}{% endif %}\n\
         {% if link is defined %}Link: {{ link }}{% endif %}\n\
         Valid {{ expires_minutes }} minutes.",
        "{% if code is defined %}<b>{{ code }}</b>{% endif %}\
         {% if link is defined %}<a href=\"{{ link }}\">Sign in</a>{% endif %}",
    )
    .unwrap();
}

#[test]
fn login_code_default_renders_every_payload_shape() {
    let r = EmailRenderer::embedded();
    let full = phase4_payload(EmailKind::LoginCode);
    let link = full["link"].clone();

    // Both.
    let (subject, text, html) = r.render_with(None, EmailKind::LoginCode, &full).unwrap();
    assert_eq!(subject, "Your Acme sign-in code");
    assert!(text.contains("482913") && text.contains(&link), "{text}");
    assert!(
        html.contains("<b>482913</b>") && html.contains("token=tok-123"),
        "{html}"
    );
    assert!(
        text.contains("The code and the link expire in 15 minutes"),
        "{text}"
    );

    // Code only: nothing about a link.
    let mut p = full.clone();
    p.remove("link");
    let (subject, text, html) = r.render_with(None, EmailKind::LoginCode, &p).unwrap();
    assert_eq!(subject, "Your Acme sign-in code");
    assert!(text.contains("482913") && html.contains("<b>482913</b>"));
    for body in [&text, &html] {
        let lower = body.to_lowercase();
        assert!(
            !lower.contains("link"),
            "code-only email mentions a link: {body}"
        );
        assert!(!lower.contains("button"), "{body}");
        assert!(!body.contains("tok-123"), "{body}");
    }
    assert!(text.contains("The code expires in 15 minutes"), "{text}");

    // Link only: no code anywhere.
    let mut p = full.clone();
    p.remove("code");
    let (subject, text, html) = r.render_with(None, EmailKind::LoginCode, &p).unwrap();
    assert_eq!(subject, "Your Acme sign-in link");
    assert!(text.contains(&link) && html.contains("token=tok-123"));
    for body in [&text, &html] {
        assert!(
            !body.to_lowercase().contains("code"),
            "link-only email mentions a code: {body}"
        );
        assert!(!body.contains("482913"), "{body}");
    }
    assert!(text.contains("The link expires in 15 minutes"), "{text}");
    assert!(text.contains("If you did not try to sign in, ignore this email"));
}
