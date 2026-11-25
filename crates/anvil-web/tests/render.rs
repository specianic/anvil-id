//! Renders every page template of the embedded default theme from sample contexts (insta
//! snapshots) and checks the theme contract: stable ids, the CSRF input, escaping, no external
//! hosts, and theme-directory override with fallback.

use anvil_core::flow::form::{FieldKind, FormDescription, FormField, FormMessage, MessageLevel};
use anvil_web::render::Renderer;
use minijinja::value::{Serde, Value};
use minijinja::context;

fn renderer() -> Renderer {
    Renderer::new(None).expect("embedded theme compiles")
}

fn page(title: &str) -> Value {
    page_with(title, false)
}

fn page_with(title: &str, dev_mode: bool) -> Value {
    context! {
        title => title,
        tenant_name => "Acme",
        dev_mode => dev_mode,
        asset_base => "/t/acme/assets",
        links => context! {
            login => "/t/acme/ui/login?flow=f1",
            registration => "/t/acme/ui/registration",
            recovery => "/t/acme/ui/recovery",
        },
    }
}

fn field(name: &str, kind: FieldKind, label: &str, value: Option<&str>) -> FormField {
    FormField {
        name: name.into(),
        kind,
        label: label.into(),
        value: value.map(str::to_owned),
        required: kind != FieldKind::Hidden,
        autocomplete: None,
        messages: Vec::new(),
    }
}

fn form(id: &str, fields: Vec<FormField>) -> FormDescription {
    FormDescription {
        id: id.into(),
        action: format!("/t/acme/ui/{id}?flow=f1"),
        method: "post",
        fields,
        messages: Vec::new(),
        csrf_token: "csrf-sample-token".into(),
    }
}

fn render_form(template: &str, title: &str, f: &FormDescription) -> String {
    let html = renderer()
        .page(template, context! { page => page(title), form => Value::from(Serde(f)) })
        .unwrap_or_else(|e| panic!("{template} renders: {e}"))
        .0;
    assert!(
        html.contains(&format!("id=\"{}-submit\"", f.id)),
        "{template}: submit id"
    );
    assert!(
        html.contains("name=\"csrf_token\" value=\"csrf-sample-token\""),
        "{template}: csrf input"
    );
    assert_no_external(template, &html, &[]);
    html
}

/// minijinja's HTML escaping also escapes `/` as `&#x2f;`; browsers decode it. Checks compare on
/// the decoded text.
fn decoded(html: &str) -> String {
    html.replace("&#x2f;", "/")
}

/// No absolute URL in the output except values supplied by the context.
fn assert_no_external(template: &str, html: &str, allowed: &[&str]) {
    let mut scrubbed = decoded(html);
    for a in allowed {
        scrubbed = scrubbed.replace(a, "");
    }
    for needle in ["http://", "https://", "//cdn", "<script", " style=", "onclick="] {
        assert!(
            !scrubbed.contains(needle),
            "{template} contains {needle:?}:\n{html}"
        );
    }
}

fn login_form() -> FormDescription {
    let mut f = form(
        "login",
        vec![
            field("identifier", FieldKind::Email, "Email", Some("ada@example.test")),
            field("password", FieldKind::Password, "Password", None),
        ],
    );
    f.messages.push(FormMessage {
        level: MessageLevel::Error,
        key: "login.invalid_credentials".into(),
        text: "The email or password is incorrect.".into(),
    });
    f
}

#[test]
fn login() {
    let html = render_form("login.html", "Sign in", &login_form());
    assert!(html.contains("id=\"link-recovery\""));
    assert!(html.contains("role=\"alert\""));
    insta::assert_snapshot!("login", html);
}

#[test]
fn registration() {
    let mut pw = field("password", FieldKind::Password, "Password", Some("never-echoed"));
    pw.messages.push(FormMessage {
        level: MessageLevel::Error,
        key: "password.too_short".into(),
        text: "must be at least 8 characters".into(),
    });
    let f = form(
        "registration",
        vec![
            field("email", FieldKind::Email, "Email", Some("ada@example.test")),
            field("name", FieldKind::Text, "Name", Some("Ada")),
            pw,
        ],
    );
    let html = render_form("registration.html", "Create an account", &f);
    assert!(!html.contains("never-echoed"), "password values are never written back");
    assert!(html.contains("aria-invalid=\"true\""));
    insta::assert_snapshot!("registration", html);
}

#[test]
fn verification() {
    let f = form(
        "verification",
        vec![field("token", FieldKind::Hidden, "", Some("tok-123"))],
    );
    let html = render_form("verification.html", "Confirm your email address", &f);
    assert!(html.contains("type=\"hidden\" id=\"token\" name=\"token\" value=\"tok-123\""));
    insta::assert_snapshot!("verification", html);
}

#[test]
fn recovery() {
    let f = form(
        "recovery",
        vec![field("email", FieldKind::Email, "Email", None)],
    );
    insta::assert_snapshot!("recovery", render_form("recovery.html", "Reset your password", &f));
}

#[test]
fn recovery_reset() {
    let f = form(
        "recovery-reset",
        vec![
            field("token", FieldKind::Hidden, "", Some("tok-456")),
            field("password", FieldKind::Password, "New password", None),
        ],
    );
    insta::assert_snapshot!(
        "recovery_reset",
        render_form("recovery_reset.html", "Choose a new password", &f)
    );
}

#[test]
fn setup() {
    let f = form(
        "setup",
        vec![
            field("token", FieldKind::Hidden, "", Some("setup-tok")),
            field("email", FieldKind::Email, "Administrator email", None),
            field("password", FieldKind::Password, "Password", None),
        ],
    );
    insta::assert_snapshot!("setup", render_form("setup.html", "Set up AnvilID", &f));
}

#[test]
fn setup_done() {
    let token_endpoint = "https://op.test/t/system/token";
    let api = "https://op.test/api/admin/v1";
    let html = renderer()
        .page(
            "setup_done.html",
            context! {
                page => page("Setup complete"),
                admin_email => "admin@example.test",
                mgmt_client_id => "mgmt-123",
                mgmt_client_secret => "secret-shown-once",
                token_endpoint => token_endpoint,
                admin_api_base => api,
            },
        )
        .expect("renders")
        .0;
    for id in [
        "mgmt-client-id",
        "mgmt-client-secret",
        "token-endpoint",
        "admin-api-base",
        "admin-email",
    ] {
        assert!(html.contains(&format!("id=\"{id}\"")), "{id}");
    }
    assert_no_external("setup_done.html", &html, &[token_endpoint, api]);
    insta::assert_snapshot!("setup_done", html);
}

#[test]
fn message() {
    let html = renderer()
        .page(
            "message.html",
            context! {
                page => page("Check your email"),
                heading => "Check your email",
                body_key => "recovery.sent",
                body => "If an account exists for that address, we have sent instructions.",
            },
        )
        .expect("renders")
        .0;
    assert!(html.contains("data-message-key=\"recovery.sent\""));
    assert_no_external("message.html", &html, &[]);
    insta::assert_snapshot!("message", html);
}

fn error_html(key: &str) -> String {
    renderer()
        .page(
            "error.html",
            context! {
                page => page("Error"),
                status => 400,
                error_key => key,
                heading => Value::from(()),
                detail => Value::from(()),
            },
        )
        .expect("renders")
        .0
}

#[test]
fn error() {
    let html = error_html("redirect_uri_mismatch");
    assert!(html.contains("The redirect URI in this request is not registered for this client."));
    assert!(html.contains("data-error-key=\"redirect_uri_mismatch\""));
    assert_no_external("error.html", &html, &[]);
    insta::assert_snapshot!("error_redirect_uri_mismatch", html);
    assert!(error_html("something_new").contains("Something went wrong."));
}

#[test]
fn values_are_auto_escaped() {
    let f = form(
        "login",
        vec![field("identifier", FieldKind::Email, "Email", Some("<script>alert(1)</script>"))],
    );
    let html = render_form("login.html", "Sign in", &f);
    assert!(!html.contains("<script>"));
    assert!(html.contains("&lt;script&gt;"));
}

#[test]
fn dev_banner_only_in_dev_mode() {
    let f = login_form();
    let prod = render_form("login.html", "Sign in", &f);
    assert!(!prod.contains("dev-mode-banner"));
    let dev_page = page_with("Sign in", true);
    let dev = renderer()
        .page("login.html", context! { page => dev_page, form => Value::from(Serde(&f)) })
        .expect("renders")
        .0;
    assert!(dev.contains("id=\"dev-mode-banner\""));
}

#[test]
fn theme_dir_override_wins_and_falls_back() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(dir.path().join("templates")).expect("mkdir");
    std::fs::write(
        dir.path().join("templates/login.html"),
        "{% extends \"base.html\" %}{% block content %}<p id=\"custom-login\">{{ form.id }}</p>{% endblock %}",
    )
    .expect("write");
    let r = Renderer::new(Some(dir.path())).expect("renderer with override");
    let f = login_form();
    let html = r
        .page("login.html", context! { page => page("Sign in"), form => Value::from(Serde(&f)) })
        .expect("renders")
        .0;
    assert!(html.contains("<p id=\"custom-login\">login</p>"), "{html}");
    // base.html is not overridden: the embedded one is used.
    assert!(decoded(&html).contains("/t/acme/assets/anvil.css"));
    // A template missing from the override directory falls back to the embedded one.
    let err = r
        .page(
            "error.html",
            context! { page => page("Error"), status => 404, error_key => "not_found" },
        )
        .expect("embedded fallback")
        .0;
    assert!(err.contains("Page not found."));
}

#[test]
fn broken_override_fails_at_startup() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(dir.path().join("templates")).expect("mkdir");
    std::fs::write(dir.path().join("templates/login.html"), "{% if %}").expect("write");
    assert!(Renderer::new(Some(dir.path())).is_err());
}
