//! Account attributes page (AUTH-14) on the selected backend (`ANVILID_TEST_DB`): typed no-JS
//! inputs for the user-editable attributes, schema validation with field errors, refusal of
//! non-editable attributes, the settings-flow CSRF binding, the conditional navigation entry and
//! the audit trail. Attributes are defined through `AttributeService` (admin routes: 05-23).

mod support;
mod ui_helpers;

use std::sync::Arc;

use anvil_core::model::{
    AttributeDefinition, AuditAction, AuditActor, AuditEvent, AuditQuery, RequestContext, UserId,
};
use anvil_core::ports::Clock as _;
use anvil_core::service::attribute::AttributeService;
use anvil_core::service::flow::FLOW_LIFETIME;
use anvil_web::adapters::attribute_schema::JsonSchemaCheck;
use axum::body::Body;
use axum::http::{Method, Request, header};
use serde_json::{Map, Value, json};
use support::{TestApp, TestResponse, csrf_from, location};
use ui_helpers::*;

const EMAIL: &str = "alice@example.com";
const PASSWORD: &str = "correct horse battery";
const PAGE: &str = "/ui/account/attributes";

// ---------------------------------------------------------------------------------------------
// Helpers (test code only)
// ---------------------------------------------------------------------------------------------

fn service(app: &TestApp) -> AttributeService {
    AttributeService {
        storage: app.storage_arc(),
        clock: Arc::new(anvil_core::clock::SystemClock),
        check: Arc::new(JsonSchemaCheck::new()),
    }
}

async fn define(app: &TestApp, name: &str, schema: Value, required: bool, editable: bool) {
    service(app)
        .define(
            default_tenant(app).id,
            AuditActor::admin("test-admin"),
            &AttributeDefinition {
                name: name.to_owned(),
                schema,
                required,
                user_editable: editable,
                claim: None,
                position: 0,
            },
            &RequestContext::system(),
        )
        .await
        .expect("definition accepted");
}

/// The attribute set used by most tests: one of each form shape, a non-editable attribute and
/// an editable one the page shows read-only.
async fn define_all(app: &TestApp) {
    define(
        app,
        "department",
        json!({"type": "string", "enum": ["eng", "ops"], "title": "Department"}),
        false,
        true,
    )
    .await;
    define(app, "vip", json!({"type": "boolean"}), false, true).await;
    define(
        app,
        "age",
        json!({"type": "integer", "minimum": 0, "maximum": 150}),
        false,
        true,
    )
    .await;
    define(app, "score", json!({"type": "number"}), false, true).await;
    define(
        app,
        "work_email",
        json!({"type": "string", "format": "email", "maxLength": 100}),
        false,
        true,
    )
    .await;
    define(
        app,
        "homepage",
        json!({"type": "string", "format": "uri"}),
        false,
        true,
    )
    .await;
    define(
        app,
        "birthday",
        json!({"type": "string", "format": "date"}),
        false,
        true,
    )
    .await;
    define(app, "cost_center", json!({"type": "integer"}), false, false).await;
    define(
        app,
        "tags",
        json!({"type": "array", "items": {"type": "string"}}),
        false,
        true,
    )
    .await;
}

async fn signed_in() -> TestApp {
    let app = TestApp::new().await;
    register(&app, "", EMAIL, PASSWORD).await;
    let resp = login(&app, "", EMAIL, PASSWORD).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert!(session_cookie(&app).is_some());
    app
}

async fn user_id(app: &TestApp) -> UserId {
    app.storage()
        .users()
        .get_by_email(default_tenant(app).id, EMAIL)
        .await
        .expect("lookup")
        .expect("user")
        .id
}

async fn stored(app: &TestApp) -> Map<String, Value> {
    let u = user_id(app).await;
    service(app)
        .user_values(default_tenant(app).id, u)
        .await
        .expect("values")
}

async fn set_stored(app: &TestApp, values: Value) {
    let u = user_id(app).await;
    app.storage()
        .attributes()
        .set_user_values(
            default_tenant(app).id,
            u,
            values.as_object().expect("object"),
            time::OffsetDateTime::now_utc(),
        )
        .await
        .expect("stored");
}

async fn updates(app: &TestApp) -> Vec<AuditEvent> {
    app.storage()
        .audit()
        .query(
            default_tenant(app).id,
            &AuditQuery {
                limit: 200,
                ..AuditQuery::default()
            },
        )
        .await
        .expect("audit")
        .items
        .into_iter()
        .filter(|e| e.action == AuditAction::UserAttributesUpdated)
        .collect()
}

/// The form action (path) and CSRF token of the attributes page.
async fn open(app: &TestApp) -> (String, String) {
    let resp = app.get(PAGE).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let html = resp.html();
    let start = html.find("<form id=\"attributes-form\"").expect("form");
    let a = html[start..].find("action=\"").expect("action") + start + 8;
    let b = html[a..].find('"').expect("quote") + a;
    (
        to_path(app, &html[a..b].replace("&amp;", "&")),
        csrf_from(&html),
    )
}

/// The opening tag of the element with `id`.
fn tag(html: &str, id: &str) -> String {
    let marker = format!("id=\"{id}\"");
    let at = html
        .find(&marker)
        .unwrap_or_else(|| panic!("#{id} in {html}"));
    let start = html[..at].rfind('<').expect("tag start");
    let end = html[at..].find('>').expect("tag end") + at;
    html[start..=end].to_owned()
}

fn assert_messages(resp: &TestResponse, status: u16, key: &str) {
    assert_eq!(resp.status, status, "{}", resp.text());
    assert_eq!(message_keys(&resp.html()), vec![key.to_owned()]);
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn without_a_session_both_routes_go_to_sign_in() {
    let app = TestApp::new().await;
    let resp = app.get(PAGE).await;
    assert_eq!(resp.status, 303);
    assert!(
        location(&resp).ends_with("/ui/login?return_to=%2Fui%2Faccount%2Fattributes"),
        "{}",
        location(&resp)
    );
    let resp = app
        .post_form(&format!("{PAGE}?flow=x"), &[("csrf_token", "x")])
        .await;
    assert_eq!(resp.status, 303);
}

#[tokio::test]
async fn nav_entry_only_with_user_editable_attributes() {
    let app = signed_in().await;
    // No attributes: an empty page and no navigation entry.
    let html = app.get(PAGE).await.html();
    assert!(html.contains("id=\"attributes-none\""));
    assert!(!html.contains("account-nav-attributes"));
    assert!(!html.contains("attributes-form"));
    // U-L5: one heading per level; the H1 is not repeated as an H2.
    assert_eq!(html.matches("<h1").count(), 1, "{html}");
    assert_eq!(html.matches("<h2").count(), 0, "{html}");
    assert_eq!(
        html.matches("Additional information</h").count(),
        1,
        "{html}"
    );

    // A non-editable attribute alone does not show the entry either.
    define(
        &app,
        "cost_center",
        json!({"type": "integer"}),
        false,
        false,
    )
    .await;
    let html = app.get(PAGE).await.html();
    assert!(html.contains("id=\"attributes-none\""));
    assert!(!html.contains("account-nav-attributes"));

    define(&app, "nickname_2", json!({"type": "string"}), false, true).await;
    let html = app.get(PAGE).await.html();
    let link = tag(&html, "account-nav-attributes");
    assert!(link.contains("href=\"/ui/account/attributes\""), "{link}");
    assert!(link.contains("aria-current=\"page\""), "{link}");
    // The other seven entries are unchanged.
    for id in [
        "profile", "email", "password", "security", "sessions", "apps", "linked",
    ] {
        assert!(html.contains(&format!("id=\"account-nav-{id}\"")), "{id}");
    }
}

#[tokio::test]
async fn page_renders_typed_inputs() {
    let app = signed_in().await;
    define_all(&app).await;
    set_stored(
        &app,
        json!({"department": "ops", "vip": true, "tags": ["a"], "cost_center": 7}),
    )
    .await;
    let resp = app.get(PAGE).await;
    assert_eq!(resp.status, 200);
    assert_eq!(resp.header("cache-control"), Some("no-store"));
    let html = resp.html();

    let select = tag(&html, "attr-department");
    assert!(select.starts_with("<select") && select.contains("name=\"attr.department\""));
    assert!(html.contains("<label for=\"attr-department\">Department"));
    assert!(html.contains("<option value=\"ops\" selected>ops</option>"));
    assert!(html.contains("<option value=\"eng\">eng</option>"));

    let vip = tag(&html, "attr-vip");
    assert!(
        vip.contains("type=\"checkbox\"") && vip.contains(" checked"),
        "{vip}"
    );
    let age = tag(&html, "attr-age");
    for attr in ["type=\"number\"", "step=\"1\"", "min=\"0\"", "max=\"150\""] {
        assert!(age.contains(attr), "{attr}: {age}");
    }
    assert!(tag(&html, "attr-score").contains("step=\"any\""));
    let mail = tag(&html, "attr-work_email");
    assert!(
        mail.contains("type=\"email\"") && mail.contains("maxlength=\"100\""),
        "{mail}"
    );
    assert!(tag(&html, "attr-homepage").contains("type=\"url\""));
    assert!(tag(&html, "attr-birthday").contains("type=\"date\""));

    // Complex editable attribute: read-only. Non-editable: not shown at all.
    assert!(html.contains("id=\"attr-tags-value\""));
    assert!(html.contains("[&quot;a&quot;]") || html.contains("[\"a\"]"));
    assert!(!html.contains("name=\"attr.tags\""));
    assert!(!html.contains("cost_center"));
    // No script needed.
    assert!(!html.contains("<script"));
}

#[tokio::test]
async fn valid_values_are_saved_and_audited() {
    let app = signed_in().await;
    define_all(&app).await;
    set_stored(&app, json!({"vip": true, "tags": ["a"], "cost_center": 7})).await;
    let (action, csrf) = open(&app).await;
    let resp = app
        .post_form(
            &action,
            &[
                ("csrf_token", &csrf),
                ("attr.department", "eng"),
                ("attr.age", "42"),
                ("attr.score", "2.5"),
                ("attr.work_email", "alice@work.example"),
                ("attr.homepage", "https://alice.example/"),
                ("attr.birthday", "1990-02-03"),
            ],
        )
        .await;
    assert_messages(&resp, 200, "attributes.saved");
    // The unchecked checkbox is false; untouched values (read-only, non-editable) are kept.
    assert_eq!(
        Value::Object(stored(&app).await),
        json!({
            "department": "eng", "vip": false, "age": 42, "score": 2.5,
            "work_email": "alice@work.example", "homepage": "https://alice.example/",
            "birthday": "1990-02-03", "tags": ["a"], "cost_center": 7,
        })
    );
    let events = updates(&app).await;
    assert_eq!(events.len(), 1);
    let u = user_id(&app).await;
    assert_eq!(events[0].actor.id.as_deref(), Some(u.to_string().as_str()));
    assert_eq!(events[0].target.as_deref(), Some(u.to_string().as_str()));
    // The audit record names no values.
    let details = format!("{:?}", events[0].details.as_map());
    assert!(
        !details.contains("alice@work.example") && !details.contains("eng"),
        "{details}"
    );

    // Clearing a text field removes the value; resubmitting the same values changes nothing.
    let resp = app
        .post_form(
            &action,
            &[
                ("csrf_token", &csrf),
                ("attr.homepage", ""),
                ("attr.vip", "true"),
            ],
        )
        .await;
    assert_messages(&resp, 200, "attributes.saved");
    let values = stored(&app).await;
    assert!(!values.contains_key("homepage"));
    assert_eq!(values["vip"], true);
    let resp = app
        .post_form(&action, &[("csrf_token", &csrf), ("attr.vip", "true")])
        .await;
    assert_messages(&resp, 200, "attributes.saved");
    assert_eq!(updates(&app).await.len(), 2);
}

#[tokio::test]
async fn invalid_values_are_refused_with_field_errors() {
    let app = signed_in().await;
    define_all(&app).await;
    for (field, value) in [
        ("attr.department", "sales"),
        ("attr.age", "abc"),
        ("attr.age", "200"),
        ("attr.work_email", "not-an-email"),
        ("attr.birthday", "yesterday"),
    ] {
        let (action, csrf) = open(&app).await;
        // Post/Redirect/Get: 303 with the flash, the GET shows the refusal.
        let posted = app
            .post_form(&action, &[("csrf_token", &csrf), (field, value)])
            .await;
        assert!(support::is_prg(&posted), "{field}: {}", posted.status);
        let resp = app.follow(&posted).await;
        assert_messages(&resp, 400, "attributes.invalid");
        let html = resp.html();
        let id = format!("attr-{}", field.trim_start_matches("attr."));
        assert!(
            html.contains(&format!("id=\"{id}-error\"")),
            "{field}: {html}"
        );
        assert!(tag(&html, &id).contains("aria-invalid=\"true\""), "{field}");
        if field != "attr.department" {
            // What the user typed is shown again.
            assert!(
                tag(&html, &id).contains(&format!("value=\"{value}\"")),
                "{field}"
            );
        }
    }
    // An unknown attribute is refused too.
    let (action, csrf) = open(&app).await;
    let resp = app
        .post_form_follow(&action, &[("csrf_token", &csrf), ("attr.shoe_size", "42")])
        .await;
    assert_messages(&resp, 400, "attributes.invalid");
    assert!(stored(&app).await.is_empty());
    assert!(updates(&app).await.is_empty());
}

#[tokio::test]
async fn non_editable_attributes_are_refused() {
    let app = signed_in().await;
    define_all(&app).await;
    set_stored(&app, json!({"cost_center": 7, "tags": ["a"]})).await;
    for (field, value) in [("attr.cost_center", "8"), ("attr.tags", "[\"b\"]")] {
        let (action, csrf) = open(&app).await;
        let resp = app
            .post_form_follow(
                &action,
                &[
                    ("csrf_token", &csrf),
                    ("attr.department", "eng"),
                    (field, value),
                ],
            )
            .await;
        assert_messages(&resp, 400, "attributes.not_editable");
    }
    // Nothing was saved, not even the valid department.
    assert_eq!(
        Value::Object(stored(&app).await),
        json!({"cost_center": 7, "tags": ["a"]})
    );
    assert!(updates(&app).await.is_empty());
}

#[tokio::test]
async fn submissions_need_the_settings_flow_binding() {
    let app = signed_in().await;
    define_all(&app).await;
    let (action, csrf) = open(&app).await;
    let expect_csrf = |resp: &TestResponse, what: &str| {
        assert_eq!(resp.status, 403, "{what}: {}", resp.text());
        assert_eq!(error_key(&resp.html()).as_deref(), Some("csrf"), "{what}");
    };

    let resp = app.post_form(&action, &[("attr.department", "eng")]).await;
    expect_csrf(&resp, "missing token");
    let resp = app
        .post_form(
            &action,
            &[("csrf_token", "wrong"), ("attr.department", "eng")],
        )
        .await;
    expect_csrf(&resp, "wrong token");
    let resp = app
        .post_form(PAGE, &[("csrf_token", &csrf), ("attr.department", "eng")])
        .await;
    expect_csrf(&resp, "missing flow id");
    // Even a refused (non-editable) submission checks the binding first.
    let resp = app
        .post_form(
            &action,
            &[("csrf_token", "wrong"), ("attr.cost_center", "1")],
        )
        .await;
    expect_csrf(&resp, "non-editable, wrong token");

    // Without the flow cookie (another browser).
    let flow_cookie_name = flow_cookie(&app).expect("flow cookie").0;
    let session = session_cookie(&app).expect("session");
    let body = format!("csrf_token={csrf}&attr.department=eng");
    let req = Request::builder()
        .method(Method::POST)
        .uri(&action)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, format!("{}={}", session.0, session.1))
        .body(Body::from(body.clone()))
        .expect("request");
    let resp = app.send(req).await;
    expect_csrf(&resp, "missing flow cookie");
    assert!(!flow_cookie_name.is_empty());

    // Cross-site POSTs are stopped by the Fetch-Metadata layer.
    let req = Request::builder()
        .method(Method::POST)
        .uri(&action)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("sec-fetch-site", "cross-site")
        .header("sec-fetch-mode", "navigate")
        .body(Body::from(body))
        .expect("request");
    let resp = app.send(req).await;
    assert_eq!(resp.status, 403, "{}", resp.text());

    assert!(stored(&app).await.is_empty());
    assert!(updates(&app).await.is_empty());
}

#[tokio::test]
async fn expired_flow_shows_the_page_again() {
    let app = signed_in().await;
    define_all(&app).await;
    let (action, csrf) = open(&app).await;
    app.clock().advance(std::time::Duration::from_secs(
        FLOW_LIFETIME.whole_seconds() as u64 + 60,
    ));
    let resp = app
        .post_form_follow(
            &action,
            &[("csrf_token", &csrf), ("attr.department", "eng")],
        )
        .await;
    assert_messages(&resp, 400, "account.flow_expired");
    // A fresh flow is bound to the re-rendered form.
    assert_ne!(csrf_from(&resp.html()), csrf);
    assert!(stored(&app).await.is_empty());
}

#[tokio::test]
async fn german_page() {
    let app = signed_in().await;
    define_all(&app).await;
    let req = Request::builder()
        .uri(PAGE)
        .header(header::ACCEPT_LANGUAGE, "de")
        .body(Body::empty())
        .expect("request");
    let html = app.send(req).await.html();
    assert!(html.contains("Weitere Angaben"), "{html}");
    assert!(html.contains("Nicht festgelegt"));
}

// ---------------------------------------------------------------------------------------------
// The navigation entry on every account page (05-33)
// ---------------------------------------------------------------------------------------------

/// Every account page reachable with a plain GET, with the navigation entry it marks current.
/// The email confirmation page (no token: 400) belongs to "email".
const ACCOUNT_PAGES: [(&str, &str, u16); 9] = [
    ("/ui/account/profile", "profile", 200),
    ("/ui/account/email", "email", 200),
    ("/ui/account/email/confirm", "email", 400),
    ("/ui/account/password", "password", 200),
    ("/ui/account/security", "security", 200),
    ("/ui/account/sessions", "sessions", 200),
    ("/ui/account/apps", "apps", 200),
    ("/ui/account/linked", "linked", 200),
    (PAGE, "attributes", 200),
];

/// The number of `aria-current` marks in the account navigation of `html`.
fn current_marks(html: &str) -> usize {
    let start = html.find("id=\"account-nav\"").expect("account nav");
    let end = html[start..].find("</nav>").expect("nav end") + start;
    html[start..end].matches("aria-current=\"page\"").count()
}

/// The page at `path` with the expected status.
async fn page_html(app: &TestApp, path: &str, status: u16) -> String {
    let resp = app.get(path).await;
    assert_eq!(resp.status, status, "{path}: {}", resp.text());
    resp.html()
}

/// RFC 6238 TOTP (HMAC-SHA1, 6 digits, 30 s) of the base32 `key` at the app clock (test code;
/// the server checks it with its own implementation).
fn totp_now(app: &TestApp, key: &str) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut secret = Vec::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in key.bytes().filter(|c| !c.is_ascii_whitespace()) {
        let v = ALPHABET.iter().position(|&a| a == c).expect("base32 char") as u32;
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            secret.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    let step = u64::try_from(app.clock().now().unix_timestamp()).expect("positive") / 30;
    let tag = aws_lc_rs::hmac::sign(
        &aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &secret),
        &step.to_be_bytes(),
    );
    let h = tag.as_ref();
    let off = usize::from(h[h.len() - 1] & 0x0f);
    let bin = (u32::from(h[off]) & 0x7f) << 24
        | u32::from(h[off + 1]) << 16
        | u32::from(h[off + 2]) << 8
        | u32::from(h[off + 3]);
    format!("{:06}", bin % 1_000_000)
}

/// The action (path) of the form with `id` in `html`.
fn form_action_of(app: &TestApp, html: &str, id: &str) -> String {
    let start = html
        .find(&format!("<form id=\"{id}\""))
        .unwrap_or_else(|| panic!("form #{id} in {html}"));
    let a = html[start..].find("action=\"").expect("action") + start + 8;
    let b = html[a..].find('"').expect("quote") + a;
    to_path(app, &html[a..b].replace("&amp;", "&"))
}

/// The TOTP enrolment page and the recovery-codes page shown after confirming it.
async fn enrolment_and_codes_pages(app: &TestApp) -> (String, String) {
    let html = page_html(app, "/ui/account/security", 200).await;
    let csrf = csrf_from(&html);
    let begin = form_action_of(app, &html, "totp-begin");
    let resp = app.post_form(&begin, &[("csrf_token", &csrf)]).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let enrolment = resp.html();
    let code = totp_now(app, &element_text(&enrolment, "totp-secret"));
    let confirm = form_action_of(app, &enrolment, "totp-confirm");
    let resp = app
        .post_form(&confirm, &[("csrf_token", &csrf), ("code", &code)])
        .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let codes = resp.html();
    assert_eq!(
        message_keys(&codes),
        vec!["account.totp_enrolled".to_owned()]
    );
    (enrolment, codes)
}

#[tokio::test]
async fn attributes_nav_on_every_account_page() {
    let app = signed_in().await;
    define(&app, "nickname_2", json!({"type": "string"}), false, true).await;
    for (path, current, status) in ACCOUNT_PAGES {
        let html = page_html(&app, path, status).await;
        let link = tag(&html, "account-nav-attributes");
        assert!(
            link.contains("href=\"/ui/account/attributes\""),
            "{path}: {link}"
        );
        assert_eq!(current_marks(&html), 1, "{path}");
        let own = tag(&html, &format!("account-nav-{current}"));
        assert!(own.contains("aria-current=\"page\""), "{path}: {own}");
    }
    // The TOTP enrolment and recovery-codes pages carry it too.
    let (enrolment, codes) = enrolment_and_codes_pages(&app).await;
    for html in [&enrolment, &codes] {
        assert!(html.contains("id=\"account-nav-attributes\""));
        assert_eq!(current_marks(html), 1);
        assert!(tag(html, "account-nav-security").contains("aria-current=\"page\""));
    }
}

#[tokio::test]
async fn attributes_nav_hidden_without_editable_attributes() {
    let app = signed_in().await;
    // No attributes at all.
    for (path, _, status) in ACCOUNT_PAGES {
        let html = page_html(&app, path, status).await;
        assert!(!html.contains("account-nav-attributes"), "{path}");
        assert!(html.contains("id=\"account-nav-linked\""), "{path}");
    }
    // Only a non-editable attribute: still on none of them.
    define(
        &app,
        "cost_center",
        json!({"type": "integer"}),
        false,
        false,
    )
    .await;
    for (path, _, status) in ACCOUNT_PAGES {
        let html = page_html(&app, path, status).await;
        assert!(!html.contains("account-nav-attributes"), "{path}");
    }
    let (enrolment, codes) = enrolment_and_codes_pages(&app).await;
    assert!(!enrolment.contains("account-nav-attributes"));
    assert!(!codes.contains("account-nav-attributes"));
}
