//! Helpers for the email code / magic link tests (`flow_email_code.rs`, `security_email_code.rs`;
//! test code only). Emails are read from the outbox through the storage port and opened with the
//! KEK (no SMTP or Mailpit needed).

#![allow(dead_code)]

use std::net::SocketAddr;

use anvil_cache::limiter::RateQuota;
use anvil_core::model::{
    AuditAction, AuditQuery, BrowserSession, SecretHash, TenantSettings, UserId, UserUpdate,
};
use anvil_core::ports::Clock as _;
use anvil_web::AppConfig;
use axum::body::Body;
use axum::http::{Method, Request, header};

use crate::support::{TestApp, TestResponse, csrf_from};
use crate::ui_helpers::*;

pub const ALICE: &str = "alice@example.com";
pub const BOB: &str = "bob@example.com";
pub const PASSWORD: &str = "correct horse battery";

/// An installed app with the auth route-class limit raised (many POSTs from one peer; the class
/// limit is tested in `security_ratelimit.rs`), Alice (verified) and Bob (unverified) registered,
/// and email sign-in enabled on the default tenant.
pub async fn setup() -> TestApp {
    setup_with(|_| {}).await
}

pub async fn setup_with(f: impl FnOnce(&mut AppConfig)) -> TestApp {
    let app = TestApp::with(|c| {
        c.rate_limits.auth = RateQuota::per_minute(6000, 1000);
        f(c);
    })
    .await;
    register(&app, "", ALICE, PASSWORD).await;
    register(&app, "", BOB, PASSWORD).await;
    set_verified(&app, ALICE, true).await;
    enable(&app, true).await;
    app
}

/// Turns email sign-in on (both the code and the link) or off for the default tenant (through
/// storage; the admin API's SMTP requirement is tested in 04-11).
pub async fn enable(app: &TestApp, on: bool) {
    set_email_methods(app, on, on).await;
}

/// Sets the default tenant's `email_otp` (the code) and `magic_link` (the link) independently.
pub async fn set_email_methods(app: &TestApp, code: bool, link: bool) {
    update_settings(app, |s| {
        s.email_otp = code;
        s.magic_link = link;
    })
    .await;
}

/// Changes the default tenant's current settings (read back from storage, not the harness copy).
pub async fn update_settings(app: &TestApp, f: impl FnOnce(&mut TenantSettings)) {
    let id = default_tenant(app).id;
    let mut settings = app
        .storage()
        .tenants()
        .get(id)
        .await
        .expect("tenant lookup")
        .expect("tenant")
        .settings;
    f(&mut settings);
    set_settings(app, id, settings).await;
}

pub async fn user_id(app: &TestApp, email: &str) -> UserId {
    app.storage()
        .users()
        .get_by_email(default_tenant(app).id, email)
        .await
        .expect("lookup")
        .expect("user")
        .id
}

pub async fn set_verified(app: &TestApp, email: &str, verified: bool) {
    let t = default_tenant(app).id;
    let id = user_id(app, email).await;
    app.storage()
        .users()
        .update(
            t,
            id,
            &UserUpdate {
                email_verified: Some(verified),
                ..UserUpdate::default()
            },
            app.clock().now(),
        )
        .await
        .expect("update")
        .expect("user");
}

/// The `action` of the form with `id` in a page, as a path.
pub fn action_of(app: &TestApp, html: &str, id: &str) -> String {
    let marker = format!("<form id=\"{id}\"");
    let start = html
        .find(&marker)
        .unwrap_or_else(|| panic!("form #{id} in {html}"));
    form_action(app, &html[start..])
}

/// The value of the hidden input `name` (with an id) in a page.
pub fn hidden(html: &str, name: &str) -> Option<String> {
    hidden_inputs(html)
        .into_iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v)
}

/// The flow id in a form action (`…?flow={id}`).
pub fn flow_in(action: &str) -> String {
    let (_, rest) = action.split_once("flow=").expect("flow parameter");
    rest.split('&').next().unwrap_or_default().to_owned()
}

/// Opens `login_path` (default `/ui/login`) and posts its "Email me a sign-in code" form for
/// `email`. Returns the response (the "check your email" page).
pub async fn request_code_at(app: &TestApp, login_path: &str, email: &str) -> TestResponse {
    let page = app.get(login_path).await;
    assert_eq!(page.status, 200, "{}", page.text());
    let html = page.html();
    let action = action_of(app, &html, "email-code-request");
    let csrf = csrf_from(&html);
    post_form_follow(
        app,
        &action,
        &[("csrf_token", csrf.as_str()), ("email", email)],
    )
    .await
}

pub async fn request_code(app: &TestApp, email: &str) -> TestResponse {
    request_code_at(app, "/ui/login", email).await
}

/// "Send a new code" from a "check your email" page.
pub async fn resend(app: &TestApp, page: &TestResponse) -> TestResponse {
    let html = page.html();
    let action = action_of(app, &html, "email-code-resend");
    let csrf = csrf_from(&html);
    let token = hidden(&html, "factor_token").expect("factor_token");
    post_form_follow(
        app,
        &action,
        &[
            ("csrf_token", csrf.as_str()),
            ("factor_token", token.as_str()),
        ],
    )
    .await
}

/// Posts `code` with the code form of a "check your email" page. A refused code answers
/// Post/Redirect/Get; the redirect is followed like a browser (the page showing the error).
pub async fn submit_code(app: &TestApp, page: &TestResponse, code: &str) -> TestResponse {
    let html = page.html();
    let action = action_of(app, &html, "email-code");
    let csrf = csrf_from(&html);
    let token = hidden(&html, "factor_token").expect("factor_token");
    post_form_follow(
        app,
        &action,
        &[
            ("csrf_token", csrf.as_str()),
            ("factor_token", token.as_str()),
            ("code", code),
        ],
    )
    .await
}

/// A sent sign-in email. `code` and `link` are empty when the email did not carry them; the raw
/// opened payload is in `payload`.
#[derive(Debug, Clone)]
pub struct LoginCode {
    pub to: String,
    pub code: String,
    /// The magic link as a path.
    pub link: String,
    pub expires_minutes: String,
    pub payload: std::collections::BTreeMap<String, String>,
}

/// Every `login_code` email in the outbox since the last call.
pub async fn login_codes(app: &TestApp) -> Vec<LoginCode> {
    take_emails(app)
        .await
        .into_iter()
        .filter(|e| e.template == "login_code")
        .map(|e| LoginCode {
            to: e.to.clone(),
            code: e.payload.get("code").cloned().unwrap_or_default(),
            link: e
                .payload
                .get("link")
                .map(|l| to_path(app, l))
                .unwrap_or_default(),
            expires_minutes: e.payload["expires_minutes"].clone(),
            payload: e.payload.clone(),
        })
        .collect()
}

/// The only `login_code` email since the last call.
pub async fn one_code(app: &TestApp) -> LoginCode {
    let mut all = login_codes(app).await;
    assert_eq!(all.len(), 1, "exactly one login_code email: {all:?}");
    all.remove(0)
}

/// GETs the magic link page and posts its button (with the harness jar, i.e. the same browser).
/// Returns `(link page, POST response)`.
pub async fn open_link(app: &TestApp, link: &str) -> (TestResponse, TestResponse) {
    let page = app.get(link).await;
    assert_eq!(page.status, 200, "{}", page.text());
    let resp = post_link(app, &page, None).await;
    (page, resp)
}

/// Posts the button of a magic link page. `cookie`: `Some` replaces the jar's cookies with this
/// `Cookie` header (another browser).
pub async fn post_link(app: &TestApp, page: &TestResponse, cookie: Option<&str>) -> TestResponse {
    let html = page.html();
    let action = action_of(app, &html, "magic-link");
    let csrf = csrf_from(&html);
    let token = hidden(&html, "token").expect("token");
    let pairs = [("csrf_token", csrf.as_str()), ("token", token.as_str())];
    match cookie {
        None => post_form_follow(app, &action, &pairs).await,
        Some(c) => post_with_cookie(app, &action, &pairs, c).await,
    }
}

/// A same-origin form POST with an explicit `Cookie` header (the jar is not used).
pub async fn post_with_cookie(
    app: &TestApp,
    path: &str,
    pairs: &[(&str, &str)],
    cookie: &str,
) -> TestResponse {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish();
    app.send(
        Request::builder()
            .method(Method::POST)
            .uri(path)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header("sec-fetch-site", "same-origin")
            .header(header::COOKIE, cookie)
            .header(header::CONTENT_LENGTH, body.len())
            .body(Body::from(body))
            .expect("request"),
    )
    .await
}

/// A GET from `peer`.
pub async fn get_from(app: &TestApp, peer: SocketAddr, path: &str) -> TestResponse {
    app.send_from(
        peer,
        Request::get(path).body(Body::empty()).expect("request"),
    )
    .await
}

/// A same-origin form POST from `peer` (a Post/Redirect/Get answer is followed).
pub async fn post_from(
    app: &TestApp,
    peer: SocketAddr,
    path: &str,
    pairs: &[(&str, &str)],
) -> TestResponse {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish();
    let resp = app
        .send_from(
            peer,
            Request::builder()
                .method(Method::POST)
                .uri(path)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header("sec-fetch-site", "same-origin")
                .header(header::CONTENT_LENGTH, body.len())
                .body(Body::from(body))
                .expect("request"),
        )
        .await;
    // A refused submission answers Post/Redirect/Get; follow it like a browser.
    if crate::support::is_prg(&resp) {
        return app.follow(&resp).await;
    }
    resp
}

/// The active session of the jar's session cookie, if any.
pub async fn session(app: &TestApp) -> Option<BrowserSession> {
    let (_, value) = session_cookie(app)?;
    app.storage()
        .sessions()
        .get_active(
            default_tenant(app).id,
            &SecretHash(anvil_jose::encoding::secret_hash(&value)),
            app.clock().now(),
        )
        .await
        .expect("session lookup")
}

pub fn strs(xs: &[&str]) -> Vec<String> {
    xs.iter().map(|x| (*x).to_owned()).collect()
}

/// Audit events of `action` in the default tenant (newest first).
pub async fn audit(app: &TestApp, action: AuditAction) -> Vec<anvil_core::model::AuditEvent> {
    app.storage()
        .audit()
        .query(
            default_tenant(app).id,
            &AuditQuery {
                action: Some(action),
                limit: 100,
                ..AuditQuery::default()
            },
        )
        .await
        .expect("audit query")
        .items
}

/// A page with its per-request values (CSRF token, flow ids, limiter token) replaced, so pages of
/// two requests can be compared byte for byte.
pub fn normalized(html: &str) -> String {
    let mut out = normalize(html);
    for name in ["factor_token"] {
        let marker = format!("name=\"{name}\" value=\"");
        while let Some(i) = out.find(&marker) {
            let start = i + marker.len();
            let end = out[start..].find('"').expect("quoted") + start;
            out.replace_range(i..end, &format!("name=\"{name}\" data-normalized=\"X"));
        }
    }
    out
}
