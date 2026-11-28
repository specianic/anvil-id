//! End-user flow navigation (U-H1, U-H2, U-H6, U-M10) on the selected backend
//! (`ANVILID_TEST_DB`): every detour of a request-bound flow keeps the app's authorization request
//! on its links (read from the flow row, not the query string), a stale `request=` stops on `GET`
//! before any credential form, and request ids or hosts taken from a link or header never reach a
//! link unchecked.
//!
//! The route-class limit for auth POSTs is raised so the many sign-ins from the one test peer are
//! not cut off by it (it is tested in `security_ratelimit.rs`).

mod support;
mod token_support;
mod ui_helpers;
mod upstream_flow;
mod upstream_support;

use anvil_cache::limiter::RateQuota;
use anvil_core::model::{
    AuthRequestId, ClientAuthMethod, ConsentMode, CredentialId, MfaPolicy, NewAuthorizationRequest,
    NewTotp, RegistrationMode, TOTP_SEED_PURPOSE, TenantId, UserId, credential_aad,
};
use anvil_core::ports::Clock as _;
use anvil_core::service::account::new_recovery_codes;
use anvil_jose::otp::TotpSecret;
use axum::body::Body;
use axum::http::{Method, Request, header};
use serde_json::json;
use support::{TestApp, TestResponse, csrf_from, location};
use token_support::{CHALLENGE, REDIRECT, Rp, register_with, web_input};
use ui_helpers::{
    default_tenant, error_key, form_action, hidden_inputs, message_keys, post_form_follow,
    set_settings, submit_form, take_emails, to_path,
};
use upstream_support::MOCK_EMAIL;

const ALICE: &str = "alice@example.com";
const PASSWORD: &str = "correct horse battery";
/// The display name of the test client ("Continue to Shop").
const APP_NAME: &str = "Shop";

// ---------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------

/// An app with a raised auth route-class limit and Alice registered.
async fn app() -> TestApp {
    let app = TestApp::with(|c| c.rate_limits.auth = RateQuota::per_minute(6000, 1000)).await;
    ui_helpers::register(&app, "", ALICE, PASSWORD).await;
    app
}

/// A first-party confidential client named [`APP_NAME`] in `tenant` (no consent screen).
async fn shop(app: &TestApp, tenant: TenantId) -> Rp {
    register_with(
        app,
        tenant,
        web_input(ClientAuthMethod::ClientSecretBasic),
        |c| {
            c.name = APP_NAME.into();
            c.consent_mode = ConsentMode::SkipFirstParty;
        },
    )
    .await
}

/// `GET /authorize` for `rp` without a session: answers 303 to the sign-in page with a fresh
/// request; returns the request id.
async fn authorize(app: &TestApp, rp: &Rp) -> String {
    let q = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("response_type", "code"),
            ("client_id", rp.id()),
            ("redirect_uri", REDIRECT),
            ("scope", "openid"),
            ("state", "st-1"),
            ("nonce", "n-1"),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
        ])
        .finish();
    let resp = app.get(&format!("/authorize?{q}")).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    let path = to_path(app, &location(&resp));
    path.strip_prefix("/ui/login?request=")
        .unwrap_or_else(|| panic!("authorize sends the user to sign in: {path}"))
        .split('&')
        .next()
        .expect("request id")
        .to_owned()
}

/// App, client and a live request for it.
async fn request_bound() -> (TestApp, Rp, String) {
    let app = app().await;
    let rp = shop(&app, default_tenant(&app).id).await;
    let request = authorize(&app, &rp).await;
    (app, rp, request)
}

/// The `href` of the element with `id`, decoded like a browser would (`None` when absent).
fn href(html: &str, id: &str) -> Option<String> {
    let start = html.find(&format!("id=\"{id}\""))?;
    let tag_end = html[start..].find('>')? + start;
    let tag_start = html[..start].rfind('<')?;
    let tag = &html[tag_start..tag_end];
    let marker = "href=\"";
    let at = tag.find(marker)? + marker.len();
    let end = tag[at..].find('"')? + at;
    Some(tag[at..end].replace("&#x2f;", "/").replace("&amp;", "&"))
}

/// Asserts that the link `id` of `html` exists and carries `request=<request>`.
fn assert_keeps(html: &str, id: &str, request: &str) {
    let link = href(html, id).unwrap_or_else(|| panic!("#{id} in {html}"));
    assert!(
        link.contains(&format!("request={request}")),
        "#{id} keeps the request: {link}"
    );
}

/// The issuer of the default tenant.
fn issuer(app: &TestApp) -> String {
    app.issuer(None)
}

/// Stores an authorization request for `client_id` in `tenant` directly (through the port).
async fn stored_request(app: &TestApp, tenant: TenantId, client_id: &str) -> AuthRequestId {
    let id = AuthRequestId(uuid::Uuid::now_v7());
    let now = app.clock().now();
    app.storage()
        .grants()
        .create_authorization_request(
            tenant,
            &NewAuthorizationRequest {
                id,
                client_id: client_id.to_owned(),
                params: token_support::params("openid", Some(CHALLENGE)),
                created_at: now,
                expires_at: now + time::Duration::minutes(15),
            },
        )
        .await
        .expect("request stored");
    id
}

/// A request with custom headers (same-origin form POST when `form` is set).
async fn send_with(
    app: &TestApp,
    method: Method,
    path: &str,
    headers: &[(&str, &str)],
    form: Option<&[(&str, &str)]>,
) -> TestResponse {
    let mut req = Request::builder().method(method).uri(path);
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let body = match form {
        Some(pairs) => {
            let body = url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(pairs)
                .finish();
            req = req
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header("sec-fetch-site", "same-origin");
            Body::from(body)
        }
        None => Body::empty(),
    };
    app.send(req.body(body).expect("request")).await
}

/// Enrols an authenticator app for `email` (sealed like production); returns nothing (the
/// detour tests never finish the second factor).
async fn enrol_totp(app: &TestApp, email: &str) -> UserId {
    let tenant = default_tenant(app).id;
    let user = app
        .storage()
        .users()
        .get_by_email(tenant, email)
        .await
        .expect("lookup")
        .expect("user")
        .id;
    let id = CredentialId::new_v7();
    let seed = TotpSecret::generate();
    let secret_enc = app
        .kek()
        .seal(TOTP_SEED_PURPOSE, &credential_aad(id), seed.as_bytes())
        .expect("seal");
    let (_, hashes) = new_recovery_codes(app.kek()).expect("codes");
    let now = app.clock().now();
    app.storage()
        .users()
        .create_totp(
            tenant,
            user,
            &NewTotp {
                id,
                secret_enc,
                created_at: now,
            },
            &hashes,
            now,
        )
        .await
        .expect("totp");
    user
}

/// The value of the hidden input `name`.
fn hidden(html: &str, name: &str) -> String {
    hidden_inputs(html)
        .into_iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v)
        .unwrap_or_else(|| panic!("hidden {name} in {html}"))
}

/// The flow id of the first form's action.
fn flow_of(app: &TestApp, html: &str) -> String {
    let action = form_action(app, html);
    action
        .split_once("flow=")
        .map(|(_, rest)| rest.split('&').next().unwrap_or_default().to_owned())
        .unwrap_or_else(|| panic!("flow-bound action: {action}"))
}

/// Updates the default tenant's settings.
async fn tenant_settings(app: &TestApp, f: impl FnOnce(&mut anvil_core::model::TenantSettings)) {
    let t = default_tenant(app);
    let mut settings = t.settings.clone();
    f(&mut settings);
    set_settings(app, t.id, settings).await;
}

// ---------------------------------------------------------------------------------------------
// Request ids from links (negative tests)
// ---------------------------------------------------------------------------------------------

/// Unknown, expired, malformed and another tenant's request ids on a `GET` link all answer the
/// same `flow_expired` page (400) with a bare sign-in link and no credential form; the id is never
/// echoed. Nothing tells the variants apart.
#[tokio::test]
async fn unknown_or_foreign_request_on_link_is_ignored() {
    let app = app().await;
    let tenant = default_tenant(&app);
    // A request of this tenant that expired.
    let rp = shop(&app, tenant.id).await;
    let expired = stored_request(&app, tenant.id, rp.id()).await.0.to_string();
    app.clock().advance(std::time::Duration::from_secs(16 * 60));
    // Another tenant's live request (its own client).
    let acme = ui_helpers::create_tenant(&app, "acme").await;
    let acme_rp = shop(&app, acme.id).await;
    let foreign = stored_request(&app, acme.id, acme_rp.id())
        .await
        .0
        .to_string();
    let unknown = uuid::Uuid::now_v7().to_string();

    let mut bodies = Vec::new();
    for page in ["/ui/login", "/ui/registration", "/ui/recovery"] {
        for id in [
            unknown.as_str(),
            expired.as_str(),
            foreign.as_str(),
            "not-a-request",
        ] {
            let resp = app.get(&format!("{page}?request={id}")).await;
            assert_eq!(resp.status, 400, "{page} {id}: {}", resp.text());
            let html = resp.html();
            assert_eq!(error_key(&html).as_deref(), Some("flow_expired"), "{html}");
            assert!(!html.contains("name=\"password\""), "no credential form");
            assert!(!html.contains("name=\"csrf_token\""), "no form at all");
            assert!(!html.contains(id), "the id is never echoed: {html}");
            assert_eq!(
                href(&html, "link-login").as_deref(),
                Some(format!("{}/ui/login", issuer(&app)).as_str()),
                "a bare way to start again"
            );
            assert!(html.contains("This sign-in link has expired"), "{html}");
            bodies.push(resp.text().replace(id, ""));
        }
    }
    assert!(
        bodies.windows(2).all(|w| w[0] == w[1]),
        "every stale variant renders the same page"
    );
    // The foreign request still belongs to its own tenant.
    let own = app
        .get(&format!("/t/acme/ui/login?request={foreign}"))
        .await;
    assert_eq!(own.status, 200, "{}", own.text());
}

/// Hosts never come from the request: a forged `Host`, `X-Forwarded-Host` or `Forwarded` header
/// appears in no link of the request-bound pages (sign-in, failed sign-in, recovery, the
/// continue link of the recovery message).
#[tokio::test]
async fn continue_link_never_takes_host_from_request() {
    let (app, _rp, request) = request_bound().await;
    let forged: &[(&str, &str)] = &[
        ("x-forwarded-host", "evil.test"),
        ("forwarded", "host=evil.test;proto=https"),
        ("x-forwarded-proto", "http"),
    ];
    let page = send_with(
        &app,
        Method::GET,
        &format!("/ui/login?request={request}"),
        forged,
        None,
    )
    .await;
    assert_eq!(page.status, 200, "{}", page.text());
    let html = page.html();
    assert!(!html.contains("evil.test"), "{html}");
    assert_keeps(&html, "link-recovery", &request);
    assert!(
        href(&html, "link-recovery")
            .expect("recovery link")
            .starts_with(&issuer(&app)),
        "{html}"
    );

    // A failed sign-in re-renders from the flow row, still on the issuer's origin.
    let action = form_action(&app, &html);
    let csrf = csrf_from(&html);
    let failed = send_with(
        &app,
        Method::POST,
        &action,
        forged,
        Some(&[
            ("csrf_token", &csrf),
            ("identifier", ALICE),
            ("password", "wrong password!"),
        ]),
    )
    .await;
    // Post/Redirect/Get: the redirect and the page it leads to stay on the issuer's origin.
    assert_eq!(failed.status, 303, "{}", failed.text());
    let to = location(&failed);
    assert!(!to.contains("evil.test"), "{to}");
    assert!(to.starts_with(&issuer(&app)), "{to}");
    let failed = send_with(&app, Method::GET, &to_path(&app, &to), forged, None).await;
    assert_eq!(failed.status, 400, "{}", failed.text());
    let html = failed.html();
    assert!(!html.contains("evil.test"), "{html}");
    assert_keeps(&html, "link-recovery", &request);

    // The recovery message continues to the app on the issuer's origin.
    let rec = send_with(
        &app,
        Method::GET,
        &format!("/ui/recovery?request={request}"),
        forged,
        None,
    )
    .await;
    let html = rec.html();
    let action = form_action(&app, &html);
    let csrf = csrf_from(&html);
    let sent = send_with(
        &app,
        Method::POST,
        &action,
        forged,
        Some(&[("csrf_token", &csrf), ("email", ALICE)]),
    )
    .await;
    assert_eq!(sent.status, 200, "{}", sent.text());
    let html = sent.html();
    assert!(!html.contains("evil.test"), "{html}");
    let cont = href(&html, "link-continue").expect("continue link");
    assert_eq!(cont, format!("{}/ui/login?request={request}", issuer(&app)));
    // The emailed link too.
    let emails = take_emails(&app).await;
    assert!(
        emails
            .iter()
            .all(|e| !e.payload["link"].contains("evil.test")),
        "{emails:?}"
    );
}

// ---------------------------------------------------------------------------------------------
// Detours keep the request
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn failed_sign_in_keeps_the_request_on_create_account_and_forgot_password() {
    let (app, _rp, request) = request_bound().await;
    let resp = submit_form(
        &app,
        &format!("/ui/login?request={request}"),
        &[("identifier", ALICE), ("password", "wrong password!")],
    )
    .await;
    assert_eq!(resp.status, 400, "{}", resp.text());
    let html = resp.html();
    assert_keeps(&html, "link-registration", &request);
    assert_keeps(&html, "link-recovery", &request);

    // Following "Forgot password" keeps it on the way back too.
    let recovery = href(&html, "link-recovery").expect("recovery");
    let page = app.get(&to_path(&app, &recovery)).await;
    assert_eq!(page.status, 200, "{}", page.text());
    assert_keeps(&page.html(), "link-login", &request);
}

#[tokio::test]
async fn ui_locales_travel_with_the_request_on_detour_links() {
    let (app, _rp, request) = request_bound().await;
    let resp = submit_form(
        &app,
        &format!("/ui/login?request={request}&ui_locales=de"),
        &[("identifier", ALICE), ("password", "wrong password!")],
    )
    .await;
    assert_eq!(resp.status, 400, "{}", resp.text());
    let link = href(&resp.html(), "link-recovery").expect("recovery");
    assert!(
        link.ends_with(&format!("/ui/recovery?request={request}&ui_locales=de")),
        "{link}"
    );
}

#[tokio::test]
async fn registration_error_keeps_the_request_on_sign_in() {
    let (app, _rp, request) = request_bound().await;
    let page = app
        .get(&format!("/ui/registration?request={request}"))
        .await;
    assert_eq!(page.status, 200, "{}", page.text());
    assert_keeps(&page.html(), "link-login", &request);
    let resp = submit_form(
        &app,
        &format!("/ui/registration?request={request}"),
        &[("email", "not an email"), ("password", "x")],
    )
    .await;
    assert_eq!(resp.status, 400, "{}", resp.text());
    assert_keeps(&resp.html(), "link-login", &request);
}

#[tokio::test]
async fn recovery_keeps_the_request_and_its_message_continues_to_the_app() {
    let (app, _rp, request) = request_bound().await;
    let resp = submit_form(
        &app,
        &format!("/ui/recovery?request={request}"),
        &[("email", "not an email")],
    )
    .await;
    assert_eq!(resp.status, 400, "{}", resp.text());
    assert_keeps(&resp.html(), "link-login", &request);

    let sent = submit_form(
        &app,
        &format!("/ui/recovery?request={request}"),
        &[("email", ALICE)],
    )
    .await;
    assert_eq!(sent.status, 200, "{}", sent.text());
    let html = sent.html();
    assert!(message_keys(&html).contains(&"recovery.sent".to_owned()));
    assert_eq!(
        href(&html, "link-continue").as_deref(),
        Some(format!("{}/ui/login?request={request}", issuer(&app)).as_str())
    );
    assert!(html.contains(&format!("Continue to {APP_NAME}")), "{html}");
}

#[tokio::test]
async fn second_factor_start_over_keeps_the_request_and_restart_continues_it() {
    let (app, _rp, request) = request_bound().await;
    enrol_totp(&app, ALICE).await;
    let page = submit_form(
        &app,
        &format!("/ui/login?request={request}"),
        &[("identifier", ALICE), ("password", PASSWORD)],
    )
    .await;
    assert_eq!(page.status, 200, "{}", page.text());
    let html = page.html();
    assert!(html.contains("id=\"second-factor\""), "{html}");
    assert_keeps(&html, "link-login", &request);

    // A wrong code re-renders with the request.
    let action = form_action(&app, &html);
    let csrf = csrf_from(&html);
    let token = hidden(&html, "factor_token");
    let wrong = post_form_follow(
        &app,
        &action,
        &[
            ("csrf_token", &csrf),
            ("factor_token", &token),
            ("code", "000000"),
        ],
    )
    .await;
    assert_eq!(wrong.status, 400, "{}", wrong.text());
    assert_keeps(&wrong.html(), "link-login", &request);

    // A post without a valid binding token restarts the sign-in for the same request.
    let restarted = post_form_follow(
        &app,
        &action,
        &[
            ("csrf_token", &csrf),
            ("factor_token", "garbage"),
            ("code", "000000"),
        ],
    )
    .await;
    assert_eq!(restarted.status, 400, "{}", restarted.text());
    let html = restarted.html();
    assert!(message_keys(&html).contains(&"flow.expired".to_owned()));
    assert_keeps(&html, "link-recovery", &request);
    // The restarted flow carries the request: a password-only user would continue it.
    let flow = flow_of(&app, &html);
    let meta = app
        .storage()
        .flows()
        .get(
            default_tenant(&app).id,
            anvil_core::model::FlowId(uuid::Uuid::parse_str(&flow).expect("uuid")),
            app.clock().now(),
        )
        .await
        .expect("flow lookup")
        .expect("flow");
    assert_eq!(
        meta.auth_request_id.map(|r| r.0.to_string()).as_deref(),
        Some(request.as_str())
    );
}

#[tokio::test]
async fn second_factor_get_bounce_keeps_the_request_only_for_the_flow_browser() {
    let (app, _rp, request) = request_bound().await;
    enrol_totp(&app, ALICE).await;
    let page = submit_form(
        &app,
        &format!("/ui/login?request={request}"),
        &[("identifier", ALICE), ("password", PASSWORD)],
    )
    .await;
    let html = page.html();
    let action = form_action(&app, &html);
    // In the browser holding the flow cookie, the GET shows the step again (Post/Redirect/Get)
    // with the request's links.
    let resp = app.get(&action).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert!(resp.html().contains("id=\"second-factor\""));
    assert_keeps(&resp.html(), "link-login", &request);
    // Without the flow cookie: the bare sign-in page.
    app.clear_cookies();
    let resp = app.get(&action).await;
    assert_eq!(resp.status, 303);
    assert_eq!(location(&resp), format!("{}/ui/login", issuer(&app)));
}

#[tokio::test]
async fn mfa_enrolment_start_over_keeps_the_request() {
    let (app, _rp, request) = request_bound().await;
    tenant_settings(&app, |s| s.mfa_policy = MfaPolicy::Required).await;
    let page = submit_form(
        &app,
        &format!("/ui/login?request={request}"),
        &[("identifier", ALICE), ("password", PASSWORD)],
    )
    .await;
    assert_eq!(page.status, 200, "{}", page.text());
    let html = page.html();
    assert!(html.contains("id=\"mfa-enroll\""), "{html}");
    assert_keeps(&html, "link-login", &request);
    // A wrong confirming code keeps it.
    let action = form_action(&app, &html);
    let csrf = csrf_from(&html);
    let token = hidden(&html, "factor_token");
    let wrong = post_form_follow(
        &app,
        &action,
        &[
            ("csrf_token", &csrf),
            ("factor_token", &token),
            ("code", "000000"),
        ],
    )
    .await;
    assert_eq!(wrong.status, 400, "{}", wrong.text());
    assert_keeps(&wrong.html(), "link-login", &request);
}

#[tokio::test]
async fn email_code_use_another_way_keeps_the_request() {
    let (app, _rp, request) = request_bound().await;
    tenant_settings(&app, |s| s.email_otp = true).await;
    let page = app.get(&format!("/ui/login?request={request}")).await;
    assert_eq!(page.status, 200, "{}", page.text());
    let html = page.html();
    let flow = flow_of(&app, &html);
    let csrf = csrf_from(&html);
    let sent = app
        .post_form(
            &format!("/ui/login/email-code?flow={flow}"),
            &[("csrf_token", &csrf), ("email", ALICE)],
        )
        .await;
    assert_eq!(sent.status, 200, "{}", sent.text());
    let html = sent.html();
    assert!(html.contains("id=\"email-code\""), "{html}");
    assert_keeps(&html, "link-login", &request);
    // A wrong code keeps it.
    let token = hidden(&html, "factor_token");
    let wrong = post_form_follow(
        &app,
        &format!("/ui/login/email-code/verify?flow={flow}"),
        &[
            ("csrf_token", &csrf),
            ("factor_token", &token),
            ("code", "00000000"),
        ],
    )
    .await;
    assert_eq!(wrong.status, 400, "{}", wrong.text());
    assert_keeps(&wrong.html(), "link-login", &request);
}

#[tokio::test]
async fn upstream_link_cancel_keeps_the_request() {
    let u = upstream_flow::setup(true).await;
    upstream_flow::tenant_settings(&u.app, |s| s.auto_link = false).await;
    ui_helpers::register(&u.app, "", MOCK_EMAIL, PASSWORD).await;
    upstream_flow::mark_verified(&u.app, MOCK_EMAIL).await;
    let rp = shop(&u.app, default_tenant(&u.app).id).await;
    let request = authorize(&u.app, &rp).await;

    let page = u.app.get(&format!("/ui/login?request={request}")).await;
    assert_eq!(page.status, 200, "{}", page.text());
    let html = page.html();
    let action = upstream_flow::button_action(&u.app, &html, upstream_flow::SLUG);
    let started = upstream_flow::post_start(&u.app, &action, &csrf_from(&html)).await;
    upstream_flow::reply_for(&u, &started, json!({}));
    let resp = upstream_flow::callback(&u, &started).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let html = resp.html();
    assert!(html.contains("id=\"upstream-link\""), "{html}");
    assert_keeps(&html, "link-cancel", &request);

    // A wrong password keeps the confirmation page and the request.
    let action = form_action(&u.app, &html);
    let csrf = csrf_from(&html);
    let wrong = u
        .app
        .post_form_follow(
            &action,
            &[
                ("csrf_token", &csrf),
                ("identifier", MOCK_EMAIL),
                ("password", "wrong password!"),
            ],
        )
        .await;
    assert_eq!(wrong.status, 400, "{}", wrong.text());
    assert_keeps(&wrong.html(), "link-cancel", &request);
}

#[tokio::test]
async fn closed_registration_message_keeps_the_request() {
    let (app, _rp, request) = request_bound().await;
    tenant_settings(&app, |s| s.registration = RegistrationMode::Disabled).await;
    let resp = app
        .get(&format!("/ui/registration?request={request}"))
        .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let html = resp.html();
    assert!(message_keys(&html).contains(&"registration.disabled".to_owned()));
    assert_eq!(
        href(&html, "link-continue").as_deref(),
        Some(format!("{}/ui/login?request={request}", issuer(&app)).as_str())
    );
}

// ---------------------------------------------------------------------------------------------
// Emailed links carry the request (U-H6, U-M10)
// ---------------------------------------------------------------------------------------------

/// Follows a continue link through sign-in to the RP: `GET /ui/login?request=` → password →
/// 303 to the authorization continuation → 303 to the RP with a code.
async fn sign_in_and_reach_the_rp(app: &TestApp, login_url: &str, email: &str, password: &str) {
    let resp = submit_form(
        app,
        &to_path(app, login_url),
        &[("identifier", email), ("password", password)],
    )
    .await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    let cont = to_path(app, &location(&resp));
    assert!(cont.starts_with("/authorize/continue?request="), "{cont}");
    let resp = app.get(&cont).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    let rp = location(&resp);
    assert!(rp.starts_with(&format!("{REDIRECT}?")), "{rp}");
    assert!(rp.contains("code="), "a code for the RP: {rp}");
}

#[tokio::test]
async fn emailed_recovery_link_carries_the_request_and_continues_to_the_app() {
    let (app, _rp, request) = request_bound().await;
    let sent = submit_form(
        &app,
        &format!("/ui/recovery?request={request}"),
        &[("email", ALICE)],
    )
    .await;
    assert_eq!(sent.status, 200, "{}", sent.text());
    let emails = take_emails(&app).await;
    let link = ui_helpers::link_of(&app, &emails, "recovery");
    assert!(link.starts_with("/ui/recovery?token="), "{link}");
    assert!(link.ends_with(&format!("&request={request}")), "{link}");

    // Opened in another browser (no cookies): reset, then continue to the app.
    app.clear_cookies();
    let new_password = "a brand new passphrase";
    let done = submit_form(&app, &link, &[("password", new_password)]).await;
    assert_eq!(done.status, 200, "{}", done.text());
    let html = done.html();
    assert!(message_keys(&html).contains(&"recovery.done".to_owned()));
    let cont = href(&html, "link-continue").expect("continue link");
    assert_eq!(cont, format!("{}/ui/login?request={request}", issuer(&app)));
    assert!(html.contains(&format!("Continue to {APP_NAME}")), "{html}");
    assert!(
        href(&html, "link-login").is_none(),
        "one way forward: {html}"
    );
    sign_in_and_reach_the_rp(&app, &cont, ALICE, new_password).await;
}

#[tokio::test]
async fn registration_check_email_names_the_address_and_verification_continues() {
    let app = TestApp::with(|c| c.rate_limits.auth = RateQuota::per_minute(6000, 1000)).await;
    tenant_settings(&app, |s| s.require_verified_email = true).await;
    let rp = shop(&app, default_tenant(&app).id).await;
    let request = authorize(&app, &rp).await;
    const BOB: &str = "bob@example.com";
    let resp = submit_form(
        &app,
        &format!("/ui/registration?request={request}"),
        &[("email", " Bob@Example.com "), ("password", PASSWORD)],
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let html = resp.html();
    assert!(message_keys(&html).contains(&"registration.check_email".to_owned()));
    assert_eq!(
        ui_helpers::element_text(&html, "message-sent-to"),
        format!("We sent the confirmation link to {BOB}.")
    );
    // While the request is live the page already offers the way back to the app.
    assert_keeps(&html, "link-continue", &request);

    let emails = take_emails(&app).await;
    let link = ui_helpers::link_of(&app, &emails, "verification");
    assert!(link.starts_with("/ui/verification?token="), "{link}");
    assert!(link.ends_with(&format!("&request={request}")), "{link}");
    app.clear_cookies();
    let done = submit_form(&app, &link, &[]).await;
    assert_eq!(done.status, 200, "{}", done.text());
    let html = done.html();
    assert!(message_keys(&html).contains(&"verification.done".to_owned()));
    let cont = href(&html, "link-continue").expect("continue link");
    assert_eq!(cont, format!("{}/ui/login?request={request}", issuer(&app)));
    sign_in_and_reach_the_rp(&app, &cont, BOB, PASSWORD).await;
}

/// An emailed link opened after its request expired (requests live 15 minutes, the recovery
/// token an hour) still resets the password but offers no continuation, never an error.
#[tokio::test]
async fn emailed_link_with_expired_request_works_without_continue() {
    let (app, _rp, request) = request_bound().await;
    let sent = submit_form(
        &app,
        &format!("/ui/recovery?request={request}"),
        &[("email", ALICE)],
    )
    .await;
    assert_eq!(sent.status, 200, "{}", sent.text());
    let emails = take_emails(&app).await;
    let link = ui_helpers::link_of(&app, &emails, "recovery");
    assert!(link.ends_with(&format!("&request={request}")), "{link}");
    app.clear_cookies();
    app.clock().advance(std::time::Duration::from_secs(16 * 60));
    let page = app.get(&link).await;
    assert_eq!(page.status, 200, "{}", page.text());
    let html = page.html();
    assert!(html.contains("name=\"password\""), "the reset form: {html}");
    assert!(!html.contains(&format!("request={request}")), "{html}");
    let done = submit_form(&app, &link, &[("password", "another fresh passphrase")]).await;
    assert_eq!(done.status, 200, "{}", done.text());
    let html = done.html();
    assert!(message_keys(&html).contains(&"recovery.done".to_owned()));
    assert!(href(&html, "link-continue").is_none(), "{html}");
    assert_eq!(
        href(&html, "link-login").as_deref(),
        Some(format!("{}/ui/login", issuer(&app)).as_str())
    );
}

/// An emailed link whose `request=` was swapped for another tenant's, an unknown or a malformed
/// id: the token still works, no continuation, the id is never echoed.
#[tokio::test]
async fn emailed_link_with_foreign_unknown_or_malformed_request_works_without_continue() {
    let (app, _rp, request) = request_bound().await;
    let acme = ui_helpers::create_tenant(&app, "acme").await;
    let acme_rp = shop(&app, acme.id).await;
    let foreign = stored_request(&app, acme.id, acme_rp.id())
        .await
        .0
        .to_string();
    let unknown = uuid::Uuid::now_v7().to_string();
    for id in [foreign.as_str(), unknown.as_str(), "nope"] {
        let sent = submit_form(
            &app,
            &format!("/ui/recovery?request={request}"),
            &[("email", ALICE)],
        )
        .await;
        assert_eq!(sent.status, 200, "{}", sent.text());
        let emails = take_emails(&app).await;
        let link = ui_helpers::link_of(&app, &emails, "recovery");
        let link = format!(
            "{}&request={id}",
            link.strip_suffix(&format!("&request={request}"))
                .expect("link carries the request")
        );
        let page = app.get(&link).await;
        assert_eq!(page.status, 200, "{id}: {}", page.text());
        assert!(!page.html().contains(&format!("request={id}")), "{id}");
        let done = submit_form(&app, &link, &[("password", "another fresh passphrase")]).await;
        assert_eq!(done.status, 200, "{id}: {}", done.text());
        let html = done.html();
        assert!(href(&html, "link-continue").is_none(), "{id}: {html}");
        assert_eq!(
            href(&html, "link-login").as_deref(),
            Some(format!("{}/ui/login", issuer(&app)).as_str()),
            "{id}"
        );
    }
}

/// Admin invitations and upstream just-in-time verification emails are not part of an
/// authorization flow: their links carry no request.
#[tokio::test]
async fn invitation_and_upstream_jit_emails_carry_no_request() {
    // Invitation (admin API): built without any flow.
    let app = TestApp::new().await;
    let tenant = default_tenant(&app);
    let kek = anvil_jose::kek::Kek::generate();
    let invitation = anvil_core::service::user::build_invitation(
        &kek,
        app.clock().now(),
        &tenant,
        &issuer(&app),
        UserId::new_v7(),
        "bob@example.com",
    )
    .expect("invitation");
    let payload =
        anvil_core::model::open_payload(&kek, tenant.id, &invitation.email.payload).expect("open");
    assert!(!payload["link"].contains("request="), "{}", payload["link"]);

    // Upstream just-in-time registration started from an app's sign-in page.
    let u = upstream_flow::setup(false).await;
    let rp = shop(&u.app, default_tenant(&u.app).id).await;
    let request = authorize(&u.app, &rp).await;
    let page = u.app.get(&format!("/ui/login?request={request}")).await;
    let html = page.html();
    let action = upstream_flow::button_action(&u.app, &html, upstream_flow::SLUG);
    let started = upstream_flow::post_start(&u.app, &action, &csrf_from(&html)).await;
    upstream_flow::reply_for(&u, &started, json!({}));
    let resp = upstream_flow::callback(&u, &started).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    let emails = take_emails(&u.app).await;
    let link = ui_helpers::link_of(&u.app, &emails, "verification");
    assert!(link.starts_with("/ui/verification?token="), "{link}");
    assert!(!link.contains("request="), "{link}");
}
