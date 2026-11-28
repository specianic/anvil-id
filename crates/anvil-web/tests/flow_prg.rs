//! Post/Redirect/Get on the end-user flow pages (U-M1, plan 07.1-07) on the selected backend
//! (`ANVILID_TEST_DB`): a failed form POST answers 303 to a `GET` of the same flow page with a
//! sealed one-shot flash cookie; the `GET` shows the step again with the messages and the
//! non-secret values, bound to the CSRF token derived from the flow cookie. Negative tests for
//! every binding property of the derived CSRF token and the flash.

mod support;
mod token_support;
mod ui_helpers;

use anvil_cache::limiter::RateQuota;
use anvil_core::model::{
    AuditAction, AuditQuery, FlowId, MfaPolicy, NewAuthorizationRequest, TenantId, TenantSettings,
};
use anvil_core::ports::Clock as _;
use anvil_core::service::flow::flow_csrf;
use anvil_jose::encoding::b64url_decode;
use axum::body::Body;
use axum::http::{Request, header};
use support::{TestApp, TestResponse, csrf_from, is_prg, location};
use ui_helpers::*;

const EMAIL: &str = "alice@example.com";
const PASSWORD: &str = "correct horse battery";
const WRONG: &str = "Wrong-Password-4711";

async fn app() -> TestApp {
    let app = TestApp::with(|c| c.rate_limits.auth = RateQuota::per_minute(6000, 1000)).await;
    register(&app, "", EMAIL, PASSWORD).await;
    take_emails(&app).await;
    app
}

/// A live authorization request of a registered test client.
async fn live_request(app: &TestApp) -> String {
    let tenant = default_tenant(app).id;
    let rp = token_support::register(
        app,
        tenant,
        token_support::web_input(anvil_core::model::ClientAuthMethod::ClientSecretBasic),
    )
    .await;
    let id = anvil_core::model::AuthRequestId(uuid::Uuid::now_v7());
    let now = app.clock().now();
    app.storage()
        .grants()
        .create_authorization_request(
            tenant,
            &NewAuthorizationRequest {
                id,
                client_id: rp.id().to_owned(),
                params: token_support::params("openid", Some(token_support::CHALLENGE)),
                created_at: now,
                expires_at: now + time::Duration::minutes(15),
            },
        )
        .await
        .expect("request stored");
    id.0.to_string()
}

/// A live authorization request of a first-party client that skips the consent screen.
async fn first_party_request(app: &TestApp) -> String {
    let tenant = default_tenant(app).id;
    let rp = token_support::register_with(
        app,
        tenant,
        token_support::web_input(anvil_core::model::ClientAuthMethod::ClientSecretBasic),
        |c| c.consent_mode = anvil_core::model::ConsentMode::SkipFirstParty,
    )
    .await;
    let id = anvil_core::model::AuthRequestId(uuid::Uuid::now_v7());
    let now = app.clock().now();
    app.storage()
        .grants()
        .create_authorization_request(
            tenant,
            &NewAuthorizationRequest {
                id,
                client_id: rp.id().to_owned(),
                params: token_support::params("openid", Some(token_support::CHALLENGE)),
                created_at: now,
                expires_at: now + time::Duration::minutes(15),
            },
        )
        .await
        .expect("request stored");
    id.0.to_string()
}

/// The flow id of a form action (`…?flow={id}[&…]`).
fn flow_in(action: &str) -> String {
    action
        .split_once("?flow=")
        .map(|(_, rest)| rest.split('&').next().unwrap_or_default().to_owned())
        .expect("flow id in the action")
}

fn flow_id(s: &str) -> FlowId {
    FlowId(uuid::Uuid::parse_str(s).expect("uuid"))
}

/// The raw `Set-Cookie` value of the flash cookie of a response.
fn flash_set_cookie(resp: &TestResponse) -> String {
    resp.headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|c| c.contains("anvil_flash_"))
        .expect("a flash cookie")
        .to_owned()
}

/// The flash cookie value of a response.
fn flash_value(resp: &TestResponse) -> String {
    let raw = flash_set_cookie(resp);
    let pair = raw.split(';').next().expect("name=value");
    pair.split_once('=').expect("=").1.to_owned()
}

/// Opens a flash value with the harness KEK (purpose and AAD of `ui::flash`).
fn open_flash(app: &TestApp, tenant: TenantId, flow: FlowId, value: &str) -> Option<String> {
    let mut aad = Vec::new();
    aad.extend_from_slice(tenant.0.as_bytes());
    aad.extend_from_slice(flow.0.as_bytes());
    let raw = b64url_decode(value).ok()?;
    let plain = app.kek().open("anvilid/ui-flash/v1", &aad, &raw).ok()?;
    Some(String::from_utf8(plain.to_vec()).expect("utf-8 JSON"))
}

/// The `value` of the input with `id`, if it has one.
fn input_value(html: &str, id: &str) -> Option<String> {
    let start = html.find(&format!("id=\"{id}\""))?;
    let tag = &html[start..start + html[start..].find('>')?];
    let i = tag.find("value=\"")? + "value=\"".len();
    let end = tag[i..].find('"')? + i;
    Some(tag[i..end].to_owned())
}

async fn failed_logins(app: &TestApp) -> usize {
    app.storage()
        .audit()
        .query(
            default_tenant(app).id,
            &AuditQuery {
                action: Some(AuditAction::LoginFailed),
                limit: 100,
                ..AuditQuery::default()
            },
        )
        .await
        .expect("audit query")
        .items
        .len()
}

#[tokio::test]
async fn failed_sign_in_redirects_and_the_get_shows_the_error_once() {
    let app = app().await;
    let request = live_request(&app).await;
    let path = format!("/ui/login?request={request}");
    let page = app.get(&path).await;
    assert_eq!(page.status, 200);
    let html = page.html();
    let action = form_action(&app, &html);
    let flow = flow_in(&action);
    let resp = app
        .post_form(
            &action,
            &[
                ("csrf_token", csrf_from(&html).as_str()),
                ("identifier", EMAIL),
                ("password", WRONG),
            ],
        )
        .await;
    assert!(is_prg(&resp), "{} {}", resp.status, resp.text());
    assert_eq!(
        location(&resp),
        format!("{}/ui/login?flow={flow}", app.issuer(None))
    );
    assert_eq!(resp.header("cache-control"), Some("no-store"));
    assert!(resp.body.is_empty() || !resp.text().contains(WRONG));
    assert_eq!(failed_logins(&app).await, 1);

    // The GET: the error, the identifier, an empty password, the request's links, no-store.
    let shown = app.follow(&resp).await;
    assert_eq!(shown.status, 400, "{}", shown.text());
    let html = shown.html();
    assert_eq!(
        message_keys(&html),
        vec!["login.invalid_credentials".to_owned()]
    );
    assert_eq!(input_value(&html, "identifier").as_deref(), Some(EMAIL));
    assert_eq!(input_value(&html, "password"), None);
    assert!(!html.contains(WRONG));
    assert!(html.contains(&format!("request={request}")), "{html}");
    assert_eq!(shown.header("cache-control"), Some("no-store"));
    assert_eq!(form_action(&app, &html), action, "the same flow");
    // The flash is cleared by the GET that read it.
    let cleared = flash_set_cookie(&shown);
    assert!(cleared.contains("Max-Age=0"), "{cleared}");

    // Reload: the same step without the message, nothing posted again.
    let reload = app.get(&location(&resp)).await;
    assert_eq!(reload.status, 200, "{}", reload.text());
    assert!(message_keys(&reload.html()).is_empty());
    assert_eq!(failed_logins(&app).await, 1, "a reload never re-posts");

    // The re-shown form is bound: the right password signs in and continues the request.
    let resp = app
        .post_form(
            &action,
            &[
                ("csrf_token", csrf_from(&html).as_str()),
                ("identifier", EMAIL),
                ("password", PASSWORD),
            ],
        )
        .await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert_eq!(
        location(&resp),
        format!("{}/authorize/continue?request={request}", app.issuer(None))
    );
}

#[tokio::test]
async fn flash_cookie_is_strict_http_only_and_short_lived() {
    let app = app().await;
    let resp = submit_form_raw(
        &app,
        "/ui/login",
        &[("identifier", EMAIL), ("password", WRONG)],
    )
    .await;
    assert!(is_prg(&resp));
    let raw = flash_set_cookie(&resp);
    assert!(raw.contains("HttpOnly"), "{raw}");
    assert!(raw.contains("SameSite=Strict"), "{raw}");
    assert!(raw.contains("Path=/"), "{raw}");
    let max_age: i64 = raw
        .split(';')
        .map(str::trim)
        .find_map(|a| a.strip_prefix("Max-Age="))
        .expect("Max-Age")
        .parse()
        .expect("seconds");
    assert!(max_age > 0 && max_age <= 120, "{raw}");
    assert!(!raw.contains("Domain"), "{raw}");
}

#[tokio::test]
async fn flash_never_contains_password_or_code() {
    let app = app().await;
    let tenant = default_tenant(&app).id;
    let page = app.get("/ui/login").await;
    let html = page.html();
    let action = form_action(&app, &html);
    let csrf = csrf_from(&html);
    let resp = app
        .post_form(
            &action,
            &[
                ("csrf_token", csrf.as_str()),
                ("identifier", EMAIL),
                ("password", WRONG),
            ],
        )
        .await;
    let value = flash_value(&resp);
    for secret in [WRONG, EMAIL, csrf.as_str()] {
        assert!(!value.contains(secret), "sealed: {secret}");
    }
    let plain = open_flash(&app, tenant, flow_id(&flow_in(&action)), &value).expect("opens");
    assert!(!plain.contains(WRONG), "{plain}");
    assert!(!plain.contains(&csrf), "{plain}");
    assert!(plain.contains(EMAIL), "the identifier comes back: {plain}");

    // An enrolment code and the factor token never go into the flash either.
    let t = default_tenant(&app);
    set_settings(
        &app,
        t.id,
        TenantSettings {
            mfa_policy: MfaPolicy::Required,
            ..t.settings.clone()
        },
    )
    .await;
    app.clear_cookies();
    let page = submit_form(
        &app,
        "/ui/login",
        &[("identifier", EMAIL), ("password", PASSWORD)],
    )
    .await;
    let html = page.html();
    assert!(html.contains("id=\"mfa-enroll\""), "{html}");
    let action = form_action(&app, &html);
    let factor = hidden_inputs(&html)
        .into_iter()
        .find(|(n, _)| n == "factor_token")
        .map(|(_, v)| v)
        .expect("factor token");
    let resp = app
        .post_form(
            &action,
            &[
                ("csrf_token", csrf_from(&html).as_str()),
                ("factor_token", factor.as_str()),
                ("code", "000000"),
            ],
        )
        .await;
    assert!(is_prg(&resp), "{} {}", resp.status, resp.text());
    let plain = open_flash(
        &app,
        tenant,
        flow_id(&flow_in(&action)),
        &flash_value(&resp),
    )
    .expect("opens");
    assert!(!plain.contains("000000"), "{plain}");
    assert!(!plain.contains(&factor), "{plain}");
    assert!(plain.contains("mfa_enroll.code_invalid"), "{plain}");

    // The GET shows the same enrolment (same key) with a working factor token.
    let shown = app.follow(&resp).await;
    assert_eq!(shown.status, 400, "{}", shown.text());
    let again = shown.html();
    assert_eq!(
        element_text(&again, "totp-secret"),
        element_text(&html, "totp-secret")
    );
    assert!(
        hidden_inputs(&again)
            .iter()
            .any(|(n, v)| n == "factor_token" && !v.is_empty())
    );
}

#[tokio::test]
async fn flash_from_other_flow_or_tenant_is_ignored() {
    let app = app().await;
    let resp = submit_form_raw(
        &app,
        "/ui/login",
        &[("identifier", EMAIL), ("password", WRONG)],
    )
    .await;
    assert!(is_prg(&resp));
    let raw = flash_set_cookie(&resp);
    let (name, value) = raw
        .split(';')
        .next()
        .and_then(|p| p.split_once('='))
        .map(|(n, v)| (n.to_owned(), v.to_owned()))
        .expect("name=value");

    // A second flow in the same browser, with the first flow's flash: no message shown.
    app.clear_cookies();
    let page = app.get("/ui/login").await;
    let html = page.html();
    let action = form_action(&app, &html);
    let (flow_cookie_name, flow_cookie_value) = flow_cookie(&app).expect("flow cookie");
    let cookie = format!("{flow_cookie_name}={flow_cookie_value}; {name}={value}");
    let get = |path: String, cookie: String| {
        let app = &app;
        async move {
            app.send(
                Request::get(path)
                    .header(header::COOKIE, cookie)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
        }
    };
    let shown = get(action.clone(), cookie).await;
    assert_eq!(shown.status, 200, "{}", shown.text());
    assert!(message_keys(&shown.html()).is_empty(), "{}", shown.html());
    assert!(
        flash_set_cookie(&shown).contains("Max-Age=0"),
        "cleared anyway"
    );

    // A tampered flash for the right flow: ignored.
    let mut tampered = value.clone();
    let last = if value.ends_with('A') { "B" } else { "A" };
    tampered.replace_range(value.len() - 1.., last);
    let shown = get(
        action.clone(),
        format!("{flow_cookie_name}={flow_cookie_value}; {name}={tampered}"),
    )
    .await;
    assert_eq!(shown.status, 200);
    assert!(message_keys(&shown.html()).is_empty());

    // Another tenant's page with this tenant's flash under its own cookie name: ignored.
    let other = create_tenant(&app, "other").await;
    app.clear_cookies();
    let page = app.get("/t/other/ui/login").await;
    assert_eq!(page.status, 200, "{}", page.text());
    let action = form_action(&app, &page.html());
    let (other_flow_name, other_flow_value) = flow_cookie(&app).expect("flow cookie");
    let other_flash_name = other_flow_name.replacen("anvil_flow_", "anvil_flash_", 1);
    assert_ne!(other_flash_name, name, "per-tenant cookie names");
    let _ = other;
    let shown = get(
        action,
        format!("{other_flow_name}={other_flow_value}; {other_flash_name}={value}"),
    )
    .await;
    assert_eq!(shown.status, 200, "{}", shown.text());
    assert!(message_keys(&shown.html()).is_empty());
}

#[tokio::test]
async fn derived_csrf_rejected_for_other_cookie() {
    let app = app().await;
    let tenant = default_tenant(&app).id;
    // Browser A.
    let page = app.get("/ui/login").await;
    let html = page.html();
    let action = form_action(&app, &html);
    let csrf_a = csrf_from(&html);
    let flow_a = flow_id(&flow_in(&action));
    let (cookie_name, cookie_a) = flow_cookie(&app).expect("flow cookie A");
    assert_eq!(
        csrf_a,
        flow_csrf(app.kek(), tenant, flow_a, &cookie_a),
        "the form's token is the derived one"
    );
    // Browser B.
    app.clear_cookies();
    app.get("/ui/login").await;
    let (_, cookie_b) = flow_cookie(&app).expect("flow cookie B");
    assert_ne!(cookie_a, cookie_b);

    // B posts to A's flow with A's token, or with a token derived for B's cookie, another flow or
    // another tenant: refused (403), nothing checked.
    for csrf in [
        csrf_a.clone(),
        flow_csrf(app.kek(), tenant, flow_a, &cookie_b),
        flow_csrf(app.kek(), tenant, FlowId::new_v7(), &cookie_a),
        flow_csrf(app.kek(), TenantId::new_v7(), flow_a, &cookie_a),
    ] {
        let resp = app
            .post_form(
                &action,
                &[
                    ("csrf_token", csrf.as_str()),
                    ("identifier", EMAIL),
                    ("password", PASSWORD),
                ],
            )
            .await;
        assert_eq!(resp.status, 403, "{}", resp.text());
        assert!(!is_prg(&resp));
    }
    // A token derived for another flow or tenant does not work with A's own cookie either.
    app.clear_cookies();
    for csrf in [
        flow_csrf(app.kek(), tenant, FlowId::new_v7(), &cookie_a),
        flow_csrf(app.kek(), TenantId::new_v7(), flow_a, &cookie_a),
    ] {
        let resp = app
            .send(
                Request::post(action.clone())
                    .header(header::COOKIE, format!("{cookie_name}={cookie_a}"))
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .header("sec-fetch-site", "same-origin")
                    .body(Body::from(format!(
                        "csrf_token={csrf}&identifier=alice%40example.com&password=x"
                    )))
                    .expect("request"),
            )
            .await;
        assert_eq!(resp.status, 403, "{}", resp.text());
    }
    assert_eq!(failed_logins(&app).await, 0, "no password was looked at");

    // B's GET of A's flow shows no form state of A: a fresh flow with its own token.
    app.clear_cookies();
    let resp = app
        .send(
            Request::get(action.clone())
                .header(header::COOKIE, format!("{cookie_name}={cookie_b}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let html = resp.html();
    assert_ne!(form_action(&app, &html), action);
    assert_ne!(csrf_from(&html), csrf_a);
}

#[tokio::test]
async fn prg_get_without_flow_cookie_shows_no_form_state() {
    let app = app().await;
    let resp = submit_form_raw(
        &app,
        "/ui/login",
        &[("identifier", EMAIL), ("password", WRONG)],
    )
    .await;
    assert!(is_prg(&resp));
    let to = to_path(&app, &location(&resp));
    // Without any cookie (another browser, or the cookies are gone): a fresh sign-in form, no
    // message, no identifier, another flow.
    app.clear_cookies();
    let shown = app.get(&to).await;
    assert_eq!(shown.status, 200, "{}", shown.text());
    let html = shown.html();
    assert!(message_keys(&html).is_empty(), "{html}");
    assert_eq!(input_value(&html, "identifier"), None);
    assert_ne!(
        flow_in(&form_action(&app, &html)),
        flow_in(&to),
        "a new flow"
    );

    // The second-factor page without the flow cookie: back to the sign-in page, no form.
    app.clear_cookies();
    let second = to.replace("/ui/login?", "/ui/login/second-factor?");
    let resp = app.get(&second).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert_eq!(location(&resp), format!("{}/ui/login", app.issuer(None)));
    // The email-code page likewise (email sign-in on).
    let t = default_tenant(&app);
    set_settings(
        &app,
        t.id,
        TenantSettings {
            email_otp: true,
            ..t.settings.clone()
        },
    )
    .await;
    let resp = app
        .get(&to.replace("/ui/login?", "/ui/login/email-code?"))
        .await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert_eq!(location(&resp), format!("{}/ui/login", app.issuer(None)));
}

#[tokio::test]
async fn unknown_and_known_identifiers_get_the_same_redirect_and_page() {
    let app = app().await;
    let mut seen = Vec::new();
    for identifier in [EMAIL, "nobody@example.com"] {
        app.clear_cookies();
        let resp = submit_form_raw(
            &app,
            "/ui/login",
            &[("identifier", identifier), ("password", WRONG)],
        )
        .await;
        assert!(is_prg(&resp));
        let flow = flow_in(&location(&resp));
        let mut headers: Vec<(String, String)> = resp
            .headers
            .iter()
            .filter(|(k, _)| *k != header::SET_COOKIE && *k != "x-request-id")
            .map(|(k, v)| {
                (
                    k.to_string(),
                    v.to_str().unwrap_or_default().replace(&flow, "FLOW"),
                )
            })
            .collect();
        headers.sort();
        let shown = app.follow(&resp).await;
        let body = normalize(&shown.html()).replace(identifier, "IDENT");
        seen.push((resp.status, headers, shown.status, body));
    }
    assert_eq!(seen[0], seen[1]);
}

#[tokio::test]
async fn registration_errors_redirect_and_keep_email_and_name_only() {
    let app = TestApp::new().await;
    let page = app.get("/ui/registration").await;
    let html = page.html();
    let action = form_action(&app, &html);
    let resp = app
        .post_form(
            &action,
            &[
                ("csrf_token", csrf_from(&html).as_str()),
                ("email", "new@example.com"),
                ("name", "Ada Lovelace"),
                ("password", "short"),
            ],
        )
        .await;
    assert!(is_prg(&resp), "{} {}", resp.status, resp.text());
    assert_eq!(
        location(&resp),
        format!(
            "{}/ui/registration?flow={}",
            app.issuer(None),
            flow_in(&action)
        )
    );
    let shown = app.follow(&resp).await;
    assert_eq!(shown.status, 400, "{}", shown.text());
    let html = shown.html();
    assert!(!message_keys(&html).is_empty());
    assert_eq!(
        input_value(&html, "email").as_deref(),
        Some("new@example.com")
    );
    assert_eq!(input_value(&html, "name").as_deref(), Some("Ada Lovelace"));
    assert_eq!(input_value(&html, "password"), None);
    // Completing the re-shown form registers.
    let resp = app
        .post_form(
            &action,
            &[
                ("csrf_token", csrf_from(&html).as_str()),
                ("email", "new@example.com"),
                ("password", PASSWORD),
            ],
        )
        .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
}

#[tokio::test]
async fn recovery_request_and_reset_errors_redirect() {
    let app = app().await;
    // The request form: an invalid address.
    let resp = submit_form_raw(&app, "/ui/recovery", &[("email", "not-an-address")]).await;
    assert!(is_prg(&resp), "{} {}", resp.status, resp.text());
    assert!(location(&resp).contains("/ui/recovery?flow="));
    let shown = app.follow(&resp).await;
    assert_eq!(shown.status, 400, "{}", shown.text());
    assert_eq!(
        input_value(&shown.html(), "email").as_deref(),
        Some("not-an-address")
    );

    // The reset form: a too-short password keeps the emailed token usable.
    app.clear_cookies();
    let resp = submit_form(&app, "/ui/recovery", &[("email", EMAIL)]).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let link = link_of(&app, &take_emails(&app).await, "recovery");
    let resp = submit_form_raw(&app, &link, &[("password", "short")]).await;
    assert!(is_prg(&resp), "{} {}", resp.status, resp.text());
    assert!(location(&resp).contains("/ui/recovery?flow="));
    let token = link.split("token=").nth(1).expect("token").to_owned();
    let value = flash_value(&resp);
    assert!(!value.contains(&token), "the token is sealed");
    let shown = app.follow(&resp).await;
    assert_eq!(shown.status, 400, "{}", shown.text());
    let html = shown.html();
    assert!(html.contains("id=\"recovery-reset-submit\""), "{html}");
    let action = form_action(&app, &html);
    let hidden = hidden_inputs(&html);
    let mut pairs: Vec<(&str, &str)> = vec![("password", "a brand new passphrase")];
    let csrf = csrf_from(&html);
    pairs.push(("csrf_token", &csrf));
    for (k, v) in &hidden {
        pairs.push((k, v));
    }
    let resp = app.post_form(&action, &pairs).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(message_keys(&resp.html()), vec!["recovery.done".to_owned()]);
}

#[tokio::test]
async fn verification_error_redirects() {
    let app = TestApp::new().await;
    let page = app.get("/ui/verification").await;
    let html = page.html();
    let action = form_action(&app, &html);
    let resp = app
        .post_form(
            &action,
            &[("csrf_token", csrf_from(&html).as_str()), ("token", "")],
        )
        .await;
    assert!(is_prg(&resp), "{} {}", resp.status, resp.text());
    assert!(location(&resp).contains("/ui/verification?flow="));
    let shown = app.follow(&resp).await;
    assert_eq!(shown.status, 400, "{}", shown.text());
    assert_eq!(
        message_keys(&shown.html()),
        vec!["verification.invalid_token".to_owned()]
    );
}

#[tokio::test]
async fn a_lock_stays_a_direct_answer() {
    let app = app().await;
    for _ in 0..5 {
        let resp = submit_form_raw(
            &app,
            "/ui/login",
            &[("identifier", EMAIL), ("password", WRONG)],
        )
        .await;
        assert!(is_prg(&resp));
    }
    let resp = submit_form_raw(
        &app,
        "/ui/login",
        &[("identifier", EMAIL), ("password", WRONG)],
    )
    .await;
    assert_eq!(resp.status, 429, "{}", resp.text());
    assert!(resp.header("retry-after").is_some());
    assert!(!is_prg(&resp));
}

#[tokio::test]
async fn get_with_consumed_reset_token_consumes_nothing_and_offers_new_link() {
    let app = app().await;
    let resp = submit_form(&app, "/ui/recovery", &[("email", EMAIL)]).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let link = link_of(&app, &take_emails(&app).await, "recovery");

    // Opening the link twice consumes nothing: both show the reset form.
    for _ in 0..2 {
        app.clear_cookies();
        let page = app.get(&link).await;
        assert_eq!(page.status, 200, "{}", page.text());
        assert!(page.html().contains("id=\"recovery-reset-submit\""));
    }
    let resp = submit_form(&app, &link, &[("password", "a brand new passphrase")]).await;
    assert_eq!(message_keys(&resp.html()), vec!["recovery.done".to_owned()]);

    // The used link: "expired" on GET, the request form to ask for a new one, no password field.
    app.clear_cookies();
    let page = app.get(&link).await;
    assert_eq!(page.status, 400, "{}", page.text());
    let html = page.html();
    assert_eq!(message_keys(&html), vec!["links.expired".to_owned()]);
    assert!(html.contains("This link has expired or was already used."));
    assert!(html.contains("id=\"recovery\""), "the request form: {html}");
    assert!(html.contains("Send a new link"), "{html}");
    assert!(!html.contains("type=\"password\""), "{html}");
    assert_eq!(page.header("cache-control"), Some("no-store"));
    // The form there sends a new link.
    let resp = app
        .post_form(
            &form_action(&app, &html),
            &[("csrf_token", csrf_from(&html).as_str()), ("email", EMAIL)],
        )
        .await;
    assert_eq!(message_keys(&resp.html()), vec!["recovery.sent".to_owned()]);
    assert_eq!(
        take_emails(&app)
            .await
            .iter()
            .filter(|e| e.template == "recovery")
            .count(),
        1
    );

    // An unknown token and an expired one look the same.
    app.clear_cookies();
    let unknown = app.get("/ui/recovery?token=never-issued").await;
    assert_eq!(unknown.status, 400);
    assert_eq!(
        message_keys(&unknown.html()),
        vec!["links.expired".to_owned()]
    );
    let resp = submit_form(&app, "/ui/recovery", &[("email", EMAIL)]).await;
    assert_eq!(resp.status, 200);
    let fresh = link_of(&app, &take_emails(&app).await, "recovery");
    app.clock()
        .advance(std::time::Duration::from_secs(2 * 3600));
    app.clear_cookies();
    let expired = app.get(&fresh).await;
    assert_eq!(expired.status, 400);
    assert_eq!(
        message_keys(&expired.html()),
        vec!["links.expired".to_owned()]
    );
}

#[tokio::test]
async fn verification_link_is_checked_on_get_and_never_consumed_by_it() {
    let app = TestApp::new().await;
    register(&app, "", EMAIL, PASSWORD).await;
    let link = link_of(&app, &take_emails(&app).await, "verification");

    // A usable link: the confirmation button, as often as it is opened.
    for _ in 0..2 {
        app.clear_cookies();
        let page = app.get(&link).await;
        assert_eq!(page.status, 200, "{}", page.text());
        assert!(page.html().contains("id=\"verification-submit\""));
    }
    let resp = submit_form(&app, &link, &[]).await;
    assert_eq!(
        message_keys(&resp.html()),
        vec!["verification.done".to_owned()]
    );

    // Used: "expired", no button, the way to sign in.
    app.clear_cookies();
    let page = app.get(&link).await;
    assert_eq!(page.status, 400, "{}", page.text());
    let html = page.html();
    assert_eq!(message_keys(&html), vec!["links.expired".to_owned()]);
    assert!(!html.contains("id=\"verification-submit\""), "{html}");
    assert!(!html.contains("<form"), "{html}");
    assert!(html.contains("id=\"link-login\""), "{html}");
    assert_eq!(page.header("cache-control"), Some("no-store"));

    // Expired (24 h) looks the same.
    register(&app, "", "bob@example.com", PASSWORD).await;
    let bob = link_of(&app, &take_emails(&app).await, "verification");
    app.clock()
        .advance(std::time::Duration::from_secs(25 * 3600));
    app.clear_cookies();
    let page = app.get(&bob).await;
    assert_eq!(page.status, 400);
    assert_eq!(message_keys(&page.html()), vec!["links.expired".to_owned()]);
}

// ---------------------------------------------------------------------------------------------
// Recovery codes of a required in-flow enrolment (U-H7, plan 07.1-13)
// ---------------------------------------------------------------------------------------------

/// RFC 6238 code (SHA-1, 6 digits, 30 s) of `seed` at `unix` (test implementation).
fn totp_code(seed: &[u8], unix: i64) -> String {
    use aws_lc_rs::hmac;
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, seed);
    let counter = u64::try_from(unix / 30).expect("positive time");
    let tag = hmac::sign(&key, &counter.to_be_bytes());
    let h = tag.as_ref();
    let off = usize::from(h[h.len() - 1] & 0x0f);
    let bin = (u32::from(h[off]) & 0x7f) << 24
        | u32::from(h[off + 1]) << 16
        | u32::from(h[off + 2]) << 8
        | u32::from(h[off + 3]);
    format!("{:06}", bin % 1_000_000)
}

/// RFC 4648 base32 (no padding, spaces ignored) decoder for the key shown on the page.
fn base32_decode(s: &str) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut bits = 0u32;
    let mut n = 0;
    let mut out = Vec::new();
    for c in s.bytes().filter(|c| !c.is_ascii_whitespace() && *c != b'=') {
        let v = ALPHABET
            .iter()
            .position(|a| *a == c.to_ascii_uppercase())
            .expect("base32 character");
        bits = (bits << 5) | u32::try_from(v).expect("small");
        n += 5;
        if n >= 8 {
            n -= 8;
            out.push(u8::try_from((bits >> n) & 0xff).expect("byte"));
        }
    }
    out
}

/// The `<li><code>` recovery codes of a page.
fn shown_codes(html: &str) -> Vec<String> {
    html.split("<li><code>")
        .skip(1)
        .filter_map(|rest| rest.split_once("</code>").map(|(c, _)| c.to_owned()))
        .collect()
}

/// Requires MFA, signs in at `path` (the enrolment page), confirms the authenticator app with
/// the right code and returns the 303 answer of that POST and the enrolment page it came from.
async fn enrol_in_flow(app: &TestApp, path: &str) -> (TestResponse, TestResponse) {
    let t = default_tenant(app);
    set_settings(
        app,
        t.id,
        TenantSettings {
            mfa_policy: MfaPolicy::Required,
            ..t.settings.clone()
        },
    )
    .await;
    let page = submit_form(app, path, &[("identifier", EMAIL), ("password", PASSWORD)]).await;
    assert_eq!(page.status, 200, "{}", page.text());
    let html = page.html();
    assert!(html.contains("id=\"mfa-enroll\""), "{html}");
    let seed = base32_decode(&element_text(&html, "totp-secret"));
    let code = totp_code(&seed, app.clock().now().unix_timestamp());
    let factor = hidden_inputs(&html)
        .into_iter()
        .find(|(n, _)| n == "factor_token")
        .map(|(_, v)| v)
        .expect("factor token");
    let resp = app
        .post_form(
            &form_action(app, &html),
            &[
                ("csrf_token", csrf_from(&html).as_str()),
                ("factor_token", factor.as_str()),
                ("code", code.as_str()),
            ],
        )
        .await;
    (resp, page)
}

/// The recovery-codes page path of the 303 answering the confirming code.
fn codes_path(app: &TestApp, resp: &TestResponse) -> String {
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert_eq!(resp.header("cache-control"), Some("no-store"));
    let path = to_path(app, &location(resp));
    assert!(path.starts_with("/ui/login/recovery-codes?flow="), "{path}");
    path
}

/// `GET path` with exactly this `Cookie` header (no jar cookies).
async fn get_with_cookie(app: &TestApp, path: &str, cookie: &str) -> TestResponse {
    let mut req = Request::get(path).body(Body::empty()).expect("request");
    req.headers_mut()
        .insert(header::COOKIE, cookie.parse().expect("cookie header"));
    app.send(req).await
}

fn cookie_header(cookies: &[(String, String)]) -> String {
    cookies
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("; ")
}

#[tokio::test]
async fn recovery_codes_page_is_no_store() {
    let app = app().await;
    let (resp, enrol_page) = enrol_in_flow(&app, "/ui/login").await;
    // The enrolment page: an otpauth link next to the QR code, escaped, never cached.
    let enrol_html = enrol_page.html();
    let otpauth = enrol_html
        .split("id=\"link-otpauth\" href=\"")
        .nth(1)
        .and_then(|r| r.split('"').next())
        .expect("otpauth link");
    assert!(otpauth.starts_with("otpauth://totp/"), "{otpauth}");
    assert!(
        !otpauth.contains('&') || otpauth.contains("&amp;"),
        "{otpauth}"
    );
    assert!(!otpauth.contains('<') && !otpauth.contains('>'));
    assert_eq!(enrol_page.header("cache-control"), Some("no-store"));

    // The POST signed in and redirected; it did not show the codes itself.
    assert!(session_cookie(&app).is_some(), "signed in");
    assert!(shown_codes(&resp.text()).is_empty());
    let path = codes_path(&app, &resp);
    let page = app.get(&path).await;
    assert_eq!(page.status, 200, "{}", page.text());
    assert_eq!(page.header("cache-control"), Some("no-store"));
    let codes = shown_codes(&page.html());
    assert_eq!(codes.len(), 10, "{}", page.text());
    assert!(page.html().contains("id=\"recovery-codes-confirm\""));
    // A reload shows the same codes.
    let again = app.get(&path).await;
    assert_eq!(again.status, 200);
    assert_eq!(again.header("cache-control"), Some("no-store"));
    assert_eq!(shown_codes(&again.html()), codes);
}

#[tokio::test]
async fn recovery_codes_page_requires_flow_cookie() {
    let app = app().await;
    let (resp, _) = enrol_in_flow(&app, "/ui/login").await;
    let path = codes_path(&app, &resp);
    let mine = app.cookies();
    let session: Vec<(String, String)> = mine
        .iter()
        .filter(|(k, _)| k.contains("anvil_session_"))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let (flow_name, _) = flow_cookie(&app).expect("flow cookie of the codes");

    // No flow cookie (the session alone): no codes, a way forward.
    let page = get_with_cookie(&app, &path, &cookie_header(&session)).await;
    assert_eq!(page.status, 200, "{}", page.text());
    assert_eq!(page.header("cache-control"), Some("no-store"));
    assert!(shown_codes(&page.html()).is_empty(), "{}", page.text());
    assert_eq!(
        message_keys(&page.html()),
        vec!["recovery_codes_flow.gone".to_owned()]
    );
    assert!(
        page.html().contains("id=\"link-account\""),
        "{}",
        page.text()
    );

    // Another flow's cookie: a new sign-in flow in a fresh browser.
    app.clear_cookies();
    let other = app.get("/ui/login").await;
    assert_eq!(other.status, 200);
    let (_, other_value) = flow_cookie(&app).expect("another flow cookie");
    let mut forged = session.clone();
    forged.push((flow_name.clone(), other_value));
    let page = get_with_cookie(&app, &path, &cookie_header(&forged)).await;
    assert!(shown_codes(&page.html()).is_empty(), "{}", page.text());
    assert!(!page.html().contains("id=\"recovery-codes-confirm\""));

    // A made-up flow id with the right cookie: nothing either.
    let original: Vec<(String, String)> = mine.into_iter().collect();
    let page = get_with_cookie(
        &app,
        &format!("/ui/login/recovery-codes?flow={}", uuid::Uuid::now_v7()),
        &cookie_header(&original),
    )
    .await;
    assert!(shown_codes(&page.html()).is_empty(), "{}", page.text());

    // Nothing was consumed: the browser holding the cookie still sees its codes.
    let page = get_with_cookie(&app, &path, &cookie_header(&original)).await;
    assert_eq!(shown_codes(&page.html()).len(), 10, "{}", page.text());
}

#[tokio::test]
async fn recovery_codes_gone_after_confirm() {
    let app = app().await;
    let request = first_party_request(&app).await;
    let (resp, _) = enrol_in_flow(&app, &format!("/ui/login?request={request}")).await;
    let path = codes_path(&app, &resp);
    let page = app.get(&path).await;
    let codes = shown_codes(&page.html());
    assert_eq!(codes.len(), 10);
    let html = page.html();
    let action = form_action(&app, &html);
    let csrf = csrf_from(&html);

    // Without the CSRF token, or with a wrong one: 403 and the codes are still there.
    let refused = app.post_form(&action, &[]).await;
    assert_eq!(refused.status, 403, "{}", refused.text());
    let refused = app.post_form(&action, &[("csrf_token", "forged")]).await;
    assert_eq!(refused.status, 403, "{}", refused.text());
    // The right token from another browser (no flow cookie): 403 too.
    let session = session_cookie(&app).expect("session");
    let mut req = Request::post(action.as_str())
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("sec-fetch-site", "same-origin")
        .body(Body::from(format!("csrf_token={csrf}")))
        .expect("request");
    req.headers_mut().insert(
        header::COOKIE,
        format!("{}={}", session.0, session.1)
            .parse()
            .expect("cookie"),
    );
    let refused = app.send(req).await;
    assert_eq!(refused.status, 403, "{}", refused.text());
    assert_eq!(shown_codes(&app.get(&path).await.html()), codes);

    // Confirmed: on to the authorization continuation, the flow cookie cleared.
    let done = app
        .post_form(&action, &[("csrf_token", csrf.as_str())])
        .await;
    assert_eq!(done.status, 303, "{}", done.text());
    assert_eq!(done.header("cache-control"), Some("no-store"));
    let cont = to_path(&app, &location(&done));
    assert_eq!(cont, format!("/authorize/continue?request={request}"));
    assert!(flow_cookie(&app).is_none(), "flow cookie cleared");
    let at_rp = app.get(&cont).await;
    assert_eq!(at_rp.status, 303, "{}", at_rp.text());
    assert!(location(&at_rp).contains("code="), "{}", location(&at_rp));

    // The codes are gone: the page has none, a second confirm changes nothing.
    let gone = app.get(&path).await;
    assert!(shown_codes(&gone.html()).is_empty(), "{}", gone.text());
    let flow = flow_id(&flow_in(&path));
    assert!(
        app.storage()
            .flows()
            .get(default_tenant(&app).id, flow, app.clock().now())
            .await
            .expect("lookup")
            .is_none()
    );
    let again = app
        .post_form(&action, &[("csrf_token", csrf.as_str())])
        .await;
    assert_eq!(again.status, 303);
    assert_eq!(to_path(&app, &location(&again)), path);
}

#[tokio::test]
async fn recovery_codes_flow_takes_no_sign_in_step() {
    let app = app().await;
    let (resp, enrol_page) = enrol_in_flow(&app, "/ui/login").await;
    let path = codes_path(&app, &resp);
    let flow = flow_in(&path);
    let tenant = default_tenant(&app).id;
    let held = || async {
        app.storage()
            .flows()
            .get(tenant, flow_id(&flow), app.clock().now())
            .await
            .expect("lookup")
            .is_some_and(|f| anvil_core::service::flow::holds_recovery_codes(&f))
    };
    let codes_html = app.get(&path).await.html();
    assert_eq!(shown_codes(&codes_html).len(), 10);
    let csrf = csrf_from(&codes_html);
    // Replaying the confirming code against the old (deleted) enrolment flow signs nobody in
    // again and leaves the held codes alone.
    let html = enrol_page.html();
    let replay = app
        .post_form(
            &form_action(&app, &html),
            &[
                ("csrf_token", csrf_from(&html).as_str()),
                ("code", "000000"),
            ],
        )
        .await;
    assert_ne!(replay.status, 200, "{}", replay.text());
    assert!(held().await);
    // A password POST bound to the held flow (its cookie and CSRF token) does not run a
    // sign-in step on it: the sign-in starts over in a new flow.
    let resp = app
        .post_form(
            &format!("/ui/login?flow={flow}"),
            &[
                ("csrf_token", csrf.as_str()),
                ("identifier", EMAIL),
                ("password", PASSWORD),
            ],
        )
        .await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert!(
        !location(&resp).contains(&flow),
        "a new flow: {}",
        location(&resp)
    );
    assert!(held().await);
    // The held flow is no sign-in: a PRG GET of a sign-in page shows no step of it (a fresh
    // flow instead), and the codes stay held.
    let page = app.get(&format!("/ui/login?flow={flow}")).await;
    assert_eq!(page.status, 200);
    assert!(
        !page.html().contains(&format!("flow={flow}")),
        "{}",
        page.text()
    );
    assert!(held().await);
}
