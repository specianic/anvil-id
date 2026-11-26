//! Headless flow API, browser mode (UI-05): the happy paths of every flow kind through
//! `/api/flows/v1` on the selected backend (`ANVILID_TEST_DB`), from an allow-listed same-site
//! origin, with the flow cookie and the `X-CSRF-Token` header. The security controls are in
//! `security_headless.rs`.

mod authz;
mod headless_support;
mod support;
mod ui_helpers;

use anvil_core::model::{RegistrationMode, TenantSettings};
use headless_support::*;
use serde_json::{Value, json};
use support::location;
use ui_helpers::{flow_cookie, register, session_cookie};

const EMAIL: &str = "alice@example.com";
const PASSWORD: &str = "correct horse battery";

async fn app_with_user() -> support::TestApp {
    let app = app().await;
    register(&app, "", EMAIL, PASSWORD).await;
    app
}

fn field<'a>(v: &'a Value, name: &str) -> &'a Value {
    v["form"]["fields"]
        .as_array()
        .expect("fields")
        .iter()
        .find(|f| f["name"] == name)
        .unwrap_or_else(|| panic!("field {name} in {v}"))
}

#[tokio::test]
async fn login_with_password_completes_and_continue_to_issues_a_code() {
    let app = app_with_user().await;
    let iss = app.issuer(None);
    let tenant = authz::default_tenant(&app);
    let client = authz::web_client(&app, &tenant).await;
    let resp = authz::get(
        &app,
        &authz::authorize_path("", &authz::pkce_params(&client.client_id)),
        None,
    )
    .await;
    let request = authz::assert_login_redirect(&resp, &iss);

    let (flow, v) = start(&app, "login", &json!({ "request": request })).await;
    assert_eq!(v["step"], "form");
    assert_eq!(v["flow"]["kind"], "login");
    assert!(v["flow"]["expires_at"].is_string(), "{v}");
    assert_eq!(v["form"]["id"], "login");
    assert!(
        flow_cookie(&app).is_some(),
        "the start answer sets the flow cookie"
    );
    assert_eq!(field(&v, "identifier")["kind"], "email");
    assert_eq!(field(&v, "password")["kind"], "password");
    assert_eq!(method_kinds(&v), vec!["password", "passkey"]);

    let resp = flow.submit(&app, &password(EMAIL, PASSWORD)).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(resp.header("cache-control"), Some("no-store"));
    let v = body(&resp);
    assert_eq!(v["step"], "completed");
    let continue_to = v["result"]["continue_to"].as_str().expect("continue_to");
    assert_eq!(
        continue_to,
        format!("{iss}/authorize/continue?request={request}")
    );
    assert!(session_cookie(&app).is_some(), "session cookie set");
    assert!(flow_cookie(&app).is_none(), "flow cookie cleared");

    // The SPA navigates top-level to continue_to: the session issues the code.
    let path = continue_to.strip_prefix(&iss).expect("on the issuer");
    let resp = app.get(path).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    let loc = location(&resp);
    assert!(loc.starts_with(&format!("{}?", authz::RP)), "{loc}");
    assert!(authz::param(&resp, "code").is_some(), "{loc}");
    assert_eq!(authz::param(&resp, "state").as_deref(), Some("st-1"));
}

#[tokio::test]
async fn wrong_password_answers_the_form_with_the_error_and_400() {
    let app = app_with_user().await;
    let (flow, _) = start(&app, "login", &json!({})).await;
    let resp = flow
        .submit(&app, &password(EMAIL, "wrong password 123"))
        .await;
    assert_eq!(resp.status, 400, "{}", resp.text());
    let v = body(&resp);
    assert_eq!(v["step"], "form");
    assert_eq!(message_keys(&v), vec!["login.invalid_credentials"]);
    assert_eq!(field(&v, "identifier")["value"], EMAIL, "identifier echoed");
    assert!(field(&v, "password").get("value").is_none());
    // The flow continues with the same binding.
    assert_eq!(v["flow"]["id"], flow.id.as_str());
    assert_eq!(v["csrf_token"], flow.csrf.as_str());
    assert!(session_cookie(&app).is_none());
}

#[tokio::test]
async fn get_returns_the_current_step() {
    let app = app_with_user().await;
    let (flow, started) = start(&app, "login", &json!({})).await;
    let resp = flow.get(&app).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let v = body(&resp);
    assert_eq!(v["form"], started["form"]);
    assert_eq!(v["flow"]["id"], flow.id.as_str());
    // Another kind's path does not show this flow.
    let resp = headless_support::Call::get(&format!("{API}/registration/{}", flow.id))
        .csrf(&flow.csrf)
        .send(&app)
        .await;
    assert_eq!(resp.status, 404, "{}", resp.text());
}

#[tokio::test]
async fn login_lists_email_code_and_magic_link_when_enabled() {
    let app = app().await;
    allow_origins(
        &app,
        &[SPA],
        TenantSettings {
            email_otp: true,
            magic_link: true,
            ..TenantSettings::default()
        },
    )
    .await;
    let (_, v) = start(&app, "login", &json!({})).await;
    assert_eq!(
        method_kinds(&v),
        vec!["password", "passkey", "email_code", "magic_link"]
    );
}

#[tokio::test]
async fn email_code_request_answers_the_email_step_with_its_token() {
    let app = app_with_user().await;
    allow_origins(
        &app,
        &[SPA],
        TenantSettings {
            email_otp: true,
            ..TenantSettings::default()
        },
    )
    .await;
    let (flow, _) = start(&app, "login", &json!({})).await;
    let resp = flow
        .submit(
            &app,
            &json!({"method": "email_code_request", "values": {"email": EMAIL}}),
        )
        .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let v = body(&resp);
    assert_eq!(v["form"]["id"], "email-code");
    let token = field(&v, "factor_token");
    assert_eq!(token["kind"], "hidden");
    assert!(token["value"].as_str().is_some_and(|t| !t.is_empty()));
    // A wrong code keeps the step and its token.
    let resp = flow
        .submit(
            &app,
            &json!({"method": "email_code", "values": {
                "code": "000000",
                "factor_token": token["value"],
            }}),
        )
        .await;
    assert_eq!(resp.status, 400, "{}", resp.text());
    let v = body(&resp);
    assert_eq!(v["form"]["id"], "email-code");
    assert_eq!(field(&v, "factor_token")["value"], token["value"]);
}

#[tokio::test]
async fn registration_open_signs_in_and_closed_is_refused() {
    let app = app().await;
    let (flow, v) = start(&app, "registration", &json!({})).await;
    assert_eq!(v["form"]["id"], "registration");
    assert_eq!(v["form"]["methods"], json!([]), "no sign-in methods");
    let resp = flow
        .submit(
            &app,
            &json!({"values": {"email": "bob@example.com", "password": PASSWORD}}),
        )
        .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let v = body(&resp);
    assert_eq!(v["step"], "completed", "{v}");
    assert!(session_cookie(&app).is_some());

    for mode in [RegistrationMode::Disabled, RegistrationMode::InviteOnly] {
        allow_origins(
            &app,
            &[SPA],
            TenantSettings {
                registration: mode,
                ..TenantSettings::default()
            },
        )
        .await;
        let resp = headless_support::Call::post(&format!("{API}/registration"), &json!({}))
            .send(&app)
            .await;
        assert_eq!(resp.status, 403, "{mode:?}: {}", resp.text());
        assert_eq!(body(&resp)["code"], "registration_disabled");
    }
}

#[tokio::test]
async fn recovery_request_and_verification_start() {
    let app = app_with_user().await;
    let (flow, v) = start(&app, "recovery", &json!({})).await;
    assert_eq!(v["form"]["id"], "recovery");
    let resp = flow
        .submit(&app, &json!({"values": {"email": EMAIL}}))
        .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let v = body(&resp);
    assert_eq!(v["step"], "message", "{v}");
    assert!(v["message"]["key"].is_string());
    assert!(v.get("csrf_token").is_none(), "the flow is finished");

    let (_, v) = start(&app, "verification", &json!({"token": "emailed-token"})).await;
    assert_eq!(v["form"]["id"], "verification");
    assert_eq!(field(&v, "token")["value"], "emailed-token");
}

#[tokio::test]
async fn ui_locales_de_fills_labels_and_texts() {
    let app = app_with_user().await;
    let resp = headless_support::Call::post(&format!("{API}/login?ui_locales=de"), &json!({}))
        .send(&app)
        .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let v = body(&resp);
    assert_eq!(field(&v, "identifier")["label"], "E-Mail-Adresse");
    assert_eq!(field(&v, "password")["label"], "Passwort");
    let flow = Flow::of("login", &v);
    let resp = headless_support::Call::post(
        &format!("{}?ui_locales=de", flow.path()),
        &password(EMAIL, "wrong password 123"),
    )
    .csrf(&flow.csrf)
    .send(&app)
    .await;
    let v = body(&resp);
    let text = v["form"]["messages"][0]["text"].as_str().expect("text");
    assert!(!text.is_empty());

    // Without ui_locales: keys only.
    let (_, v) = start(&app, "login", &json!({})).await;
    assert!(field(&v, "identifier").get("label").is_none(), "{v}");
    assert_eq!(field(&v, "identifier")["label_key"], "field.email");
}

#[tokio::test]
async fn upstream_method_answers_browser_required_with_the_sign_in_page() {
    let app = app_with_user().await;
    let iss = app.issuer(None);
    let request = "0192f0c4-7a1b-7c3d-8e9f-0123456789ab";
    let (flow, _) = start(&app, "login", &json!({ "request": request })).await;
    let resp = flow
        .submit(
            &app,
            &json!({"method": "upstream", "values": {"slug": "github"}}),
        )
        .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let v = body(&resp);
    assert_eq!(v["step"], "browser_required");
    assert_eq!(v["url"], format!("{iss}/ui/login?request={request}"));
}

#[tokio::test]
async fn an_unknown_kind_and_unknown_paths_are_json_404() {
    let app = app().await;
    for path in [
        format!("{API}/setup"),
        format!("{API}/settings"),
        format!("{API}/login/0190a6d4-0000-7000-8000-000000000001/nope/deeper"),
    ] {
        let resp = headless_support::Call::post(&path, &json!({}))
            .send(&app)
            .await;
        assert_eq!(resp.status, 404, "{path}: {}", resp.text());
        assert_eq!(
            resp.header("content-type"),
            Some("application/problem+json"),
            "{path}"
        );
    }
}
