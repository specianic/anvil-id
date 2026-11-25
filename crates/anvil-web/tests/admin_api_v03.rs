//! Management API 0.3 fields end to end: client logout URIs, back-channel logout, allowed
//! resources and MFA policy; tenant MFA policy, email sign-in (needs SMTP), auto-link, upstream
//! registration and default locale. Validation failures are 422 problem documents naming the
//! field.

mod admin_support;
mod support;

use admin_support::*;
use anvil_cache::limiter::RateQuota;
use axum::http::Method;
use serde_json::{Value, json};
use support::{TestApp, TestResponse, json as body_json};

async fn app_with(installation_smtp: bool) -> TestApp {
    TestApp::with(|c| {
        c.rate_limits.admin = RateQuota::per_second(100_000, 100_000);
        c.installation_smtp = installation_smtp;
    })
    .await
}

async fn req(app: &TestApp, t: &str, m: Method, path: &str, body: Option<Value>) -> TestResponse {
    call(app, m, path, Some(t), body).await
}

fn client_body(extra: Value) -> Value {
    let mut base = json!({
        "name": "RP",
        "client_type": "confidential",
        "redirect_uris": ["https://rp.example/cb"],
    });
    for (k, v) in extra.as_object().unwrap() {
        base[k] = v.clone();
    }
    base
}

#[tokio::test]
async fn client_phase4_fields_round_trip() {
    let app = app_with(false).await;
    let t = admin_token(&app, "admin:read admin:write").await;
    let clients = format!("{API}/tenants/default/clients");

    // Defaults.
    let resp = req(
        &app,
        &t,
        Method::POST,
        &clients,
        Some(client_body(json!({}))),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    let c = body_json(&resp);
    assert_eq!(c["post_logout_redirect_uris"], json!([]));
    assert_eq!(c["backchannel_logout_uri"], Value::Null);
    assert_eq!(c["backchannel_logout_session_required"], false);
    assert_eq!(c["allowed_resources"], json!([]));
    assert_eq!(c["mfa_policy"], Value::Null);

    // Create with every field.
    let resp = req(
        &app,
        &t,
        Method::POST,
        &clients,
        Some(client_body(json!({
            "post_logout_redirect_uris": ["https://rp.example/bye", "https://rp.example/bye"],
            "backchannel_logout_uri": "https://rp.example/bcl",
            "backchannel_logout_session_required": true,
            "allowed_resources": ["https://api.example/v1"],
            "mfa_policy": "required",
        }))),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    let c = body_json(&resp);
    let id = c["client_id"].as_str().unwrap().to_owned();
    assert_eq!(
        c["post_logout_redirect_uris"],
        json!(["https://rp.example/bye"])
    );
    assert_eq!(c["backchannel_logout_uri"], "https://rp.example/bcl");
    assert_eq!(c["backchannel_logout_session_required"], true);
    assert_eq!(c["allowed_resources"], json!(["https://api.example/v1"]));
    assert_eq!(c["mfa_policy"], "required");

    // Read back from storage through GET.
    let one = format!("{clients}/{id}");
    let got = body_json(&req(&app, &t, Method::GET, &one, None).await);
    assert_eq!(got["mfa_policy"], "required");
    assert_eq!(got["backchannel_logout_uri"], "https://rp.example/bcl");

    // Patch: null clears the URI and the policy; lists are replaced.
    let resp = req(
        &app,
        &t,
        Method::PATCH,
        &one,
        Some(json!({"backchannel_logout_uri": null, "mfa_policy": null,
                    "allowed_resources": ["urn:example:api"]})),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let c = body_json(&resp);
    assert_eq!(c["backchannel_logout_uri"], Value::Null);
    assert_eq!(c["mfa_policy"], Value::Null);
    assert_eq!(c["allowed_resources"], json!(["urn:example:api"]));
    assert_eq!(
        c["post_logout_redirect_uris"],
        json!(["https://rp.example/bye"]),
        "absent fields stay unchanged"
    );
}

#[tokio::test]
async fn client_phase4_fields_are_validated() {
    let app = app_with(false).await;
    let t = admin_token(&app, "admin:read admin:write").await;
    let clients = format!("{API}/tenants/default/clients");
    for (extra, field) in [
        (
            json!({"backchannel_logout_uri": "https://rp.example/bcl#frag"}),
            "backchannel_logout_uri",
        ),
        (
            json!({"backchannel_logout_uri": "/bcl"}),
            "backchannel_logout_uri",
        ),
        (
            json!({"backchannel_logout_uri": "http://rp.example/bcl"}),
            "backchannel_logout_uri",
        ),
        (
            json!({"post_logout_redirect_uris": ["https://rp.example/out#x"]}),
            "post_logout_redirect_uris",
        ),
        (
            json!({"allowed_resources": ["https://api.example/#f"]}),
            "allowed_resources",
        ),
        (
            json!({"allowed_resources": ["https://api.example/?q=1"]}),
            "allowed_resources",
        ),
    ] {
        let resp = req(
            &app,
            &t,
            Method::POST,
            &clients,
            Some(client_body(extra.clone())),
        )
        .await;
        assert_field_error(&resp, field);
    }
    let resp = req(
        &app,
        &t,
        Method::POST,
        &clients,
        Some(client_body(json!({"mfa_policy": "sometimes"}))),
    )
    .await;
    assert_field_error(&resp, "body");

    // The same rules apply to PATCH.
    let resp = req(
        &app,
        &t,
        Method::POST,
        &clients,
        Some(client_body(json!({}))),
    )
    .await;
    let id = body_json(&resp)["client_id"].as_str().unwrap().to_owned();
    let resp = req(
        &app,
        &t,
        Method::PATCH,
        &format!("{clients}/{id}"),
        Some(json!({"backchannel_logout_uri": "relative"})),
    )
    .await;
    assert_field_error(&resp, "backchannel_logout_uri");
}

#[tokio::test]
async fn tenant_phase4_settings_round_trip_and_validation() {
    let app = app_with(false).await;
    let t = admin_token(&app, "admin:read admin:write").await;
    let tenant = format!("{API}/tenants/default");

    let s = &body_json(&req(&app, &t, Method::GET, &tenant, None).await)["settings"];
    assert_eq!(s["mfa_policy"], "optional");
    assert_eq!(s["email_otp"], false);
    assert_eq!(s["magic_link"], false);
    assert_eq!(s["auto_link"], true);
    assert_eq!(s["upstream_registration"], Value::Null);
    assert_eq!(s["default_locale"], "en");

    let resp = req(
        &app,
        &t,
        Method::PATCH,
        &tenant,
        Some(
            json!({"settings": {"mfa_policy": "required", "auto_link": false,
                                 "upstream_registration": false, "default_locale": "de-DE"}}),
        ),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let s = &body_json(&resp)["settings"];
    assert_eq!(s["mfa_policy"], "required");
    assert_eq!(s["auto_link"], false);
    assert_eq!(s["upstream_registration"], false);
    assert_eq!(s["default_locale"], "de-DE");
    assert_eq!(
        s["signing_algs"],
        json!(["RS256"]),
        "other settings unchanged"
    );

    // null follows registration again; absent keeps the rest.
    let resp = req(
        &app,
        &t,
        Method::PATCH,
        &tenant,
        Some(json!({"settings": {"upstream_registration": null}})),
    )
    .await;
    let s = &body_json(&resp)["settings"];
    assert_eq!(s["upstream_registration"], Value::Null);
    assert_eq!(s["mfa_policy"], "required");

    let resp = req(
        &app,
        &t,
        Method::PATCH,
        &tenant,
        Some(json!({"settings": {"default_locale": "x y"}})),
    )
    .await;
    assert_field_error(&resp, "default_locale");

    // Email sign-in without any SMTP is refused.
    for field in ["email_otp", "magic_link"] {
        let resp = req(
            &app,
            &t,
            Method::PATCH,
            &tenant,
            Some(json!({"settings": {field: true}})),
        )
        .await;
        assert_field_error(&resp, field);
    }
    // Also for a new tenant.
    let resp = req(
        &app,
        &t,
        Method::POST,
        &format!("{API}/tenants"),
        Some(json!({"slug": "acme", "display_name": "Acme", "settings": {"magic_link": true}})),
    )
    .await;
    assert_field_error(&resp, "magic_link");

    // With the tenant's own SMTP settings it is accepted.
    let resp = req(
        &app,
        &t,
        Method::PUT,
        &format!("{tenant}/smtp"),
        Some(json!({"host": "127.0.0.1", "port": 2525, "from": "noreply@example.com", "tls": "none"})),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let resp = req(
        &app,
        &t,
        Method::PATCH,
        &tenant,
        Some(json!({"settings": {"email_otp": true, "magic_link": true}})),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let s = &body_json(&resp)["settings"];
    assert_eq!(s["email_otp"], true);
    assert_eq!(s["magic_link"], true);
}

#[tokio::test]
async fn installation_smtp_allows_email_sign_in() {
    let app = app_with(true).await;
    let t = admin_token(&app, "admin:read admin:write").await;
    let resp = req(
        &app,
        &t,
        Method::POST,
        &format!("{API}/tenants"),
        Some(json!({"slug": "acme", "display_name": "Acme",
                    "settings": {"email_otp": true, "magic_link": true, "default_locale": "pt-BR"}})),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    let s = &body_json(&resp)["settings"];
    assert_eq!(s["email_otp"], true);
    assert_eq!(s["magic_link"], true);
    assert_eq!(s["default_locale"], "pt-BR");
}
