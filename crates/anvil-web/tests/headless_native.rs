//! Native-app mode of the headless flow API (UI-05, decision Q6) end to end, on the selected
//! backend (`ANVILID_TEST_DB`): a first-party `headless_native` client pushes its request with a
//! PKCE challenge, starts a token-bound flow with the `request_uri`, signs in through the API,
//! receives the code as JSON and redeems it at `/token` with its `code_verifier`. Also the second
//! factor when the tenant requires TOTP, and the second factor of the browser mode (07-10
//! deferred item). The negative tests live in `security_headless.rs`.

mod authz;
mod headless_support;
mod native_support;
mod par_support;
mod support;
mod token_support;
mod ui_helpers;

use anvil_core::model::{
    CredentialId, MfaPolicy, NewTotp, TOTP_SEED_PURPOSE, TenantSettings, UserId, credential_aad,
};
use anvil_core::ports::Clock as _;
use anvil_core::service::account::new_recovery_codes;
use anvil_jose::otp::TotpSecret;
use aws_lc_rs::hmac;
use headless_support::{SPA, allow_origins, app, body, message_keys, password, start};
use native_support::*;
use par_support::exchange;
use serde_json::{Value, json};
use support::TestApp;
use token_support::jwt_claims;
use ui_helpers::{default_tenant, register, session_cookie};

const EMAIL: &str = "alice@example.com";
const PASSWORD: &str = "correct horse battery";

/// The headless app with a registered user and an empty cookie jar (registration signs in).
async fn app_with_user() -> TestApp {
    let app = app().await;
    register(&app, "", EMAIL, PASSWORD).await;
    app.clear_cookies();
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

/// Asserts the token response is for `client` and the user, with the pushed nonce.
fn assert_tokens(
    resp: &support::TestResponse,
    client_id: &str,
    user: UserId,
    issuer: &str,
) -> Value {
    assert_eq!(resp.status, 200, "{}", resp.text());
    let v = support::json(resp);
    assert!(v["access_token"].is_string(), "{v}");
    let claims = jwt_claims(v["id_token"].as_str().expect("id_token"));
    assert_eq!(claims["sub"], user.to_string());
    assert_eq!(claims["aud"], json!([client_id]));
    assert_eq!(claims["iss"], issuer);
    assert_eq!(claims["nonce"], token_support::NONCE);
    claims
}

#[tokio::test]
async fn native_login_with_password_returns_a_code_redeemed_with_the_verifier() {
    let app = app_with_user().await;
    let iss = app.issuer(None);
    let client = native_client(&app).await;

    let (flow, v) = started(&app, &client).await;
    assert_eq!(v["step"], "form", "{v}");
    assert_eq!(v["form"]["id"], "login");
    // A 43-character base64url token (256 bits), returned once.
    assert_eq!(flow.token.len(), 43);
    // Browser-only methods are not offered.
    let kinds: Vec<&str> = v["form"]["methods"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|m| m["kind"].as_str())
        .collect();
    assert!(kinds.contains(&"password"), "{kinds:?}");
    assert!(!kinds.contains(&"passkey"), "{kinds:?}");

    // The current step reads back without the token being repeated.
    let resp = flow.get(&app).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let current = body(&resp);
    assert_eq!(current["form"]["id"], "login");
    assert!(current.get("flow_token").is_none());
    assert!(current.get("csrf_token").is_none());

    let resp = flow.submit(&app, &password(EMAIL, PASSWORD)).await;
    assert!(!sets_cookie(&resp), "no session cookie: {:?}", resp.headers);
    let code = code_of(&resp, &iss);

    let resp = exchange(&app, &client, &code).await;
    assert_tokens(&resp, client.id(), user_id(&app).await, &iss);
    assert!(session_cookie(&app).is_none());
}

#[tokio::test]
async fn native_wrong_password_answers_the_form_and_the_flow_continues() {
    let app = app_with_user().await;
    let iss = app.issuer(None);
    let client = native_client(&app).await;
    let (flow, _) = started(&app, &client).await;

    let resp = flow
        .submit(&app, &password(EMAIL, "wrong password 123"))
        .await;
    assert_eq!(resp.status, 400, "{}", resp.text());
    let v = body(&resp);
    assert_eq!(message_keys(&v), vec!["login.invalid_credentials"]);
    assert!(v.get("csrf_token").is_none());

    let resp = flow.submit(&app, &password(EMAIL, PASSWORD)).await;
    let code = code_of(&resp, &iss);
    let resp = exchange(&app, &client, &code).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
}

/// Enrols an authenticator app for the user directly through storage; returns its seed.
async fn enrol_totp(app: &TestApp) -> Vec<u8> {
    let tenant = default_tenant(app).id;
    let user = user_id(app).await;
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
    seed.as_bytes().to_vec()
}

fn totp_code(seed: &[u8], unix: i64) -> String {
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

/// The tenant requires a second factor; the user has an authenticator app.
async fn require_totp(app: &TestApp) -> Vec<u8> {
    // The browser-mode origin allow-list stays.
    allow_origins(
        app,
        &[SPA],
        TenantSettings {
            mfa_policy: MfaPolicy::Required,
            ..TenantSettings::default()
        },
    )
    .await;
    enrol_totp(app).await
}

/// The `factor_token` hidden field of a second-factor answer.
fn factor_token(v: &Value) -> String {
    v["form"]["fields"]
        .as_array()
        .expect("fields")
        .iter()
        .find(|f| f["name"] == "factor_token")
        .and_then(|f| f["value"].as_str())
        .expect("factor_token")
        .to_owned()
}

#[tokio::test]
async fn native_login_with_required_totp_returns_the_code_after_the_second_factor() {
    let app = app_with_user().await;
    let iss = app.issuer(None);
    let seed = require_totp(&app).await;
    let client = native_client(&app).await;
    let (flow, _) = started(&app, &client).await;

    let resp = flow.submit(&app, &password(EMAIL, PASSWORD)).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let v = body(&resp);
    assert_eq!(v["step"], "form", "{v}");
    assert_eq!(v["form"]["id"], "second-factor", "{v}");
    let token = factor_token(&v);

    // A wrong code keeps the step.
    let resp = flow
        .submit(
            &app,
            &json!({"method": "totp", "values": {"code": "000000", "factor_token": token}}),
        )
        .await;
    assert_eq!(resp.status, 400, "{}", resp.text());
    assert_eq!(body(&resp)["form"]["id"], "second-factor");

    let code = totp_code(&seed, app.clock().now().unix_timestamp());
    let resp = flow
        .submit(
            &app,
            &json!({"method": "totp", "values": {"code": code, "factor_token": token}}),
        )
        .await;
    assert!(!sets_cookie(&resp));
    let code = code_of(&resp, &iss);
    let resp = exchange(&app, &client, &code).await;
    let claims = assert_tokens(&resp, client.id(), user_id(&app).await, &iss);
    let amr: Vec<&str> = claims["amr"]
        .as_array()
        .expect("amr")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(amr.contains(&"otp") && amr.contains(&"mfa"), "{amr:?}");
}

#[tokio::test]
async fn browser_mode_second_factor_completes_the_sign_in() {
    // Deferred from 07-10: the second factor through the browser-mode API.
    let app = app_with_user().await;
    let seed = require_totp(&app).await;
    let (flow, _) = start(&app, "login", &json!({})).await;
    let resp = flow.submit(&app, &password(EMAIL, PASSWORD)).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let v = body(&resp);
    assert_eq!(v["form"]["id"], "second-factor", "{v}");
    let token = factor_token(&v);
    assert!(session_cookie(&app).is_none());

    let code = totp_code(&seed, app.clock().now().unix_timestamp());
    let resp = flow
        .submit(
            &app,
            &json!({"method": "totp", "values": {"code": code, "factor_token": token}}),
        )
        .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(body(&resp)["step"], "completed");
    assert!(session_cookie(&app).is_some());
}
