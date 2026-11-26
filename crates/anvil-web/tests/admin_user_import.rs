//! User import over the management API (ADM-08, plan 07-17) on the selected backend
//! (`ANVILID_TEST_DB`): a Firebase hash profile created through
//! `POST …/password-hash-profiles`, an NDJSON batch through `POST …/users/import`, sign-in with
//! the old passwords through the UI login form (known-answer inputs of 07-14: Openwall bcrypt
//! and the published Firebase scrypt vector), a dry run that writes nothing, and an unchanged
//! rerun.

mod admin_support;
mod support;
mod ui_helpers;

use admin_support::{API, admin_token, call};
use anvil_core::model::{AuditAction, AuditQuery};
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use serde_json::{Value, json};
use support::{TestApp, TestResponse, json as body_json};
use ui_helpers::{default_tenant, login};

/// Openwall crypt_blowfish test vector: password `U*U`.
const BCRYPT_PW: &str = "U*U";
const BCRYPT_HASH: &str = "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW";
/// firebase/scrypt README: signer key, separator, rounds 8, mem_cost 14, password `user1password`.
const FB_SIGNER_KEY: &str =
    "jxspr8Ki0RYycVU8zykbdLGjFQ3McFUH0uiiTvC8pVMXAn210wjLNmdZJzxUECKbm0QsEmYUSDzZvpjeJ9WmXA==";
const FB_SEPARATOR: &str = "Bw==";
const FB_SALT: &str = "42xEC+ixf3L2lw==";
const FB_PW: &str = "user1password";
const FB_HASH: &str =
    "lSrfV15cpx95/sZS2W9c9Kp6i/LVgQNDNC/qzrCnh1SAyZvqmZqAjTdn3aoItz+VHjoZilo78198JAdRuid5lQ==";

/// `POST …/users/import` with an NDJSON body and a query string.
async fn import(app: &TestApp, token: &str, query: &str, body: &str) -> TestResponse {
    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("{API}/tenants/default/users/import{query}"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/x-ndjson")
        .body(Body::from(body.to_owned()))
        .expect("request");
    app.send(req).await
}

fn bcrypt_record(email: &str) -> String {
    json!({"email": email, "email_verified": true,
           "password": {"scheme": "bcrypt", "hash": BCRYPT_HASH}})
    .to_string()
}

fn firebase_record(email: &str, profile: &str) -> String {
    json!({"email": email, "email_verified": true,
           "password": {"scheme": "firebase_scrypt", "profile": profile,
                        "salt": {"base64": FB_SALT}, "hash": {"base64": FB_HASH}}})
    .to_string()
}

/// Signs in through the UI login form; whether a session cookie was set.
async fn ui_login(app: &TestApp, email: &str, password: &str) -> bool {
    app.clear_cookies();
    let _ = login(app, "", email, password).await;
    let ok = app.cookies().keys().any(|k| k.contains("anvil_session_"));
    app.clear_cookies();
    ok
}

async fn user_exists(app: &TestApp, email: &str) -> bool {
    let tenant = default_tenant(app);
    app.storage()
        .users()
        .get_by_email(tenant.id, email)
        .await
        .expect("lookup")
        .is_some()
}

fn counts(report: &Value) -> (u64, u64, u64, u64) {
    let c = &report["counts"];
    (
        c["created"].as_u64().unwrap(),
        c["unchanged"].as_u64().unwrap(),
        c["conflict"].as_u64().unwrap(),
        c["rejected"].as_u64().unwrap(),
    )
}

#[tokio::test]
async fn import_over_http_then_login_with_old_passwords() {
    let app = TestApp::new().await;
    let settings = admin_token(&app, "admin:settings:write").await;
    let users = admin_token(&app, "admin:users:write").await;

    // The Firebase profile is created through the API; the signer key is not returned.
    let resp = call(
        &app,
        Method::POST,
        &format!("{API}/tenants/default/password-hash-profiles"),
        Some(&settings),
        Some(json!({"name": "firebase-prod", "kind": "firebase_scrypt",
                    "signer_key": FB_SIGNER_KEY, "salt_separator": FB_SEPARATOR,
                    "rounds": 8, "mem_cost": 14})),
    )
    .await;
    assert_eq!(resp.status, StatusCode::CREATED, "{}", resp.text());
    let profile = body_json(&resp);
    let profile_id = profile["id"].as_str().expect("id").to_owned();
    assert_eq!(profile["kind"], "firebase_scrypt");
    assert_eq!(profile["salt_separator"], FB_SEPARATOR);
    assert!(profile.get("signer_key").is_none());

    // Dry run: reported as created, nothing written.
    let body = format!(
        "{}\n{}\n",
        bcrypt_record("bcrypt@example.com"),
        firebase_record("firebase@example.com", &profile_id)
    );
    let resp = import(&app, &users, "?dry_run=true&source=legacy-app", &body).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text());
    assert_eq!(resp.header("cache-control"), Some("no-store"));
    let report = body_json(&resp);
    assert_eq!(report["dry_run"], true);
    assert_eq!(counts(&report), (2, 0, 0, 0), "{report}");
    assert!(!user_exists(&app, "bcrypt@example.com").await);
    assert!(!user_exists(&app, "firebase@example.com").await);

    // The real run creates both users.
    let resp = import(&app, &users, "?source=legacy-app", &body).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text());
    let report = body_json(&resp);
    assert_eq!(report["dry_run"], false);
    assert_eq!(counts(&report), (2, 0, 0, 0), "{report}");
    assert_eq!(report["records"][0]["line"], 1);
    assert_eq!(report["records"][1]["line"], 2);
    assert!(report["records"][0]["user_id"].is_string());

    // Rerun of the same batch: unchanged, idempotent (before the first
    // sign-in replaces the imported hashes).
    let resp = import(&app, &users, "", &body).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text());
    assert_eq!(counts(&body_json(&resp)), (0, 2, 0, 0));

    // Both sign in with their old passwords (and not with a wrong one).
    assert!(ui_login(&app, "bcrypt@example.com", BCRYPT_PW).await);
    assert!(ui_login(&app, "firebase@example.com", FB_PW).await);
    assert!(!ui_login(&app, "firebase@example.com", "not-the-password-1").await);

    // After the sign-in rehash the stored credential differs from the imported hash, so the same
    // batch now reports conflicts (with `update=true` it would reset the passwords).
    let resp = import(&app, &users, "", &body).await;
    assert_eq!(counts(&body_json(&resp)), (0, 0, 2, 0));

    // Each of the four calls (dry run included) is one users_imported event; the labelled ones
    // carry the source.
    let tenant = default_tenant(&app);
    let page = app
        .storage()
        .audit()
        .query(
            tenant.id,
            &AuditQuery {
                from: None,
                to: None,
                actor_id: None,
                action: Some(AuditAction::UsersImported),
                outcome: None,
                target: None,
                before: None,
                limit: 50,
            },
        )
        .await
        .expect("audit");
    assert_eq!(page.items.len(), 4);
    let text = serde_json::to_string(
        &page
            .items
            .iter()
            .map(|e| e.details.as_map().clone())
            .collect::<Vec<_>>(),
    )
    .unwrap();
    assert!(text.contains("legacy-app"), "{text}");
}

#[tokio::test]
async fn import_reports_bad_lines_by_number_without_echoing_them() {
    let app = TestApp::new().await;
    let users = admin_token(&app, "admin:users:write").await;
    let body = format!(
        "{}\n\nnot json at all {BCRYPT_HASH}\n{{\"email\":\"bad\"}}\n",
        bcrypt_record("ok@example.com")
    );
    let resp = import(&app, &users, "", &body).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text());
    let report = body_json(&resp);
    assert_eq!(counts(&report), (1, 0, 0, 2), "{report}");
    assert_eq!(report["records"][1]["line"], 3);
    assert_eq!(report["records"][1]["reason"], "invalid_record");
    assert_eq!(report["records"][2]["line"], 4);
    assert_eq!(report["records"][2]["reason"], "invalid_email");
    let text = resp.text();
    assert!(!text.contains("not json"), "{text}");
    assert!(!text.contains("$2a$"), "{text}");
}

#[tokio::test]
async fn import_requires_ndjson_content_type_and_a_valid_query() {
    let app = TestApp::new().await;
    let users = admin_token(&app, "admin:users:write").await;
    let resp = call(
        &app,
        Method::POST,
        &format!("{API}/tenants/default/users/import"),
        Some(&users),
        Some(json!({"email": "json@example.com"})),
    )
    .await;
    admin_support::assert_problem(&resp, 400);
    assert!(!user_exists(&app, "json@example.com").await);

    let resp = import(&app, &users, "?bogus=1", &bcrypt_record("q@example.com")).await;
    admin_support::assert_problem(&resp, 422);
    let resp = import(&app, &users, "?source=", &bcrypt_record("q@example.com")).await;
    admin_support::assert_field_error(&resp, "source");
    assert!(!user_exists(&app, "q@example.com").await);

    let resp = call(
        &app,
        Method::POST,
        &format!("{API}/tenants/nope/users/import"),
        Some(&users),
        None,
    )
    .await;
    admin_support::assert_problem(&resp, 404);
}
