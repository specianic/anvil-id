//! Security controls of the user import and hash profile routes (ADM-08, plan 07-17) on the
//! selected backend (`ANVILID_TEST_DB`): least-privilege scopes, the import-only body limit
//! branch, the per-request record cap, no hash material in the report, the write-only signer key
//! and the refusal to delete a referenced profile.

mod admin_support;
mod support;

use admin_support::{API, admin_token, assert_problem, call};
use anvil_cache::limiter::RateQuota;
use anvil_core::model::{AuditQuery, UserId};
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use serde_json::json;
use support::{TestApp, TestResponse, json as body_json};

const BCRYPT_HASH: &str = "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW";
const ARGON2I_HASH: &str =
    "$argon2i$v=19$m=65536,t=2,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG";
const FB_SIGNER_KEY: &str =
    "jxspr8Ki0RYycVU8zykbdLGjFQ3McFUH0uiiTvC8pVMXAn210wjLNmdZJzxUECKbm0QsEmYUSDzZvpjeJ9WmXA==";
const FB_SALT: &str = "42xEC+ixf3L2lw==";
const FB_HASH: &str =
    "lSrfV15cpx95/sZS2W9c9Kp6i/LVgQNDNC/qzrCnh1SAyZvqmZqAjTdn3aoItz+VHjoZilo78198JAdRuid5lQ==";

/// `admin::branding::IMPORT_BODY_LIMIT` (crate-private).
const IMPORT_BODY_LIMIT: usize = 1024 * 1024;

async fn app() -> TestApp {
    TestApp::with(|c| c.rate_limits.admin = RateQuota::per_second(100_000, 100_000)).await
}

async fn send(
    app: &TestApp,
    method: Method,
    path: &str,
    token: &str,
    content_type: &str,
    body: String,
) -> TestResponse {
    let req = Request::builder()
        .method(method)
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CONTENT_LENGTH, body.len())
        .body(Body::from(body))
        .expect("request");
    app.send(req).await
}

async fn import(app: &TestApp, token: &str, query: &str, body: String) -> TestResponse {
    send(
        app,
        Method::POST,
        &format!("{API}/tenants/default/users/import{query}"),
        token,
        "application/x-ndjson",
        body,
    )
    .await
}

fn record(email: &str) -> String {
    json!({"email": email}).to_string()
}

async fn create_profile(app: &TestApp, token: &str, name: &str) -> TestResponse {
    call(
        app,
        Method::POST,
        &format!("{API}/tenants/default/password-hash-profiles"),
        Some(token),
        Some(
            json!({"name": name, "kind": "firebase_scrypt", "signer_key": FB_SIGNER_KEY,
                    "salt_separator": "Bw==", "rounds": 8, "mem_cost": 14}),
        ),
    )
    .await
}

async fn user_count(app: &TestApp) -> usize {
    let tenant = app
        .storage()
        .tenants()
        .get_by_slug("default")
        .await
        .unwrap()
        .unwrap();
    app.storage()
        .users()
        .list(
            tenant.id,
            anvil_core::model::PageRequest {
                after: None,
                limit: 200,
            },
        )
        .await
        .unwrap()
        .items
        .len()
}

#[tokio::test]
async fn import_requires_users_write_scope() {
    let app = app().await;
    for scope in [
        "admin:read",
        "admin:users:read",
        "admin:users:export",
        "admin:settings:write",
        "admin:tenants:write",
    ] {
        let token = admin_token(&app, scope).await;
        let resp = import(&app, &token, "", record("scope@example.com")).await;
        assert_problem(&resp, 403);
        assert_eq!(user_count(&app).await, 0, "{scope} imported a user");
    }
    let resp = import(&app, "not-a-token", "", record("scope@example.com")).await;
    assert_problem(&resp, 401);
    for scope in ["admin:users:write", "admin:write"] {
        let token = admin_token(&app, scope).await;
        let resp = import(&app, &token, "?dry_run=true", record("scope@example.com")).await;
        assert_eq!(resp.status, StatusCode::OK, "{scope}: {}", resp.text());
    }
}

#[tokio::test]
async fn import_body_limit_only_on_import_path() {
    let app = app().await;
    let token = admin_token(&app, "admin:write").await;
    // About 200 KiB of valid records: over the default 64 KiB, under the import limit.
    let pad = "a".repeat(1300);
    let body: String = (0..150)
        .map(|i| {
            json!({"email": format!("big{i}@example.com"), "claims": {"name": pad}}).to_string()
                + "\n"
        })
        .collect();
    assert!(body.len() > anvil_web::BODY_LIMIT && body.len() < IMPORT_BODY_LIMIT);
    let resp = import(&app, &token, "?dry_run=true", body.clone()).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text());
    assert_eq!(body_json(&resp)["counts"]["created"], 150);

    // The same body anywhere else is over the default limit.
    for (method, path) in [
        (Method::POST, format!("{API}/tenants/default/users")),
        (
            Method::POST,
            format!("{API}/tenants/default/users/import/x"),
        ),
        (Method::POST, format!("{API}/tenants/default/users/export")),
        (Method::PUT, format!("{API}/tenants/default/users/import")),
        (Method::POST, format!("{API}/tenants/default/config/plan/x")),
    ] {
        let resp = send(
            &app,
            method.clone(),
            &path,
            &token,
            "application/x-ndjson",
            body.clone(),
        )
        .await;
        assert_eq!(
            resp.status,
            StatusCode::PAYLOAD_TOO_LARGE,
            "{method} {path}: {}",
            resp.text()
        );
    }

    // One byte over the import limit is refused on the import path too: up front for an
    // announced Content-Length (by the limit layer), and while streamed without one (by the
    // handler, as a problem). Nothing is imported.
    let over = "x".repeat(IMPORT_BODY_LIMIT + 1);
    let resp = import(&app, &token, "", over.clone()).await;
    assert_eq!(
        resp.status,
        StatusCode::PAYLOAD_TOO_LARGE,
        "{}",
        resp.text()
    );
    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("{API}/tenants/default/users/import"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/x-ndjson")
        .body(Body::from(over))
        .expect("request");
    assert_problem(&app.send(req).await, 413);
    assert_eq!(user_count(&app).await, 0);
}

#[tokio::test]
async fn import_record_cap_enforced() {
    let app = app().await;
    let token = admin_token(&app, "admin:users:write").await;
    let lines = |n: usize| -> String {
        (0..n)
            .map(|i| record(&format!("cap{i}@example.com")) + "\n")
            .collect()
    };
    let resp = import(&app, &token, "", lines(1001)).await;
    let problem = assert_problem(&resp, 413);
    assert!(
        problem["detail"].as_str().unwrap().contains("1000"),
        "{problem}"
    );
    assert_eq!(user_count(&app).await, 0);
    // Nothing was audited for the refused batch.
    let tenant = app
        .storage()
        .tenants()
        .get_by_slug("default")
        .await
        .unwrap()
        .unwrap();
    let page = app
        .storage()
        .audit()
        .query(
            tenant.id,
            &AuditQuery {
                from: None,
                to: None,
                actor_id: None,
                action: Some(anvil_core::model::AuditAction::UsersImported),
                outcome: None,
                target: None,
                before: None,
                limit: 10,
            },
        )
        .await
        .unwrap();
    assert!(page.items.is_empty());
    // Exactly the cap is accepted (dry run).
    let resp = import(&app, &token, "?dry_run=true", lines(1000)).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text());
    assert_eq!(body_json(&resp)["counts"]["created"], 1000);
}

#[tokio::test]
async fn import_report_contains_no_hash() {
    let app = app().await;
    let write = admin_token(&app, "admin:write").await;
    let profile = body_json(&create_profile(&app, &write, "fb").await)["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let body = [
        json!({"email": "b@example.com", "password": {"scheme": "bcrypt", "hash": BCRYPT_HASH}})
            .to_string(),
        json!({"email": "a@example.com", "password": {"scheme": "argon2", "hash": ARGON2I_HASH}})
            .to_string(),
        json!({"email": "f@example.com", "password": {"scheme": "firebase_scrypt",
               "profile": profile, "salt": {"base64": FB_SALT}, "hash": {"base64": FB_HASH}}})
        .to_string(),
        // Rejected records that carry hashes: an unknown scheme, a broken line, an unknown profile.
        json!({"email": "u@example.com", "password": {"scheme": "md5", "hash": BCRYPT_HASH}})
            .to_string(),
        format!("{{\"email\": \"x@example.com\", \"password\": \"{BCRYPT_HASH}\""),
        json!({"email": "p@example.com", "password": {"scheme": "firebase_scrypt",
               "profile": UserId::new_v7().to_string(),
               "salt": {"base64": FB_SALT}, "hash": {"base64": FB_HASH}}})
        .to_string(),
    ]
    .join("\n");
    for query in ["?dry_run=true", ""] {
        let resp = import(&app, &write, query, body.clone()).await;
        assert_eq!(resp.status, StatusCode::OK, "{}", resp.text());
        let report = body_json(&resp);
        assert_eq!(report["counts"]["created"], 3, "{report}");
        assert_eq!(report["counts"]["rejected"], 3, "{report}");
        let text = resp.text();
        for needle in [
            "$2a$",
            "$argon2",
            "$anvil-",
            &BCRYPT_HASH[7..29],
            &ARGON2I_HASH[30..],
            &FB_HASH[..24],
            FB_SALT.trim_end_matches('='),
            "password",
            "hash",
        ] {
            assert!(!text.contains(needle), "{needle} in {text}");
        }
    }
}

#[tokio::test]
async fn profile_signer_key_never_returned() {
    let app = app().await;
    let write = admin_token(&app, "admin:settings:write").await;
    let read = admin_token(&app, "admin:settings:read").await;
    let needles = [
        FB_SIGNER_KEY,
        &FB_SIGNER_KEY[..24],
        &FB_SIGNER_KEY[40..64],
        "signer_key",
        "sealed",
    ];
    let check = |what: &str, text: &str| {
        for n in needles {
            assert!(!text.contains(n), "{what} carries {n}: {text}");
        }
    };
    let created = create_profile(&app, &write, "fb").await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.text());
    check("create", &created.text());
    let list = call(
        &app,
        Method::GET,
        &format!("{API}/tenants/default/password-hash-profiles"),
        Some(&read),
        None,
    )
    .await;
    assert_eq!(list.status, StatusCode::OK);
    assert_eq!(body_json(&list)["items"][0]["name"], "fb");
    check("list", &list.text());
    // A duplicate name is a conflict whose problem does not echo the key either.
    let dup = create_profile(&app, &write, "fb").await;
    assert_problem(&dup, 409);
    check("conflict", &dup.text());
    // A key that is not base64 is a 422 naming the field, without the value.
    let bad = call(
        &app,
        Method::POST,
        &format!("{API}/tenants/default/password-hash-profiles"),
        Some(&write),
        Some(
            json!({"name": "bad", "kind": "firebase_scrypt", "signer_key": "%%secret-ish%%",
                    "salt_separator": "Bw==", "rounds": 8, "mem_cost": 14}),
        ),
    )
    .await;
    admin_support::assert_field_error(&bad, "signer_key");
    assert!(!bad.text().contains("secret-ish"));

    // No response schema of the OpenAPI document has the key; the request schema marks it
    // write-only.
    let spec = anvil_web::admin::openapi();
    let spec = serde_json::to_value(&spec).unwrap();
    let schemas = &spec["components"]["schemas"];
    for name in ["HashProfileView", "HashProfileList"] {
        let s = schemas[name].to_string();
        assert!(!s.contains("signer_key"), "{name}: {s}");
    }
    assert_eq!(
        schemas["CreateHashProfile"]["properties"]["signer_key"]["writeOnly"],
        true
    );

    // Scopes: users and read-only tokens cannot create; users tokens cannot list.
    for scope in ["admin:users:write", "admin:read", "admin:settings:read"] {
        let token = admin_token(&app, scope).await;
        assert_problem(&create_profile(&app, &token, "other").await, 403);
    }
    let users = admin_token(&app, "admin:users:write").await;
    let resp = call(
        &app,
        Method::GET,
        &format!("{API}/tenants/default/password-hash-profiles"),
        Some(&users),
        None,
    )
    .await;
    assert_problem(&resp, 403);
}

#[tokio::test]
async fn profile_delete_referenced_conflict() {
    let app = app().await;
    let write = admin_token(&app, "admin:write").await;
    let profile = body_json(&create_profile(&app, &write, "fb").await)["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let line = json!({"email": "f@example.com", "password": {"scheme": "firebase_scrypt",
        "profile": profile, "salt": {"base64": FB_SALT}, "hash": {"base64": FB_HASH}}})
    .to_string();
    let resp = import(&app, &write, "", line).await;
    assert_eq!(body_json(&resp)["counts"]["created"], 1, "{}", resp.text());

    let path = format!("{API}/tenants/default/password-hash-profiles/{profile}");
    assert_problem(
        &call(&app, Method::DELETE, &path, Some(&write), None).await,
        409,
    );
    // Still listed.
    let list = call(
        &app,
        Method::GET,
        &format!("{API}/tenants/default/password-hash-profiles"),
        Some(&write),
        None,
    )
    .await;
    assert_eq!(body_json(&list)["items"].as_array().unwrap().len(), 1);

    // An unreferenced profile is deleted; unknown ids are 404.
    let other = body_json(&create_profile(&app, &write, "unused").await)["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let other_path = format!("{API}/tenants/default/password-hash-profiles/{other}");
    let resp = call(&app, Method::DELETE, &other_path, Some(&write), None).await;
    assert_eq!(resp.status, StatusCode::NO_CONTENT, "{}", resp.text());
    assert_problem(
        &call(&app, Method::DELETE, &other_path, Some(&write), None).await,
        404,
    );
    let junk = format!("{API}/tenants/default/password-hash-profiles/not-a-uuid");
    assert_problem(
        &call(&app, Method::DELETE, &junk, Some(&write), None).await,
        404,
    );
}
