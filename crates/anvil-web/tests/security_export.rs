//! Security controls of the user export routes (ADM-09, plan 07-17) on the selected backend
//! (`ANVILID_TEST_DB`): only `admin:users:export` or `admin:write` may export; tenants are
//! isolated; no HTTP path exports password hashes (the hash option of the CLI has no HTTP
//! spelling); the GDPR bundle does not name the administrator; every export is audited.

mod admin_support;
mod support;

use admin_support::{
    API, admin_token, assert_problem, call, mint_access_token, system_client, system_issuer,
};
use anvil_cache::limiter::RateQuota;
use anvil_core::model::{AuditAction, AuditEvent, AuditQuery, TenantId};
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use serde_json::json;
use support::{TestApp, TestResponse, json as body_json};

const BCRYPT_HASH: &str = "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW";

async fn app() -> TestApp {
    TestApp::with(|c| c.rate_limits.admin = RateQuota::per_second(100_000, 100_000)).await
}

async fn get(app: &TestApp, token: &str, path: &str) -> TestResponse {
    call(app, Method::GET, path, Some(token), None).await
}

/// A user with an Argon2id password (admin API) and one with an imported bcrypt hash.
async fn users_with_passwords(app: &TestApp) -> (String, String) {
    let token = admin_token(app, "admin:users:write").await;
    let resp = call(
        app,
        Method::POST,
        &format!("{API}/tenants/default/users"),
        Some(&token),
        Some(json!({"email": "argon@example.com", "password": "a long enough password 1"})),
    )
    .await;
    assert_eq!(resp.status, StatusCode::CREATED, "{}", resp.text());
    let argon = body_json(&resp)["id"].as_str().unwrap().to_owned();
    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("{API}/tenants/default/users/import"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/x-ndjson")
        .body(Body::from(
            json!({"email": "bcrypt@example.com",
                   "password": {"scheme": "bcrypt", "hash": BCRYPT_HASH}})
            .to_string(),
        ))
        .expect("request");
    let resp = app.send(req).await;
    let report = body_json(&resp);
    assert_eq!(report["counts"]["created"], 1, "{report}");
    let bcrypt = report["records"][0]["user_id"].as_str().unwrap().to_owned();
    (argon, bcrypt)
}

fn export_paths(user: &str) -> [String; 3] {
    [
        format!("{API}/tenants/default/users/{user}/export"),
        format!("{API}/tenants/default/users/{user}/export?profile=gdpr"),
        format!("{API}/tenants/default/users/export"),
    ]
}

/// No hash material (stored PHC strings, the imported bcrypt hash) in `text`.
fn assert_no_hash_material(what: &str, text: &str) {
    for needle in ["$argon2", "$2a$", "$2b$", "$anvil-", &BCRYPT_HASH[7..29]] {
        assert!(!text.contains(needle), "{what} carries {needle}: {text}");
    }
}

/// An export document: no hash material and no `password_hash` key.
fn assert_no_hash(what: &str, text: &str) {
    assert_no_hash_material(what, text);
    assert!(!text.contains("\"password_hash\""), "{what}: {text}");
}

async fn export_events(app: &TestApp, tenant: TenantId) -> Vec<AuditEvent> {
    app.storage()
        .audit()
        .query(
            tenant,
            &AuditQuery {
                from: None,
                to: None,
                actor_id: None,
                action: Some(AuditAction::UserExported),
                outcome: None,
                target: None,
                before: None,
                limit: 50,
            },
        )
        .await
        .expect("audit")
        .items
}

async fn default_tenant(app: &TestApp) -> TenantId {
    app.storage()
        .tenants()
        .get_by_slug("default")
        .await
        .unwrap()
        .unwrap()
        .id
}

#[tokio::test]
async fn export_requires_export_scope() {
    let app = app().await;
    let (user, _) = users_with_passwords(&app).await;
    let tenant = default_tenant(&app).await;
    // Three refusals: broad read, users read and users write never imply the export scope.
    for scope in ["admin:read", "admin:users:read", "admin:users:write"] {
        let token = admin_token(&app, scope).await;
        for path in export_paths(&user) {
            let resp = get(&app, &token, &path).await;
            let problem = assert_problem(&resp, 403);
            assert!(
                problem["detail"]
                    .as_str()
                    .unwrap()
                    .contains("admin:users:export"),
                "{problem}"
            );
            assert_no_hash(&path, &resp.text());
        }
    }
    // Neither does any other combination short of admin:write.
    let token = admin_token(&app, "admin:read admin:users:write admin:settings:write").await;
    for path in export_paths(&user) {
        assert_problem(&get(&app, &token, &path).await, 403);
    }
    assert_problem(
        &get(&app, "not-a-token", &export_paths(&user)[2]).await,
        401,
    );
    assert!(export_events(&app, tenant).await.is_empty());

    // The export scope and the admin:write umbrella are accepted.
    for scope in ["admin:users:export", "admin:write"] {
        let token = admin_token(&app, scope).await;
        for path in export_paths(&user) {
            let resp = get(&app, &token, &path).await;
            assert_eq!(
                resp.status,
                StatusCode::OK,
                "{scope} {path}: {}",
                resp.text()
            );
        }
    }
    // The export scope grants nothing else.
    let token = admin_token(&app, "admin:users:export").await;
    let resp = get(&app, &token, &format!("{API}/tenants/default/users/{user}")).await;
    assert_problem(&resp, 403);
}

#[tokio::test]
async fn export_cross_tenant_refused() {
    let app = app().await;
    let (user, _) = users_with_passwords(&app).await;
    let admin = admin_token(&app, "admin:write").await;
    let resp = call(
        &app,
        Method::POST,
        &format!("{API}/tenants"),
        Some(&admin),
        Some(json!({"slug": "other", "display_name": "Other"})),
    )
    .await;
    assert_eq!(resp.status, StatusCode::CREATED, "{}", resp.text());
    let token = admin_token(&app, "admin:users:export").await;
    // A user of `default` cannot be exported through `other`.
    for path in [
        format!("{API}/tenants/other/users/{user}/export"),
        format!("{API}/tenants/other/users/{user}/export?profile=gdpr"),
    ] {
        let resp = get(&app, &token, &path).await;
        assert_problem(&resp, 404);
        assert!(!resp.text().contains("argon@example.com"));
    }
    // The bulk export of `other` holds none of `default`'s users.
    let resp = get(&app, &token, &format!("{API}/tenants/other/users/export")).await;
    assert_eq!(resp.status, StatusCode::OK);
    assert!(resp.body.is_empty(), "{}", resp.text());
    // Unknown tenants are 404.
    let resp = get(&app, &token, &format!("{API}/tenants/nope/users/export")).await;
    assert_problem(&resp, 404);
}

#[tokio::test]
async fn export_no_hash_via_http() {
    let app = app().await;
    let (argon, bcrypt) = users_with_passwords(&app).await;
    let token = admin_token(&app, "admin:write").await;
    // Every spelling of a hash option is refused (unknown query parameter), never honoured.
    let spellings = [
        "include_password_hashes=true",
        "include_password_hashes=1",
        "include_password_hashes",
        "INCLUDE_PASSWORD_HASHES=true",
        "includePasswordHashes=true",
        "include-password-hashes=true",
        "password_hashes=true",
        "hashes=true",
        "with_hashes=true",
    ];
    for user in [&argon, &bcrypt] {
        for spelling in spellings {
            for path in [
                format!("{API}/tenants/default/users/{user}/export?{spelling}"),
                format!("{API}/tenants/default/users/{user}/export?profile=gdpr&{spelling}"),
                format!("{API}/tenants/default/users/export?{spelling}"),
            ] {
                let resp = get(&app, &token, &path).await;
                // The problem names the refused parameter, but carries no hash.
                assert_problem(&resp, 422);
                assert_no_hash_material(&path, &resp.text());
            }
        }
    }
    // The plain exports of users with passwords carry no hash either.
    for user in [&argon, &bcrypt] {
        for path in export_paths(user) {
            let resp = get(&app, &token, &path).await;
            assert_eq!(resp.status, StatusCode::OK, "{path}: {}", resp.text());
            assert_no_hash(&path, &resp.text());
        }
    }
    // The OpenAPI document offers no such parameter on any export operation.
    let spec = serde_json::to_value(anvil_web::admin::openapi()).unwrap();
    for (path, op) in [
        ("/api/admin/v1/tenants/{slug}/users/{user_id}/export", "get"),
        ("/api/admin/v1/tenants/{slug}/users/export", "get"),
    ] {
        let params = spec["paths"][path][op]["parameters"].to_string();
        assert!(!params.contains("hash"), "{path}: {params}");
    }
}

#[tokio::test]
async fn gdpr_export_redacts_admin_identity() {
    let app = app().await;
    let (user, _) = users_with_passwords(&app).await;
    // A named administrator client changes the user (the event names the client as actor).
    let admin_client = system_client(&app, &["admin:users:write"]).await;
    let system = app.system.as_ref().expect("installed");
    let admin = mint_access_token(
        &app,
        system,
        &system_issuer(&app),
        &admin_client,
        "admin:users:write",
    )
    .await;
    let resp = call(
        &app,
        Method::PATCH,
        &format!("{API}/tenants/default/users/{user}"),
        Some(&admin),
        Some(json!({"claims": {"name": "Renamed"}})),
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text());

    // Exported by another administrator client.
    let exporter = system_client(&app, &["admin:users:export"]).await;
    let token = mint_access_token(
        &app,
        system,
        &system_issuer(&app),
        &exporter,
        "admin:users:export",
    )
    .await;
    let resp = get(
        &app,
        &token,
        &format!("{API}/tenants/default/users/{user}/export?profile=gdpr"),
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text());
    let text = resp.text();
    assert!(!text.contains(&admin_client), "admin client named: {text}");
    assert!(!text.contains(&exporter), "exporter named: {text}");
    let bundle = body_json(&resp);
    let events = bundle["audit_events"].as_array().unwrap();
    let update = events
        .iter()
        .find(|e| e["action"] == "user_updated")
        .unwrap_or_else(|| panic!("user_updated event in {bundle}"));
    assert_eq!(update["actor"], "administrator");
    assert!(update["ip"].is_null(), "{update}");
    assert!(update["user_agent"].is_null(), "{update}");
}

#[tokio::test]
async fn export_is_audited() {
    let app = app().await;
    let (user, _) = users_with_passwords(&app).await;
    let tenant = default_tenant(&app).await;
    let client = system_client(&app, &["admin:users:export"]).await;
    let system = app.system.as_ref().expect("installed");
    let token = mint_access_token(
        &app,
        system,
        &system_issuer(&app),
        &client,
        "admin:users:export",
    )
    .await;
    for path in export_paths(&user) {
        let resp = get(&app, &token, &path).await;
        assert_eq!(resp.status, StatusCode::OK, "{path}: {}", resp.text());
    }
    let events = export_events(&app, tenant).await;
    assert_eq!(events.len(), 3, "{events:?}");
    let mut modes: Vec<(String, u64, Option<String>)> = events
        .iter()
        .map(|e| {
            let d = e.details.as_map();
            assert_eq!(d["include_password_hashes"], false, "{d:?}");
            assert_eq!(e.actor.id.as_deref(), Some(client.as_str()));
            (
                d["mode"].as_str().unwrap().to_owned(),
                d["count"].as_u64().unwrap(),
                e.target.clone(),
            )
        })
        .collect();
    modes.sort();
    assert_eq!(
        modes,
        [
            ("bulk".to_owned(), 2, None),
            ("gdpr".to_owned(), 1, Some(user.clone())),
            ("single".to_owned(), 1, Some(user.clone())),
        ]
    );
    // Refused requests are not exports and record nothing.
    let reader = admin_token(&app, "admin:read").await;
    assert_problem(&get(&app, &reader, &export_paths(&user)[2]).await, 403);
    assert_eq!(export_events(&app, tenant).await.len(), 3);
}
