//! Role admin API (ORG-05): role CRUD, assignments with pagination, audit rows, tenant isolation
//! (404), duplicate names (409), the last-administrator conflict (409) and the claim mapping in
//! the tenant settings.

mod admin_support;
mod support;
mod token_support;

use admin_support::{API, admin_token, assert_problem, call};
use anvil_core::model::{AuditAction, AuditEvent, AuditQuery, SYSTEM_ADMIN_ROLE, TenantId, User};
use axum::http::Method;
use serde_json::{Value, json};
use support::{TestApp, json as body_json};
use token_support::{acme, seed_user};

fn system(app: &TestApp) -> TenantId {
    app.system.as_ref().expect("installed").tenant.id
}

fn default(app: &TestApp) -> TenantId {
    app.default.as_ref().expect("installed").tenant.id
}

async fn events(app: &TestApp, tenant: TenantId) -> Vec<AuditEvent> {
    app.storage()
        .audit()
        .query(
            tenant,
            &AuditQuery {
                limit: 200,
                ..AuditQuery::default()
            },
        )
        .await
        .expect("audit query")
        .items
}

fn count(events: &[AuditEvent], action: AuditAction) -> usize {
    events.iter().filter(|e| e.action == action).count()
}

async fn create_role(app: &TestApp, token: &str, slug: &str, body: Value) -> Value {
    let resp = call(
        app,
        Method::POST,
        &format!("{API}/tenants/{slug}/roles"),
        Some(token),
        Some(body),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    body_json(&resp)
}

async fn put_assignment(app: &TestApp, token: &str, slug: &str, user: &User, role: &str) -> u16 {
    call(
        app,
        Method::PUT,
        &format!("{API}/tenants/{slug}/users/{}/roles/{role}", user.id),
        Some(token),
        None,
    )
    .await
    .status
    .as_u16()
}

#[tokio::test]
async fn role_crud_round_trip_is_audited() {
    let app = TestApp::new().await;
    let token = admin_token(&app, "admin:settings:write").await;

    let resp = call(
        &app,
        Method::POST,
        &format!("{API}/tenants/default/roles"),
        Some(&token),
        Some(json!({
            "name": "editor",
            "description": "Edits documents",
            "permissions": ["docs:write", "docs:read", "docs:write"]
        })),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    assert_eq!(
        resp.header("location"),
        Some("/api/admin/v1/tenants/default/roles/editor")
    );
    let created = body_json(&resp);
    assert_eq!(created["permissions"], json!(["docs:read", "docs:write"]));
    assert_eq!(created["description"], "Edits documents");

    let resp = call(
        &app,
        Method::GET,
        &format!("{API}/tenants/default/roles/editor"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(body_json(&resp)["id"], created["id"]);

    create_role(&app, &token, "default", json!({"name": "auditor"})).await;
    let resp = call(
        &app,
        Method::GET,
        &format!("{API}/tenants/default/roles"),
        Some(&token),
        None,
    )
    .await;
    let names: Vec<String> = body_json(&resp)["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["name"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(names, ["auditor", "editor"]);

    let resp = call(
        &app,
        Method::PATCH,
        &format!("{API}/tenants/default/roles/editor"),
        Some(&token),
        Some(json!({"name": "writer", "permissions": ["docs:write"]})),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let updated = body_json(&resp);
    assert_eq!(updated["name"], "writer");
    assert_eq!(updated["permissions"], json!(["docs:write"]));
    assert_eq!(updated["description"], "Edits documents");

    let resp = call(
        &app,
        Method::DELETE,
        &format!("{API}/tenants/default/roles/writer"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(resp.status, 204, "{}", resp.text());
    let resp = call(
        &app,
        Method::GET,
        &format!("{API}/tenants/default/roles/writer"),
        Some(&token),
        None,
    )
    .await;
    assert_problem(&resp, 404);

    let ev = events(&app, default(&app)).await;
    assert_eq!(count(&ev, AuditAction::RoleCreated), 2);
    assert_eq!(count(&ev, AuditAction::RoleUpdated), 1);
    assert_eq!(count(&ev, AuditAction::RoleDeleted), 1);
    let deleted = ev
        .iter()
        .find(|e| e.action == AuditAction::RoleDeleted)
        .unwrap();
    assert_eq!(deleted.target.as_deref(), created["id"].as_str());
}

#[tokio::test]
async fn invalid_roles_are_422_and_duplicates_409() {
    let app = TestApp::new().await;
    let token = admin_token(&app, "admin:settings:write").await;
    create_role(&app, &token, "default", json!({"name": "editor"})).await;

    let resp = call(
        &app,
        Method::POST,
        &format!("{API}/tenants/default/roles"),
        Some(&token),
        Some(json!({"name": "editor"})),
    )
    .await;
    assert_problem(&resp, 409);
    // Renaming onto an existing name conflicts too.
    create_role(&app, &token, "default", json!({"name": "viewer"})).await;
    let resp = call(
        &app,
        Method::PATCH,
        &format!("{API}/tenants/default/roles/viewer"),
        Some(&token),
        Some(json!({"name": "editor"})),
    )
    .await;
    assert_problem(&resp, 409);

    for body in [
        json!({"name": "Bad Name"}),
        json!({"name": "ok", "permissions": ["has space"]}),
        json!({"name": "ok", "description": "x".repeat(501)}),
        json!({"name": "ok", "unknown": 1}),
    ] {
        let resp = call(
            &app,
            Method::POST,
            &format!("{API}/tenants/default/roles"),
            Some(&token),
            Some(body.clone()),
        )
        .await;
        assert_problem(&resp, 422);
    }
}

#[tokio::test]
async fn another_tenants_role_is_404() {
    let app = TestApp::new().await;
    acme(&app).await;
    let token = admin_token(&app, "admin:settings:write admin:users:write").await;
    create_role(&app, &token, "acme", json!({"name": "acme-only"})).await;
    for (method, path) in [
        (Method::GET, "roles/acme-only"),
        (Method::PATCH, "roles/acme-only"),
        (Method::DELETE, "roles/acme-only"),
        (Method::GET, "roles/acme-only/users"),
    ] {
        let body = (method == Method::PATCH).then(|| json!({"description": "x"}));
        let resp = call(
            &app,
            method,
            &format!("{API}/tenants/default/{path}"),
            Some(&token),
            body,
        )
        .await;
        assert_problem(&resp, 404);
    }
}

#[tokio::test]
async fn assignments_paginate_and_are_audited() {
    let app = TestApp::new().await;
    let tenant = default(&app);
    let token = admin_token(&app, "admin:settings:write admin:users:write").await;
    create_role(
        &app,
        &token,
        "default",
        json!({"name": "editor", "permissions": ["docs:write"]}),
    )
    .await;
    let mut users = Vec::new();
    for i in 0..3 {
        let u = seed_user(&app, tenant, &format!("u{i}@example.test")).await;
        assert_eq!(
            put_assignment(&app, &token, "default", &u, "editor").await,
            200
        );
        users.push(u);
    }
    // Idempotent.
    let resp = call(
        &app,
        Method::PUT,
        &format!("{API}/tenants/default/users/{}/roles/editor", users[0].id),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let body = body_json(&resp);
    assert_eq!(body["user_id"], users[0].id.to_string());
    assert_eq!(body["role"]["name"], "editor");

    let resp = call(
        &app,
        Method::GET,
        &format!("{API}/tenants/default/roles/editor/users?limit=2"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let first = body_json(&resp);
    assert_eq!(first["items"].as_array().unwrap().len(), 2);
    let cursor = first["next_cursor"]
        .as_str()
        .expect("more pages")
        .to_owned();
    let resp = call(
        &app,
        Method::GET,
        &format!("{API}/tenants/default/roles/editor/users?limit=2&after={cursor}"),
        Some(&token),
        None,
    )
    .await;
    let second = body_json(&resp);
    assert_eq!(second["items"].as_array().unwrap().len(), 1);
    assert!(second["next_cursor"].is_null());

    let resp = call(
        &app,
        Method::GET,
        &format!("{API}/tenants/default/users/{}/roles", users[1].id),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(body_json(&resp)["items"][0]["name"], "editor");

    let path = format!("{API}/tenants/default/users/{}/roles/editor", users[1].id);
    let resp = call(&app, Method::DELETE, &path, Some(&token), None).await;
    assert_eq!(resp.status, 204, "{}", resp.text());
    let resp = call(&app, Method::DELETE, &path, Some(&token), None).await;
    assert_problem(&resp, 404);
    let resp = call(
        &app,
        Method::GET,
        &format!("{API}/tenants/default/users/{}/roles", users[1].id),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(body_json(&resp)["items"], json!([]));

    // Unknown users and malformed ids are 404.
    let resp = call(
        &app,
        Method::GET,
        &format!("{API}/tenants/default/users/not-a-uuid/roles"),
        Some(&token),
        None,
    )
    .await;
    assert_problem(&resp, 404);
    let resp = call(
        &app,
        Method::PUT,
        &format!(
            "{API}/tenants/default/users/{}/roles/editor",
            uuid::Uuid::now_v7()
        ),
        Some(&token),
        None,
    )
    .await;
    assert_problem(&resp, 404);

    let ev = events(&app, tenant).await;
    assert_eq!(count(&ev, AuditAction::RoleAssigned), 4);
    assert_eq!(count(&ev, AuditAction::RoleUnassigned), 1);
    let unassigned = ev
        .iter()
        .find(|e| e.action == AuditAction::RoleUnassigned)
        .unwrap();
    assert_eq!(unassigned.target, Some(users[1].id.to_string()));
}

#[tokio::test]
async fn removing_the_last_administrator_is_409_until_another_exists() {
    let app = TestApp::new().await;
    let sys = system(&app);
    let token = admin_token(&app, "admin:write").await;
    let first = seed_user(&app, sys, "first@example.test").await;
    let second = seed_user(&app, sys, "second@example.test").await;
    assert_eq!(
        put_assignment(&app, &token, "system", &first, SYSTEM_ADMIN_ROLE).await,
        200
    );

    let path = |u: &User| {
        format!(
            "{API}/tenants/system/users/{}/roles/{SYSTEM_ADMIN_ROLE}",
            u.id
        )
    };
    let resp = call(&app, Method::DELETE, &path(&first), Some(&token), None).await;
    let problem = assert_problem(&resp, 409);
    assert_eq!(problem["type"], "urn:anvilid:problem:conflict", "{problem}");

    assert_eq!(
        put_assignment(&app, &token, "system", &second, SYSTEM_ADMIN_ROLE).await,
        200
    );
    let resp = call(&app, Method::DELETE, &path(&first), Some(&token), None).await;
    assert_eq!(resp.status, 204, "{}", resp.text());
    // Now `second` is the last one.
    let resp = call(&app, Method::DELETE, &path(&second), Some(&token), None).await;
    assert_problem(&resp, 409);
}

#[tokio::test]
async fn tenant_settings_expose_and_patch_the_claim_mapping() {
    let app = TestApp::new().await;
    let token = admin_token(&app, "admin:tenants:write").await;
    let resp = call(
        &app,
        Method::GET,
        &format!("{API}/tenants/default"),
        Some(&token),
        None,
    )
    .await;
    let claims = body_json(&resp)["settings"]["claims"].clone();
    assert_eq!(claims["roles"]["claim"], "roles", "{claims}");
    assert_eq!(claims["roles"]["scope"], "roles");
    assert_eq!(claims["permissions"]["tokens"], json!(["access_token"]));

    // Rename the roles claim; permissions stay as they were.
    let resp = call(
        &app,
        Method::PATCH,
        &format!("{API}/tenants/default"),
        Some(&token),
        Some(json!({"settings": {"claims": {"roles": {
            "claim": "groups", "tokens": ["access_token", "id_token"], "scope": null
        }}}})),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let claims = body_json(&resp)["settings"]["claims"].clone();
    assert_eq!(claims["roles"]["claim"], "groups");
    assert!(claims["roles"]["scope"].is_null());
    assert_eq!(claims["permissions"]["claim"], "permissions");

    // null disables a rule.
    let resp = call(
        &app,
        Method::PATCH,
        &format!("{API}/tenants/default"),
        Some(&token),
        Some(json!({"settings": {"claims": {"permissions": null}}})),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let claims = body_json(&resp)["settings"]["claims"].clone();
    assert!(claims["permissions"].is_null(), "{claims}");
    assert_eq!(claims["roles"]["claim"], "groups");
}
