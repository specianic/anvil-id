//! Attribute admin API (AUTH-14): definition create/replace/delete with schema validation
//! problems, user values with per-pointer field errors, audit rows, and tenant isolation (404).

mod admin_support;
mod support;
mod token_support;

use admin_support::{API, admin_token, assert_field_error, assert_problem, call};
use anvil_core::model::{AuditAction, AuditEvent, AuditQuery, TenantId};
use axum::http::Method;
use serde_json::{Value, json};
use support::{TestApp, json as body_json};
use token_support::{acme, default_tenant, seed_user};

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

fn department() -> Value {
    json!({
        "schema": {"type": "string", "enum": ["eng", "sales"]},
        "required": false,
        "user_editable": true,
        "claim": {"claim": "department", "tokens": ["access_token"], "scope": null},
        "position": 1
    })
}

async fn put(app: &TestApp, token: &str, path: &str, body: Value) -> support::TestResponse {
    call(
        app,
        Method::PUT,
        &format!("{API}{path}"),
        Some(token),
        Some(body),
    )
    .await
}

#[tokio::test]
async fn definition_crud_round_trip_is_audited() {
    let app = TestApp::new().await;
    let token = admin_token(&app, "admin:settings:write").await;
    let tenant = default_tenant(&app);

    let resp = put(
        &app,
        &token,
        "/tenants/default/attributes/dept",
        department(),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let def = body_json(&resp);
    assert_eq!(def["name"], "dept");
    assert_eq!(def["schema"]["enum"], json!(["eng", "sales"]));
    assert_eq!(def["user_editable"], true);
    assert_eq!(def["claim"]["claim"], "department");
    assert_eq!(def["claim"]["tokens"], json!(["access_token"]));
    assert_eq!(def["position"], 1);

    // Replace (PUT is create-or-replace).
    let mut replaced = department();
    replaced["schema"] = json!({"type": "string", "maxLength": 20});
    replaced["user_editable"] = json!(false);
    let resp = put(&app, &token, "/tenants/default/attributes/dept", replaced).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(body_json(&resp)["schema"]["maxLength"], 20);

    let resp = put(
        &app,
        &token,
        "/tenants/default/attributes/cost_center",
        json!({"schema": {"type": "integer"}, "position": 0}),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());

    let resp = call(
        &app,
        Method::GET,
        &format!("{API}/tenants/default/attributes"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let list = body_json(&resp);
    let names: Vec<&str> = list["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["cost_center", "dept"], "position order");

    let resp = call(
        &app,
        Method::GET,
        &format!("{API}/tenants/default/attributes/dept"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(resp.status, 200);
    assert_eq!(body_json(&resp)["claim"]["claim"], "department");

    let resp = call(
        &app,
        Method::DELETE,
        &format!("{API}/tenants/default/attributes/dept"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(resp.status, 204, "{}", resp.text());
    let resp = call(
        &app,
        Method::DELETE,
        &format!("{API}/tenants/default/attributes/dept"),
        Some(&token),
        None,
    )
    .await;
    assert_problem(&resp, 404);
    let resp = call(
        &app,
        Method::GET,
        &format!("{API}/tenants/default/attributes/dept"),
        Some(&token),
        None,
    )
    .await;
    assert_problem(&resp, 404);

    let log = events(&app, tenant).await;
    assert_eq!(count(&log, AuditAction::AttributeDefined), 3);
    assert_eq!(count(&log, AuditAction::AttributeDeleted), 1);
    let defined = log
        .iter()
        .find(|e| e.action == AuditAction::AttributeDefined)
        .unwrap();
    assert!(
        defined
            .actor
            .id
            .as_deref()
            .is_some_and(|id| id.starts_with("adm-")),
        "{:?}",
        defined.actor
    );
}

#[tokio::test]
async fn invalid_definitions_are_422_problems_naming_the_field() {
    let app = TestApp::new().await;
    let token = admin_token(&app, "admin:settings:write").await;
    let tenant = default_tenant(&app);

    // Meta-invalid schema.
    let resp = put(
        &app,
        &token,
        "/tenants/default/attributes/dept",
        json!({"schema": {"type": "strin"}}),
    )
    .await;
    assert_field_error(&resp, "schema");
    // Remote $ref.
    let resp = put(
        &app,
        &token,
        "/tenants/default/attributes/dept",
        json!({"schema": {"$ref": "https://schemas.example/dept.json"}}),
    )
    .await;
    assert_field_error(&resp, "schema");
    // Reserved claim name as attribute name, malformed name.
    for name in ["email", "Dept", "1x"] {
        let resp = put(
            &app,
            &token,
            &format!("/tenants/default/attributes/{name}"),
            json!({"schema": {"type": "string"}}),
        )
        .await;
        let body = assert_problem(&resp, 422);
        assert_eq!(body["errors"][0]["field"], "name", "{name}: {body}");
    }
    // Claim rule colliding with a protocol claim.
    let resp = put(
        &app,
        &token,
        "/tenants/default/attributes/dept",
        json!({
            "schema": {"type": "string"},
            "claim": {"claim": "sub", "tokens": ["access_token"], "scope": null}
        }),
    )
    .await;
    assert_field_error(&resp, "claim");
    // Body shape.
    let resp = put(
        &app,
        &token,
        "/tenants/default/attributes/dept",
        json!({"schema": {"type": "string"}, "unknown": 1}),
    )
    .await;
    assert_field_error(&resp, "body");

    let log = events(&app, tenant).await;
    assert_eq!(
        count(&log, AuditAction::AttributeDefined),
        0,
        "nothing audited"
    );
}

#[tokio::test]
async fn user_values_are_validated_and_audited() {
    let app = TestApp::new().await;
    let settings = admin_token(&app, "admin:settings:write").await;
    let users = admin_token(&app, "admin:users:write").await;
    let tenant = default_tenant(&app);
    let user = seed_user(&app, tenant, "ada@example.test").await;
    assert_eq!(
        put(
            &app,
            &settings,
            "/tenants/default/attributes/dept",
            department()
        )
        .await
        .status,
        200
    );
    assert_eq!(
        put(
            &app,
            &settings,
            "/tenants/default/attributes/tags",
            json!({"schema": {"type": "array", "items": {"type": "string", "maxLength": 5}}}),
        )
        .await
        .status,
        200
    );
    let path = format!("/tenants/default/users/{}/attributes", user.id);

    let resp = call(
        &app,
        Method::GET,
        &format!("{API}{path}"),
        Some(&users),
        None,
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(body_json(&resp)["values"], json!({}));

    let resp = put(
        &app,
        &users,
        &path,
        json!({"values": {"dept": "eng", "tags": ["a", "b"]}}),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let body = body_json(&resp);
    assert_eq!(body["user_id"], user.id.to_string());
    assert_eq!(body["values"], json!({"dept": "eng", "tags": ["a", "b"]}));

    // An unknown key is refused by its pointer.
    let resp = put(
        &app,
        &users,
        &path,
        json!({"values": {"dept": "eng", "shoe_size": 42}}),
    )
    .await;
    let problem = assert_problem(&resp, 422);
    assert_eq!(problem["errors"][0]["field"], "/shoe_size", "{problem}");

    // Invalid values: enum violation and a too-long array item. Every pointer is listed, no
    // value is echoed, nothing is stored.
    let resp = put(
        &app,
        &users,
        &path,
        json!({"values": {"dept": "marketing", "tags": ["ok", "toolong"]}}),
    )
    .await;
    let problem = assert_problem(&resp, 422);
    let fields: Vec<&str> = problem["errors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["field"].as_str().unwrap())
        .collect();
    assert!(fields.contains(&"/dept"), "{problem}");
    assert!(fields.iter().any(|f| f.starts_with("/tags")), "{problem}");
    assert!(!resp.text().contains("marketing"), "{}", resp.text());
    assert!(!resp.text().contains("toolong"), "{}", resp.text());

    let resp = call(
        &app,
        Method::GET,
        &format!("{API}{path}"),
        Some(&users),
        None,
    )
    .await;
    assert_eq!(
        body_json(&resp)["values"],
        json!({"dept": "eng", "tags": ["a", "b"]}),
        "unchanged after the refusal"
    );

    // Replace semantics: an absent defined attribute is removed.
    let resp = put(&app, &users, &path, json!({"values": {"dept": "sales"}})).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(body_json(&resp)["values"], json!({"dept": "sales"}));

    // Unknown user and non-UUID ids are 404.
    let resp = put(
        &app,
        &users,
        "/tenants/default/users/0192f0c2-7d6a-7b1e-9a40-5f2d1c3b4a99/attributes",
        json!({"values": {}}),
    )
    .await;
    assert_problem(&resp, 404);
    let resp = call(
        &app,
        Method::GET,
        &format!("{API}/tenants/default/users/not-a-uuid/attributes"),
        Some(&users),
        None,
    )
    .await;
    assert_problem(&resp, 404);

    let log = events(&app, tenant).await;
    let updates: Vec<&AuditEvent> = log
        .iter()
        .filter(|e| e.action == AuditAction::UserAttributesUpdated)
        .collect();
    assert_eq!(
        updates.len(),
        2,
        "two accepted writes, the refusal is not audited"
    );
    for e in updates {
        assert_eq!(e.target.as_deref(), Some(user.id.to_string().as_str()));
        let details = Value::Object(e.details.as_map().clone()).to_string();
        assert!(
            !details.contains("eng") && !details.contains("sales"),
            "{details}"
        );
    }
}

#[tokio::test]
async fn attributes_of_another_tenant_are_404() {
    let app = TestApp::new().await;
    let token = admin_token(&app, "admin:write").await;
    let other = acme(&app).await;
    let user = seed_user(&app, other.id, "bob@acme.test").await;
    assert_eq!(
        put(&app, &token, "/tenants/acme/attributes/dept", department())
            .await
            .status,
        200
    );

    // The definition is acme's only.
    let resp = call(
        &app,
        Method::GET,
        &format!("{API}/tenants/default/attributes/dept"),
        Some(&token),
        None,
    )
    .await;
    assert_problem(&resp, 404);
    // acme's user through the default tenant.
    let resp = put(
        &app,
        &token,
        &format!("/tenants/default/users/{}/attributes", user.id),
        json!({"values": {}}),
    )
    .await;
    assert_problem(&resp, 404);
    let resp = call(
        &app,
        Method::GET,
        &format!("{API}/tenants/default/users/{}/attributes", user.id),
        Some(&token),
        None,
    )
    .await;
    assert_problem(&resp, 404);
    // Through its own tenant it works.
    let resp = put(
        &app,
        &token,
        &format!("/tenants/acme/users/{}/attributes", user.id),
        json!({"values": {"dept": "eng"}}),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    // Unknown tenant.
    let resp = call(
        &app,
        Method::GET,
        &format!("{API}/tenants/nope/attributes"),
        Some(&token),
        None,
    )
    .await;
    assert_problem(&resp, 404);
}
