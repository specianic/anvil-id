//! Admin-defined attributes in tokens, end to end (AUTH-14): a definition with a claim rule and
//! a user value written through the admin API reach the access token; narrowing the schema so
//! the stored value no longer validates drops the claim from new tokens while the stored value
//! stays unchanged.

mod admin_support;
mod support;
mod token_support;

use admin_support::{API, admin_token, call};
use anvil_core::model::{ClientAuthMethod, TenantId, User};
use axum::http::Method;
use serde_json::{Value, json};
use support::{TestApp, json as body_json};
use token_support::*;

/// A fresh code for `user` exchanged at `/token`; the access token's claims.
async fn access_token_claims(app: &TestApp, tenant: TenantId, rp: &Rp, user: &User) -> Value {
    let session = seed_session(app, tenant, user).await;
    let code = issue_code(
        app,
        tenant,
        rp,
        &session,
        &params("openid", Some(CHALLENGE)),
    )
    .await;
    let resp = exchange(app, rp, &code).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    jwt_claims(
        body_json(&resp)["access_token"]
            .as_str()
            .expect("access_token"),
    )
}

async fn put_definition(app: &TestApp, token: &str, schema: Value) {
    let resp = call(
        app,
        Method::PUT,
        &format!("{API}/tenants/default/attributes/department"),
        Some(token),
        Some(json!({
            "schema": schema,
            "claim": {"claim": "department", "tokens": ["access_token"], "scope": null}
        })),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
}

#[tokio::test]
async fn admin_defined_attribute_follows_the_current_schema_into_tokens() {
    let app = TestApp::new().await;
    let settings = admin_token(&app, "admin:settings:write").await;
    let users = admin_token(&app, "admin:users:write").await;
    let tenant = default_tenant(&app);
    let rp = register(&app, tenant, web_input(ClientAuthMethod::ClientSecretBasic)).await;
    let user = seed_user(&app, tenant, "ada@example.test").await;
    let values_path = format!("{API}/tenants/default/users/{}/attributes", user.id);

    put_definition(
        &app,
        &settings,
        json!({"type": "string", "enum": ["eng", "sales"]}),
    )
    .await;
    let resp = call(
        &app,
        Method::PUT,
        &values_path,
        Some(&users),
        Some(json!({"values": {"department": "eng"}})),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());

    let at = access_token_claims(&app, tenant, &rp, &user).await;
    assert_eq!(at["department"], "eng", "{at}");

    // Narrow the schema: "eng" is no longer allowed.
    put_definition(
        &app,
        &settings,
        json!({"type": "string", "enum": ["sales"]}),
    )
    .await;
    let at = access_token_claims(&app, tenant, &rp, &user).await;
    assert!(
        at.get("department").is_none(),
        "a value the current schema rejects is omitted: {at}"
    );

    // The stored value is untouched.
    let resp = call(&app, Method::GET, &values_path, Some(&users), None).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(body_json(&resp)["values"], json!({"department": "eng"}));

    // Widening the schema again brings the claim back without rewriting the value.
    put_definition(
        &app,
        &settings,
        json!({"type": "string", "enum": ["eng", "sales"]}),
    )
    .await;
    let at = access_token_claims(&app, tenant, &rp, &user).await;
    assert_eq!(at["department"], "eng", "{at}");

    // Deleting the definition drops the claim; the value stays stored.
    let resp = call(
        &app,
        Method::DELETE,
        &format!("{API}/tenants/default/attributes/department"),
        Some(&settings),
        None,
    )
    .await;
    assert_eq!(resp.status, 204, "{}", resp.text());
    let at = access_token_claims(&app, tenant, &rp, &user).await;
    assert!(at.get("department").is_none(), "{at}");
    let resp = call(&app, Method::GET, &values_path, Some(&users), None).await;
    assert_eq!(body_json(&resp)["values"], json!({"department": "eng"}));
}
