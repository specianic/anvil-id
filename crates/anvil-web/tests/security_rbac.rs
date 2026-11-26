//! RBAC negative tests (security map): tenant isolation of roles and assignments, admin scopes
//! bounded by system roles (Q3), no escalation through role definitions or assignments, the
//! last-administrator guard on every path, route scopes, and claim-mapping collisions.

mod admin_support;
mod support;
mod token_support;

use admin_support::{API, admin_token, assert_field_error, assert_problem, call};
use anvil_core::model::{
    ClientAuthMethod, NewRole, Role, RoleId, SYSTEM_ADMIN_ROLE, TenantId, User, UserStatus,
};
use axum::http::Method;
use serde_json::{Value, json};
use support::{TestApp, json as body_json};
use token_support::*;

fn system(app: &TestApp) -> TenantId {
    app.system.as_ref().expect("installed").tenant.id
}

async fn role(app: &TestApp, tenant: TenantId, name: &str, perms: &[&str]) -> Role {
    app.storage()
        .roles()
        .create(
            tenant,
            &NewRole {
                id: RoleId::new_v7(),
                org_id: None,
                name: name.into(),
                description: String::new(),
                permissions: perms.iter().map(|p| (*p).to_owned()).collect(),
                created_at: app.clock_now(),
            },
        )
        .await
        .expect("role created")
}

async fn administrator(app: &TestApp) -> Role {
    app.storage()
        .roles()
        .get_by_name(system(app), SYSTEM_ADMIN_ROLE)
        .await
        .expect("lookup")
        .expect("install creates the administrator role")
}

async fn assign(app: &TestApp, tenant: TenantId, role: &Role, user: &User) {
    assert!(
        app.storage()
            .roles()
            .assign(tenant, role.id, user.id, app.clock_now())
            .await
            .expect("assign")
    );
}

async fn role_names(app: &TestApp, tenant: TenantId, user: &User) -> Vec<String> {
    app.storage()
        .roles()
        .roles_for_user(tenant, user.id)
        .await
        .expect("roles")
        .into_iter()
        .map(|r| r.name)
        .collect()
}

/// A system administrator (holder of the `administrator` role).
async fn system_admin(app: &TestApp, email: &str) -> User {
    let user = seed_user(app, system(app), email).await;
    assign(app, system(app), &administrator(app).await, &user).await;
    user
}

/// The token response of a code flow for `user` at `/t/{slug}/token` requesting `scope`.
async fn user_tokens(
    app: &TestApp,
    tenant: TenantId,
    slug: &str,
    user: &User,
    scope: &str,
) -> Value {
    let mut input = web_input(ClientAuthMethod::ClientSecretBasic);
    input.scopes = ["openid", "admin:read", "admin:write", "admin:users:read"]
        .map(String::from)
        .to_vec();
    let rp = register(app, tenant, input).await;
    let session = seed_session(app, tenant, user).await;
    let code = issue_code(app, tenant, &rp, &session, &params(scope, Some(CHALLENGE))).await;
    let resp = token_at(
        app,
        &format!("/t/{slug}/token"),
        &rp.auth(),
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", REDIRECT),
            ("code_verifier", VERIFIER),
        ],
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    body_json(&resp)
}

fn access_token(body: &Value) -> &str {
    body["access_token"].as_str().expect("access_token")
}

// ---------------------------------------------------------------------------------------------
// Tenant isolation
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn assigning_another_tenants_role_is_refused() {
    let app = TestApp::new().await;
    let acme = acme(&app).await;
    role(&app, acme.id, "editor", &["docs:write"]).await;
    let user = seed_user(&app, default_tenant(&app), "ada@example.test").await;
    let token = admin_token(&app, "admin:write").await;

    let resp = call(
        &app,
        Method::PUT,
        &format!("{API}/tenants/default/users/{}/roles/editor", user.id),
        Some(&token),
        None,
    )
    .await;
    assert_problem(&resp, 404);
    assert!(
        role_names(&app, default_tenant(&app), &user)
            .await
            .is_empty()
    );
    assert!(role_names(&app, acme.id, &user).await.is_empty());
}

#[tokio::test]
async fn assigning_to_another_tenants_user_is_refused() {
    let app = TestApp::new().await;
    let acme = acme(&app).await;
    role(&app, default_tenant(&app), "editor", &["docs:write"]).await;
    let acme_user = seed_user(&app, acme.id, "ada@example.test").await;
    let token = admin_token(&app, "admin:write").await;

    // Addressed through the role's tenant: the user is not in it.
    let resp = call(
        &app,
        Method::PUT,
        &format!("{API}/tenants/default/users/{}/roles/editor", acme_user.id),
        Some(&token),
        None,
    )
    .await;
    assert_problem(&resp, 404);
    // Addressed through the user's tenant: the role is not in it.
    let resp = call(
        &app,
        Method::PUT,
        &format!("{API}/tenants/acme/users/{}/roles/editor", acme_user.id),
        Some(&token),
        None,
    )
    .await;
    assert_problem(&resp, 404);
    assert!(role_names(&app, acme.id, &acme_user).await.is_empty());
}

// ---------------------------------------------------------------------------------------------
// Admin scopes bounded by system roles (Q3)
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn admin_scope_requires_role_permission() {
    let app = TestApp::new().await;
    let sys = system(&app);
    let user = seed_user(&app, sys, "helpdesk@example.test").await;
    let helpdesk = role(&app, sys, "helpdesk", &["admin:users:read"]).await;
    assign(&app, sys, &helpdesk, &user).await;

    let body = user_tokens(&app, sys, "system", &user, "openid admin:write").await;
    assert_eq!(body["scope"], "admin:users:read openid", "{body}");
    let token = access_token(&body);
    // The token reads users but cannot write them or read anything else.
    let resp = call(
        &app,
        Method::GET,
        &format!("{API}/tenants/default/users"),
        Some(token),
        None,
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let resp = call(
        &app,
        Method::POST,
        &format!("{API}/tenants/default/users"),
        Some(token),
        Some(json!({"email": "x@example.test", "invite": true})),
    )
    .await;
    assert_problem(&resp, 403);
    let resp = call(
        &app,
        Method::GET,
        &format!("{API}/tenants"),
        Some(token),
        None,
    )
    .await;
    assert_problem(&resp, 403);
}

#[tokio::test]
async fn user_without_roles_gets_no_admin_scope() {
    let app = TestApp::new().await;
    let sys = system(&app);
    let user = seed_user(&app, sys, "nobody@example.test").await;
    let body = user_tokens(&app, sys, "system", &user, "openid admin:read admin:write").await;
    assert_eq!(body["scope"], "openid", "{body}");
    assert_eq!(jwt_claims(access_token(&body))["scope"], "openid");
    let resp = call(
        &app,
        Method::GET,
        &format!("{API}/tenants"),
        Some(access_token(&body)),
        None,
    )
    .await;
    assert_problem(&resp, 403);
}

#[tokio::test]
async fn non_system_tenant_role_never_grants_admin_scopes() {
    let app = TestApp::new().await;
    let acme = acme(&app).await;
    let user = seed_user(&app, acme.id, "ada@example.test").await;
    let fake_admin = role(&app, acme.id, "fake-admin", &["admin:write"]).await;
    assign(&app, acme.id, &fake_admin, &user).await;

    let body = user_tokens(&app, acme.id, "acme", &user, "openid").await;
    let at = jwt_claims(access_token(&body));
    assert_eq!(at["scope"], "openid", "{at}");
    assert!(
        !body["scope"].as_str().unwrap().contains("admin:"),
        "{body}"
    );
    // The permission is only a claim of the acme token; the admin API refuses the token.
    let resp = call(
        &app,
        Method::GET,
        &format!("{API}/tenants"),
        Some(access_token(&body)),
        None,
    )
    .await;
    assert_problem(&resp, 401);
}

// ---------------------------------------------------------------------------------------------
// Escalation
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn role_assignment_beyond_caller_scopes_is_refused() {
    let app = TestApp::new().await;
    let sys = system(&app);
    system_admin(&app, "root@example.test").await;
    let target = seed_user(&app, sys, "mallory@example.test").await;
    let users_writer = admin_token(&app, "admin:users:write").await;

    // Assigning the administrator role (admin:write) with an admin:users:write token.
    let resp = call(
        &app,
        Method::PUT,
        &format!(
            "{API}/tenants/system/users/{}/roles/{SYSTEM_ADMIN_ROLE}",
            target.id
        ),
        Some(&users_writer),
        None,
    )
    .await;
    assert_problem(&resp, 403);
    assert!(role_names(&app, sys, &target).await.is_empty());

    // A system role within the caller's scopes can be assigned.
    role(&app, sys, "helpdesk", &["admin:users:read"]).await;
    let resp = call(
        &app,
        Method::PUT,
        &format!("{API}/tenants/system/users/{}/roles/helpdesk", target.id),
        Some(&users_writer),
        None,
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());

    // Nor can it take the administrator role away from others.
    let other = system_admin(&app, "second@example.test").await;
    let resp = call(
        &app,
        Method::DELETE,
        &format!(
            "{API}/tenants/system/users/{}/roles/{SYSTEM_ADMIN_ROLE}",
            other.id
        ),
        Some(&users_writer),
        None,
    )
    .await;
    assert_problem(&resp, 403);
    assert_eq!(role_names(&app, sys, &other).await, [SYSTEM_ADMIN_ROLE]);

    // Creating or editing a system role carrying admin:write needs admin:write.
    let settings_writer = admin_token(&app, "admin:settings:write admin:users:write").await;
    let resp = call(
        &app,
        Method::POST,
        &format!("{API}/tenants/system/roles"),
        Some(&settings_writer),
        Some(json!({"name": "shadow-admin", "permissions": ["admin:write"]})),
    )
    .await;
    assert_problem(&resp, 403);
    let resp = call(
        &app,
        Method::PATCH,
        &format!("{API}/tenants/system/roles/helpdesk"),
        Some(&settings_writer),
        Some(json!({"permissions": ["admin:write"]})),
    )
    .await;
    assert_problem(&resp, 403);
    let helpdesk = app
        .storage()
        .roles()
        .get_by_name(sys, "helpdesk")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(helpdesk.permissions, ["admin:users:read"]);
}

// ---------------------------------------------------------------------------------------------
// Last administrator
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn last_administrator_cannot_be_unassigned() {
    let app = TestApp::new().await;
    let admin = system_admin(&app, "root@example.test").await;
    // A blocked holder does not count as an administrator.
    let blocked = system_admin(&app, "blocked@example.test").await;
    app.storage()
        .users()
        .update(
            system(&app),
            blocked.id,
            &anvil_core::model::UserUpdate {
                status: Some(UserStatus::Blocked),
                ..Default::default()
            },
            app.clock_now(),
        )
        .await
        .unwrap();
    let token = admin_token(&app, "admin:write").await;
    let resp = call(
        &app,
        Method::DELETE,
        &format!(
            "{API}/tenants/system/users/{}/roles/{SYSTEM_ADMIN_ROLE}",
            admin.id
        ),
        Some(&token),
        None,
    )
    .await;
    let problem = assert_problem(&resp, 409);
    assert_eq!(problem["type"], "urn:anvilid:problem:conflict");
    assert_eq!(
        role_names(&app, system(&app), &admin).await,
        [SYSTEM_ADMIN_ROLE]
    );
}

#[tokio::test]
async fn last_administrator_role_cannot_be_deleted() {
    let app = TestApp::new().await;
    let admin = system_admin(&app, "root@example.test").await;
    let token = admin_token(&app, "admin:write").await;
    let path = format!("{API}/tenants/system/roles/{SYSTEM_ADMIN_ROLE}");

    let resp = call(&app, Method::DELETE, &path, Some(&token), None).await;
    assert_problem(&resp, 409);
    // Editing the permissions to drop admin:write is the same removal.
    let resp = call(
        &app,
        Method::PATCH,
        &path,
        Some(&token),
        Some(json!({"permissions": ["admin:read"]})),
    )
    .await;
    assert_problem(&resp, 409);
    assert_eq!(administrator(&app).await.permissions, ["admin:write"]);
    assert_eq!(
        role_names(&app, system(&app), &admin).await,
        [SYSTEM_ADMIN_ROLE]
    );

    // With an administrator through another role, both are allowed.
    let other = seed_user(&app, system(&app), "second@example.test").await;
    let ops = role(&app, system(&app), "ops-admin", &["admin:write"]).await;
    assign(&app, system(&app), &ops, &other).await;
    let resp = call(
        &app,
        Method::PATCH,
        &path,
        Some(&token),
        Some(json!({"permissions": ["admin:read"]})),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let resp = call(&app, Method::DELETE, &path, Some(&token), None).await;
    assert_eq!(resp.status, 204, "{}", resp.text());
}

#[tokio::test]
async fn last_administrator_cannot_be_deleted() {
    let app = TestApp::new().await;
    let admin = system_admin(&app, "root@example.test").await;
    let token = admin_token(&app, "admin:write").await;
    let resp = call(
        &app,
        Method::DELETE,
        &format!("{API}/tenants/system/users/{}", admin.id),
        Some(&token),
        None,
    )
    .await;
    assert_problem(&resp, 409);
    assert!(
        app.storage()
            .users()
            .get(system(&app), admin.id)
            .await
            .unwrap()
            .is_some()
    );

    let second = system_admin(&app, "second@example.test").await;
    let resp = call(
        &app,
        Method::DELETE,
        &format!("{API}/tenants/system/users/{}", admin.id),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(resp.status, 204, "{}", resp.text());
    let resp = call(
        &app,
        Method::DELETE,
        &format!("{API}/tenants/system/users/{}", second.id),
        Some(&token),
        None,
    )
    .await;
    assert_problem(&resp, 409);
}

#[tokio::test]
async fn last_administrator_cannot_be_disabled() {
    let app = TestApp::new().await;
    let admin = system_admin(&app, "root@example.test").await;
    let token = admin_token(&app, "admin:write").await;
    let path = format!("{API}/tenants/system/users/{}", admin.id);
    let resp = call(
        &app,
        Method::PATCH,
        &path,
        Some(&token),
        Some(json!({"status": "blocked"})),
    )
    .await;
    assert_problem(&resp, 409);
    let stored = app
        .storage()
        .users()
        .get(system(&app), admin.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.status, UserStatus::Active);
    // Other edits of the same user are not blocked.
    let resp = call(
        &app,
        Method::PATCH,
        &path,
        Some(&token),
        Some(json!({"email_verified": false})),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());

    // Users of other tenants are never guarded.
    let user = seed_user(&app, default_tenant(&app), "ada@example.test").await;
    let fake = role(&app, default_tenant(&app), "fake-admin", &["admin:write"]).await;
    assign(&app, default_tenant(&app), &fake, &user).await;
    let resp = call(
        &app,
        Method::PATCH,
        &format!("{API}/tenants/default/users/{}", user.id),
        Some(&token),
        Some(json!({"status": "blocked"})),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
}

// ---------------------------------------------------------------------------------------------
// Route scopes and claim mapping
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn role_routes_require_scopes() {
    let app = TestApp::new().await;
    let user = seed_user(&app, default_tenant(&app), "ada@example.test").await;
    role(&app, default_tenant(&app), "editor", &["docs:write"]).await;
    let roles = format!("{API}/tenants/default/roles");
    let assignment = format!("{API}/tenants/default/users/{}/roles/editor", user.id);

    // No token, garbage token.
    let resp = call(&app, Method::GET, &roles, None, None).await;
    assert_problem(&resp, 401);
    let resp = call(&app, Method::GET, &roles, Some("garbage"), None).await;
    assert_problem(&resp, 401);

    // Read scopes cannot write.
    let settings_read = admin_token(&app, "admin:settings:read").await;
    let resp = call(&app, Method::GET, &roles, Some(&settings_read), None).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let resp = call(
        &app,
        Method::POST,
        &roles,
        Some(&settings_read),
        Some(json!({"name": "x"})),
    )
    .await;
    assert_problem(&resp, 403);
    let resp = call(
        &app,
        Method::DELETE,
        &format!("{roles}/editor"),
        Some(&settings_read),
        None,
    )
    .await;
    assert_problem(&resp, 403);
    let users_read = admin_token(&app, "admin:users:read").await;
    let resp = call(&app, Method::PUT, &assignment, Some(&users_read), None).await;
    assert_problem(&resp, 403);
    let resp = call(&app, Method::DELETE, &assignment, Some(&users_read), None).await;
    assert_problem(&resp, 403);
    // The assignment scope does not open role definitions, and vice versa.
    let resp = call(&app, Method::GET, &roles, Some(&users_read), None).await;
    assert_problem(&resp, 403);
    let resp = call(
        &app,
        Method::GET,
        &format!("{roles}/editor/users"),
        Some(&settings_read),
        None,
    )
    .await;
    assert_problem(&resp, 403);

    // A token of another tenant (right shape, wrong issuer) is refused.
    let acme = acme(&app).await;
    let acme_user = seed_user(&app, acme.id, "ada@example.test").await;
    let body = user_tokens(&app, acme.id, "acme", &acme_user, "openid admin:write").await;
    let resp = call(&app, Method::GET, &roles, Some(access_token(&body)), None).await;
    assert_problem(&resp, 401);

    // System role definitions need admin:write even with the settings write scope.
    let settings_write = admin_token(&app, "admin:settings:write").await;
    let resp = call(
        &app,
        Method::POST,
        &format!("{API}/tenants/system/roles"),
        Some(&settings_write),
        Some(json!({"name": "plain"})),
    )
    .await;
    assert_problem(&resp, 403);
    assert!(
        role_names(&app, default_tenant(&app), &user)
            .await
            .is_empty()
    );
}

#[tokio::test]
async fn claim_mapping_collision_rejected() {
    let app = TestApp::new().await;
    let token = admin_token(&app, "admin:tenants:write").await;
    for claim in ["sub", "email", "Sub", "iss", "scope"] {
        let resp = call(
            &app,
            Method::PATCH,
            &format!("{API}/tenants/default"),
            Some(&token),
            Some(json!({"settings": {"claims": {"roles": {
                "claim": claim, "tokens": ["access_token"]
            }}}})),
        )
        .await;
        assert_field_error(&resp, "claim");
    }
    // roles and permissions may not share a claim either.
    let resp = call(
        &app,
        Method::PATCH,
        &format!("{API}/tenants/default"),
        Some(&token),
        Some(json!({"settings": {"claims": {"permissions": {
            "claim": "roles", "tokens": ["access_token"]
        }}}})),
    )
    .await;
    assert_field_error(&resp, "claim");
    let stored = app
        .storage()
        .tenants()
        .get(default_tenant(&app))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.settings.claims, Default::default());

    // Creating a tenant with a colliding mapping is refused too.
    let token = admin_token(&app, "admin:tenants:write").await;
    let resp = call(
        &app,
        Method::POST,
        &format!("{API}/tenants"),
        Some(&token),
        Some(
            json!({"slug": "beta", "display_name": "Beta", "settings": {"claims": {
                "roles": {"claim": "email", "tokens": ["id_token"], "scope": null},
                "permissions": null
            }}}),
        ),
    )
    .await;
    assert_field_error(&resp, "claim");
}
