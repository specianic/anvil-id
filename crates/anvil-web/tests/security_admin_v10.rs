//! Security tests for the 1.0 organization admin routes (plan 06-12): the scope matrix of every
//! new route, organizations never in the system tenant, no admin permissions in organizations,
//! and the org-admin principal of decision Q1 (isolation to its own org and tenant, audience,
//! scope, org binding, live membership and permission, opaque tokens refused), direct member
//! adds refused for org admins, the last-org-admin lockout with the tenant-admin recovery path,
//! and invitation privacy.

mod admin_support;
mod support;
mod token_support;

use admin_support::{
    API, OrgTokenOpts, add_member, admin_token, assert_problem, call, create_org, create_role,
    org_admin_token, org_admin_token_with,
};
use anvil_core::model::{Organization, Role, Tenant, User};
use axum::http::Method;
use serde_json::{Value, json};
use support::{TestApp, json as body_json};
use token_support::{acme, seed_user};

async fn app() -> TestApp {
    TestApp::with(|c| c.rate_limits.enabled = false).await
}

fn default_tenant(app: &TestApp) -> Tenant {
    app.default.as_ref().expect("installed").tenant.clone()
}

fn org_path(tenant: &str, org: &str) -> String {
    format!("{API}/tenants/{tenant}/organizations/{org}")
}

/// An org with one org admin (org-owned role `org-admins` carrying `org:admin`) and their token.
struct OrgFixture {
    tenant: Tenant,
    org: Organization,
    admin: User,
    admin_role: Role,
    token: String,
}

async fn org_with_admin(app: &TestApp, tenant: &Tenant, slug: &str, email: &str) -> OrgFixture {
    let org = create_org(app, tenant.id, slug).await;
    let admin_role = create_role(app, tenant.id, Some(org.id), "org-admins", &["org:admin"]).await;
    let admin = seed_user(app, tenant.id, email).await;
    add_member(app, tenant.id, org.id, admin.id, &[admin_role.id]).await;
    let token = org_admin_token(app, tenant, org.id, admin.id).await.token;
    OrgFixture {
        tenant: tenant.clone(),
        org,
        admin,
        admin_role,
        token,
    }
}

impl OrgFixture {
    fn path(&self, rest: &str) -> String {
        format!("{}{rest}", org_path(&self.tenant.slug, &self.org.slug))
    }
}

// ---------------------------------------------------------------------------------------------
// Scope matrix
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn v10_admin_routes_require_scopes() {
    let app = app().await;
    let tenant = default_tenant(&app);
    let org = create_org(&app, tenant.id, "acme").await;
    let user = seed_user(&app, tenant.id, "ada@example.test").await;
    add_member(&app, tenant.id, org.id, user.id, &[]).await;
    let orgs = format!("{API}/tenants/default/organizations");
    let o = format!("{orgs}/acme");
    let inv = uuid::Uuid::now_v7();
    let u = user.id;
    // (method, path, body, is_write)
    let routes: Vec<(Method, String, Option<Value>, bool)> = vec![
        (Method::GET, orgs.clone(), None, false),
        (
            Method::POST,
            orgs.clone(),
            Some(json!({"slug": "zz", "display_name": "Z"})),
            true,
        ),
        (Method::GET, o.clone(), None, false),
        (
            Method::PATCH,
            o.clone(),
            Some(json!({"display_name": "Y"})),
            true,
        ),
        (Method::DELETE, format!("{orgs}/nope"), None, true),
        (Method::GET, format!("{o}/members"), None, false),
        (
            Method::POST,
            format!("{o}/members"),
            Some(json!({"user_id": u.0})),
            true,
        ),
        (
            Method::DELETE,
            format!("{o}/members/{}", uuid::Uuid::now_v7()),
            None,
            true,
        ),
        (Method::GET, format!("{o}/members/{u}/roles"), None, false),
        (Method::PUT, format!("{o}/members/{u}/roles/x"), None, true),
        (
            Method::DELETE,
            format!("{o}/members/{u}/roles/x"),
            None,
            true,
        ),
        (Method::GET, format!("{o}/roles"), None, false),
        (
            Method::POST,
            format!("{o}/roles"),
            Some(json!({"name": "r1"})),
            true,
        ),
        (Method::GET, format!("{o}/roles/x"), None, false),
        (
            Method::PATCH,
            format!("{o}/roles/x"),
            Some(json!({"description": "d"})),
            true,
        ),
        (Method::DELETE, format!("{o}/roles/x"), None, true),
        (Method::GET, format!("{o}/invitations"), None, false),
        (
            Method::POST,
            format!("{o}/invitations"),
            Some(json!({"email": "x@example.test"})),
            true,
        ),
        (Method::DELETE, format!("{o}/invitations/{inv}"), None, true),
    ];
    assert_scope_matrix(&app, routes).await;
}

/// For each `(method, path, body, is_write)`: no token is 401 with a challenge, another
/// resource's scope is 403, the read scope on a write is 403, and the route's own scope passes
/// authorization.
async fn assert_scope_matrix(app: &TestApp, routes: Vec<(Method, String, Option<Value>, bool)>) {
    let read = admin_token(app, "admin:organizations:read").await;
    let write = admin_token(app, "admin:organizations:write").await;
    let other = admin_token(
        app,
        "admin:users:write admin:settings:write admin:clients:write",
    )
    .await;
    for (method, path, body, is_write) in routes {
        let what = format!("{method} {path}");
        let resp = call(app, method.clone(), &path, None, body.clone()).await;
        assert_problem(&resp, 401);
        assert!(resp.header("www-authenticate").is_some(), "{what}");
        let resp = call(app, method.clone(), &path, Some(&other), body.clone()).await;
        assert_eq!(
            resp.status,
            403,
            "{what} with another resource's scope: {}",
            resp.text()
        );
        if is_write {
            let resp = call(app, method.clone(), &path, Some(&read), body.clone()).await;
            assert_eq!(
                resp.status,
                403,
                "{what} with the read scope: {}",
                resp.text()
            );
        }
        let granted = if is_write { &write } else { &read };
        let resp = call(app, method.clone(), &path, Some(granted), body).await;
        assert!(
            resp.status != 401 && resp.status != 403,
            "{what} with its scope: {} {}",
            resp.status,
            resp.text()
        );
    }
}

#[tokio::test]
async fn v10_org_sso_routes_require_scopes() {
    let app = TestApp::with(|c| {
        c.rate_limits.enabled = false;
        c.saml_experimental = true;
    })
    .await;
    let tenant = default_tenant(&app);
    create_org(&app, tenant.id, "acme").await;
    let o = format!("{API}/tenants/default/organizations/acme");
    let id = uuid::Uuid::now_v7();
    let oidc = json!({
        "slug": "acme-oidc", "display_name": "Acme",
        "config": {"type": "oidc", "issuer": "https://login.acme-corp.com", "client_id": "c"},
    });
    let routes: Vec<(Method, String, Option<Value>, bool)> = vec![
        (Method::GET, format!("{o}/connections"), None, false),
        (Method::POST, format!("{o}/connections"), Some(oidc), true),
        (
            Method::POST,
            format!("{o}/connections/saml-metadata"),
            Some(json!({"xml": "<x/>"})),
            true,
        ),
        (Method::GET, format!("{o}/connections/{id}"), None, false),
        (
            Method::PATCH,
            format!("{o}/connections/{id}"),
            Some(json!({"display_name": "x"})),
            true,
        ),
        (Method::DELETE, format!("{o}/connections/{id}"), None, true),
        (
            Method::PUT,
            format!("{o}/connections/{id}/secret"),
            Some(json!({"secret": null})),
            true,
        ),
        (Method::GET, format!("{o}/domains"), None, false),
        (
            Method::POST,
            format!("{o}/domains"),
            Some(json!({"domain": "acme-corp.com"})),
            true,
        ),
        (Method::GET, format!("{o}/domains/{id}"), None, false),
        (
            Method::PATCH,
            format!("{o}/domains/{id}"),
            Some(json!({"routing": false})),
            true,
        ),
        (Method::DELETE, format!("{o}/domains/{id}"), None, true),
        (Method::POST, format!("{o}/domains/{id}/verify"), None, true),
        (Method::GET, format!("{o}/branding"), None, false),
        (
            Method::PUT,
            format!("{o}/branding"),
            Some(json!({"tokens": {}})),
            true,
        ),
        (Method::DELETE, format!("{o}/branding"), None, true),
        (
            Method::PUT,
            format!("{o}/branding/logo"),
            Some(json!({"data": "AA=="})),
            true,
        ),
        (Method::DELETE, format!("{o}/branding/logo"), None, true),
        (
            Method::POST,
            format!("{o}/branding/preview"),
            Some(json!({"tokens": {}})),
            true,
        ),
        (
            Method::POST,
            format!("{o}/branding/publish"),
            Some(json!({"token": "x"})),
            true,
        ),
    ];
    assert_scope_matrix(&app, routes).await;
}

#[tokio::test]
async fn org_create_refused_in_system_tenant() {
    let app = app().await;
    let token = admin_token(&app, "admin:write").await;
    let resp = call(
        &app,
        Method::POST,
        &format!("{API}/tenants/system/organizations"),
        Some(&token),
        Some(json!({"slug": "acme", "display_name": "Acme"})),
    )
    .await;
    let body = assert_problem(&resp, 422);
    assert_eq!(body["errors"][0]["field"], "tenant", "{body}");
    let system = app.system.as_ref().unwrap().tenant.id;
    assert!(
        app.storage()
            .organizations()
            .get_by_slug(system, "acme")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn org_role_with_admin_permission_refused() {
    let app = app().await;
    let token = admin_token(&app, "admin:write").await;
    let tenant = default_tenant(&app);
    let org = create_org(&app, tenant.id, "acme").await;
    let roles = format!("{}/roles", org_path("default", "acme"));
    for perm in ["admin:write", "admin:users:read", "admin", "admin:future"] {
        let resp = call(
            &app,
            Method::POST,
            &roles,
            Some(&token),
            Some(json!({"name": "bad", "permissions": ["docs:read", perm]})),
        )
        .await;
        assert_problem(&resp, 422);
    }
    // `org:admin` is a valid org-role permission.
    let ok = call(
        &app,
        Method::POST,
        &roles,
        Some(&token),
        Some(json!({"name": "admins", "permissions": ["org:admin"]})),
    )
    .await;
    assert_eq!(ok.status, 201, "{}", ok.text());
    let resp = call(
        &app,
        Method::PATCH,
        &format!("{roles}/admins"),
        Some(&token),
        Some(json!({"permissions": ["org:admin", "admin:write"]})),
    )
    .await;
    assert_problem(&resp, 422);
    // A tenant role carrying an admin permission cannot be assigned in an org.
    let ada = seed_user(&app, tenant.id, "ada@example.test").await;
    add_member(&app, tenant.id, org.id, ada.id, &[]).await;
    create_role(&app, tenant.id, None, "inert-admin", &["admin:write"]).await;
    let resp = call(
        &app,
        Method::PUT,
        &format!(
            "{}/members/{}/roles/inert-admin",
            org_path("default", "acme"),
            ada.id
        ),
        Some(&token),
        None,
    )
    .await;
    assert_problem(&resp, 422);
    assert!(
        app.storage()
            .roles()
            .roles_for_user_in_org(tenant.id, ada.id, org.id)
            .await
            .unwrap()
            .is_empty()
    );
}

// ---------------------------------------------------------------------------------------------
// Org-admin principal (decision Q1)
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn org_admin_token_manages_own_org() {
    let app = app().await;
    let tenant = default_tenant(&app);
    let f = org_with_admin(&app, &tenant, "acme", "admin@example.test").await;
    let bob = seed_user(&app, tenant.id, "bob@example.test").await;
    add_member(&app, tenant.id, f.org.id, bob.id, &[]).await;
    let t = Some(f.token.as_str());

    let resp = call(&app, Method::GET, &f.path(""), t, None).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(body_json(&resp)["id"], f.org.id.to_string());
    // By id as well as by slug.
    let by_id = call(
        &app,
        Method::GET,
        &org_path("default", &f.org.id.to_string()),
        t,
        None,
    )
    .await;
    assert_eq!(by_id.status, 200, "{}", by_id.text());
    let resp = call(&app, Method::GET, &f.path("/members"), t, None).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(body_json(&resp)["items"].as_array().unwrap().len(), 2);

    let resp = call(
        &app,
        Method::POST,
        &f.path("/roles"),
        t,
        Some(json!({"name": "editors", "permissions": ["docs:write"]})),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    let resp = call(
        &app,
        Method::PUT,
        &f.path(&format!("/members/{}/roles/editors", bob.id)),
        t,
        None,
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let resp = call(&app, Method::GET, &f.path("/roles"), t, None).await;
    assert_eq!(resp.status, 200);

    let resp = call(
        &app,
        Method::POST,
        &f.path("/invitations"),
        t,
        Some(json!({"email": "carol@example.test"})),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    let id = body_json(&resp)["id"].as_str().unwrap().to_owned();
    let resp = call(&app, Method::GET, &f.path("/invitations"), t, None).await;
    assert_eq!(resp.status, 200);
    let resp = call(
        &app,
        Method::DELETE,
        &f.path(&format!("/invitations/{id}")),
        t,
        None,
    )
    .await;
    assert_eq!(resp.status, 204, "{}", resp.text());

    let resp = call(
        &app,
        Method::DELETE,
        &f.path(&format!("/members/{}", bob.id)),
        t,
        None,
    )
    .await;
    assert_eq!(resp.status, 204, "{}", resp.text());

    // Audited as the org admin (a tenant user), not as an installation admin.
    let events = app
        .storage()
        .audit()
        .query(
            tenant.id,
            &anvil_core::model::AuditQuery {
                action: Some(anvil_core::model::AuditAction::OrgMemberRemoved),
                limit: 10,
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .items;
    assert_eq!(
        events[0].actor,
        anvil_core::model::AuditActor::user(f.admin.id)
    );
}

#[tokio::test]
async fn org_admin_token_refused_for_other_org() {
    let app = app().await;
    let tenant = default_tenant(&app);
    let f = org_with_admin(&app, &tenant, "acme", "admin@example.test").await;
    let other = create_org(&app, tenant.id, "globex").await;
    let t = Some(f.token.as_str());
    for key in [
        "globex".to_owned(),
        other.id.to_string(),
        "unknown-org".to_owned(),
    ] {
        let o = org_path("default", &key);
        for (method, path, body) in [
            (Method::GET, o.clone(), None),
            (Method::GET, format!("{o}/members"), None),
            (Method::GET, format!("{o}/roles"), None),
            (
                Method::POST,
                format!("{o}/roles"),
                Some(json!({"name": "x"})),
            ),
            (Method::GET, format!("{o}/invitations"), None),
            (
                Method::POST,
                format!("{o}/invitations"),
                Some(json!({"email": "x@example.test"})),
            ),
            (Method::DELETE, format!("{o}/members/{}", f.admin.id), None),
            // 06-17: connections and domains.
            (Method::GET, format!("{o}/connections"), None),
            (
                Method::POST,
                format!("{o}/connections"),
                Some(json!({
                    "slug": "x", "display_name": "X",
                    "config": {"type": "oidc", "issuer": "https://idp.x.com", "client_id": "c"},
                })),
            ),
            (
                Method::POST,
                format!("{o}/connections/saml-metadata"),
                Some(json!({"xml": "<x/>"})),
            ),
            (Method::GET, format!("{o}/domains"), None),
            (
                Method::POST,
                format!("{o}/domains"),
                Some(json!({"domain": "evil-corp.com"})),
            ),
            (Method::GET, format!("{o}/branding"), None),
            (
                Method::PUT,
                format!("{o}/branding"),
                Some(json!({"tokens": {}})),
            ),
        ] {
            let resp = call(&app, method.clone(), &path, t, body).await;
            assert_problem(&resp, 403);
            let _ = method;
        }
    }
    assert!(
        app.storage()
            .roles()
            .list_org_roles(tenant.id, other.id)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn org_admin_token_refused_for_other_tenant() {
    let app = app().await;
    let tenant = default_tenant(&app);
    let f = org_with_admin(&app, &tenant, "acme", "admin@example.test").await;
    // Tenant `acme` has an org with the same slug and the same id string cannot exist there.
    let acme_tenant = acme(&app).await;
    let g = org_with_admin(&app, &acme_tenant, "acme", "admin@acme.test").await;
    for (token, path) in [
        (&f.token, org_path("acme", "acme")),
        (&f.token, org_path("acme", &f.org.id.to_string())),
        (&g.token, org_path("default", "acme")),
        (&g.token, org_path("default", &g.org.id.to_string())),
    ] {
        for rest in ["", "/members", "/roles", "/invitations"] {
            let resp = call(
                &app,
                Method::GET,
                &format!("{path}{rest}"),
                Some(token),
                None,
            )
            .await;
            assert_problem(&resp, 401);
        }
    }
    // Each still works at home.
    let resp = call(&app, Method::GET, &g.path("/members"), Some(&g.token), None).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
}

#[tokio::test]
async fn org_admin_token_refused_on_tenant_routes() {
    let app = app().await;
    let tenant = default_tenant(&app);
    let f = org_with_admin(&app, &tenant, "acme", "admin@example.test").await;
    let t = Some(f.token.as_str());
    let base = format!("{API}/tenants/default");
    for (method, path, body) in [
        (Method::GET, format!("{base}/users"), None),
        (Method::GET, format!("{base}/users/{}", f.admin.id), None),
        (Method::GET, format!("{base}/clients"), None),
        (Method::GET, format!("{base}/connections"), None),
        (Method::GET, format!("{base}/roles"), None),
        (Method::GET, format!("{base}/audit-events"), None),
        (Method::GET, format!("{base}/organizations"), None),
        (
            Method::POST,
            format!("{base}/organizations"),
            Some(json!({"slug": "new-org", "display_name": "New"})),
        ),
        (
            Method::PUT,
            format!("{base}/users/{}/roles/org-admins", f.admin.id),
            None,
        ),
    ] {
        let resp = call(&app, method.clone(), &path, t, body).await;
        assert_problem(&resp, 401);
    }
    // Its own org's record: read yes, update and delete no (tenant administrators only).
    let resp = call(
        &app,
        Method::PATCH,
        &f.path(""),
        t,
        Some(json!({"display_name": "Mine now"})),
    )
    .await;
    assert_problem(&resp, 403);
    let resp = call(&app, Method::DELETE, &f.path(""), t, None).await;
    assert_problem(&resp, 403);
    let org = app
        .storage()
        .organizations()
        .get(tenant.id, f.org.id)
        .await
        .unwrap()
        .expect("the org still exists");
    assert_eq!(org.display_name, f.org.display_name);
}

#[tokio::test]
async fn org_admin_token_refused_on_installation_routes() {
    let app = app().await;
    let tenant = default_tenant(&app);
    let f = org_with_admin(&app, &tenant, "acme", "admin@example.test").await;
    for (method, path, body) in [
        (Method::GET, format!("{API}/tenants"), None),
        (Method::GET, format!("{API}/tenants/default"), None),
        (Method::GET, format!("{API}/tenants/system"), None),
        (
            Method::POST,
            format!("{API}/tenants"),
            Some(json!({"slug": "evil", "display_name": "Evil"})),
        ),
        (
            Method::GET,
            format!("{API}/tenants/system/organizations"),
            None,
        ),
    ] {
        let resp = call(&app, method, &path, Some(&f.token), body).await;
        assert_problem(&resp, 401);
    }
}

#[tokio::test]
async fn org_admin_token_without_org_admin_scope_refused() {
    let app = app().await;
    let tenant = default_tenant(&app);
    let f = org_with_admin(&app, &tenant, "acme", "admin@example.test").await;
    let token = org_admin_token_with(
        &app,
        &tenant,
        f.org.id,
        f.admin.id,
        OrgTokenOpts {
            scope: "openid profile".to_owned(),
            ..OrgTokenOpts::default()
        },
    )
    .await
    .token;
    let resp = call(&app, Method::GET, &f.path("/members"), Some(&token), None).await;
    assert_problem(&resp, 403);
}

#[tokio::test]
async fn org_admin_token_with_mismatched_org_id_refused() {
    let app = app().await;
    let tenant = default_tenant(&app);
    let f = org_with_admin(&app, &tenant, "acme", "admin@example.test").await;
    let other = create_org(&app, tenant.id, "globex").await;
    // The admin is also an org admin of globex, but this token's family is bound to acme.
    add_member(&app, tenant.id, other.id, f.admin.id, &[]).await;
    let globex_admins =
        create_role(&app, tenant.id, Some(other.id), "admins", &["org:admin"]).await;
    app.storage()
        .roles()
        .assign_in_org(
            tenant.id,
            globex_admins.id,
            f.admin.id,
            other.id,
            app_now(&app),
        )
        .await
        .unwrap();
    let token = org_admin_token_with(
        &app,
        &tenant,
        f.org.id,
        f.admin.id,
        OrgTokenOpts {
            org_claim: Some(other.id.to_string()),
            ..OrgTokenOpts::default()
        },
    )
    .await
    .token;
    // The claim names globex but the family is bound to acme: not a valid org-admin token.
    let resp = call(
        &app,
        Method::GET,
        &format!("{}/members", org_path("default", "globex")),
        Some(&token),
        None,
    )
    .await;
    assert_problem(&resp, 401);
    // On acme the claim does not match the path's org.
    let resp = call(&app, Method::GET, &f.path("/members"), Some(&token), None).await;
    assert_problem(&resp, 403);
    // A token without any org_id claim is refused too.
    let token = org_admin_token_with(
        &app,
        &tenant,
        f.org.id,
        f.admin.id,
        OrgTokenOpts {
            org_claim: Some(String::new()),
            ..OrgTokenOpts::default()
        },
    )
    .await
    .token;
    let resp = call(&app, Method::GET, &f.path("/members"), Some(&token), None).await;
    assert_problem(&resp, 403);
}

fn app_now(app: &TestApp) -> time::OffsetDateTime {
    use anvil_core::ports::Clock as _;
    app.clock().now()
}

#[tokio::test]
async fn org_admin_token_refused_after_membership_removed() {
    let app = app().await;
    let tenant = default_tenant(&app);
    let f = org_with_admin(&app, &tenant, "acme", "admin@example.test").await;
    let resp = call(&app, Method::GET, &f.path("/members"), Some(&f.token), None).await;
    assert_eq!(resp.status, 200);
    let admin = admin_token(&app, "admin:organizations:write").await;
    let resp = call(
        &app,
        Method::DELETE,
        &f.path(&format!("/members/{}", f.admin.id)),
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(resp.status, 204, "{}", resp.text());
    for rest in ["", "/members", "/invitations"] {
        let resp = call(&app, Method::GET, &f.path(rest), Some(&f.token), None).await;
        assert_problem(&resp, 401);
    }
}

#[tokio::test]
async fn org_admin_opaque_token_refused() {
    let app = app().await;
    let tenant = default_tenant(&app);
    let f = org_with_admin(&app, &tenant, "acme", "admin@example.test").await;
    let token = org_admin_token_with(
        &app,
        &tenant,
        f.org.id,
        f.admin.id,
        OrgTokenOpts {
            opaque: true,
            ..OrgTokenOpts::default()
        },
    )
    .await
    .token;
    // The opaque token is a live token of the tenant (UserInfo-style verification accepts it).
    let found = app
        .storage()
        .grants()
        .find_access_token(
            tenant.id,
            &anvil_core::model::SecretHash(anvil_jose::encoding::secret_hash(&token)),
        )
        .await
        .unwrap();
    assert!(found.is_some());
    let resp = call(&app, Method::GET, &f.path("/members"), Some(&token), None).await;
    assert_problem(&resp, 401);
}

#[tokio::test]
async fn org_admin_cannot_add_member_directly() {
    let app = app().await;
    let tenant = default_tenant(&app);
    let f = org_with_admin(&app, &tenant, "acme", "admin@example.test").await;
    let bob = seed_user(&app, tenant.id, "bob@example.test").await;
    let resp = call(
        &app,
        Method::POST,
        &f.path("/members"),
        Some(&f.token),
        Some(json!({"user_id": bob.id.0})),
    )
    .await;
    assert_problem(&resp, 403);
    assert!(
        !app.storage()
            .organizations()
            .is_member(tenant.id, f.org.id, bob.id)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn org_admin_invitation_with_foreign_or_admin_role_refused() {
    let app = app().await;
    let tenant = default_tenant(&app);
    let f = org_with_admin(&app, &tenant, "acme", "admin@example.test").await;
    let other = create_org(&app, tenant.id, "globex").await;
    let foreign = create_role(&app, tenant.id, Some(other.id), "globex-role", &["x"]).await;
    let admin_role = create_role(&app, tenant.id, None, "inert-admin", &["admin:write"]).await;
    let resp = call(
        &app,
        Method::POST,
        &f.path("/invitations"),
        Some(&f.token),
        Some(json!({"email": "carol@example.test", "role_ids": [foreign.id.0]})),
    )
    .await;
    assert_problem(&resp, 404);
    let resp = call(
        &app,
        Method::POST,
        &f.path("/invitations"),
        Some(&f.token),
        Some(json!({"email": "carol@example.test", "role_ids": [admin_role.id.0]})),
    )
    .await;
    assert_problem(&resp, 422);
    // The same rule applies to assignments (one function).
    let resp = call(
        &app,
        Method::PUT,
        &f.path(&format!("/members/{}/roles/globex-role", f.admin.id)),
        Some(&f.token),
        None,
    )
    .await;
    assert_problem(&resp, 404);
    assert!(
        app.storage()
            .organizations()
            .list_invitations(tenant.id, f.org.id, true)
            .await
            .unwrap()
            .is_empty()
    );
    // Allowed: its own org role and tenant roles.
    let ok = call(
        &app,
        Method::POST,
        &f.path("/invitations"),
        Some(&f.token),
        Some(json!({"email": "carol@example.test", "role_ids": [f.admin_role.id.0]})),
    )
    .await;
    assert_eq!(ok.status, 201, "{}", ok.text());
}

#[tokio::test]
async fn org_admin_token_refused_after_org_admin_permission_removed() {
    let app = app().await;
    let tenant = default_tenant(&app);
    let f = org_with_admin(&app, &tenant, "acme", "admin@example.test").await;
    let resp = call(&app, Method::GET, &f.path("/members"), Some(&f.token), None).await;
    assert_eq!(resp.status, 200);
    // A tenant administrator takes the role away; the token is still unexpired.
    let admin = admin_token(&app, "admin:organizations:write").await;
    let resp = call(
        &app,
        Method::DELETE,
        &f.path(&format!("/members/{}/roles/org-admins", f.admin.id)),
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(resp.status, 204, "{}", resp.text());
    let resp = call(&app, Method::GET, &f.path("/members"), Some(&f.token), None).await;
    assert_problem(&resp, 403);
}

#[tokio::test]
async fn org_admin_token_without_admin_api_audience_refused() {
    let app = app().await;
    let tenant = default_tenant(&app);
    let f = org_with_admin(&app, &tenant, "acme", "admin@example.test").await;
    let token = org_admin_token_with(
        &app,
        &tenant,
        f.org.id,
        f.admin.id,
        OrgTokenOpts {
            admin_audience: false,
            ..OrgTokenOpts::default()
        },
    )
    .await
    .token;
    let claims = token_support::jwt_claims(&token);
    assert_ne!(claims["aud"], admin_support::admin_resource(&app));
    let resp = call(&app, Method::GET, &f.path("/members"), Some(&token), None).await;
    assert_problem(&resp, 401);
}

// ---------------------------------------------------------------------------------------------
// Lockout
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn org_admin_cannot_remove_last_org_admin() {
    let app = app().await;
    let tenant = default_tenant(&app);
    let f = org_with_admin(&app, &tenant, "acme", "admin@example.test").await;
    let resp = call(
        &app,
        Method::DELETE,
        &f.path(&format!("/members/{}", f.admin.id)),
        Some(&f.token),
        None,
    )
    .await;
    assert_problem(&resp, 409);
    assert!(
        app.storage()
            .organizations()
            .is_member(tenant.id, f.org.id, f.admin.id)
            .await
            .unwrap()
    );
    // With a second org admin, the first may leave.
    let second = seed_user(&app, tenant.id, "second@example.test").await;
    add_member(&app, tenant.id, f.org.id, second.id, &[f.admin_role.id]).await;
    let resp = call(
        &app,
        Method::DELETE,
        &f.path(&format!("/members/{}", f.admin.id)),
        Some(&f.token),
        None,
    )
    .await;
    assert_eq!(resp.status, 204, "{}", resp.text());
}

#[tokio::test]
async fn org_admin_cannot_demote_last_org_admin() {
    let app = app().await;
    let tenant = default_tenant(&app);
    let f = org_with_admin(&app, &tenant, "acme", "admin@example.test").await;
    // A second member without org:admin does not count.
    let bob = seed_user(&app, tenant.id, "bob@example.test").await;
    let plain = create_role(&app, tenant.id, Some(f.org.id), "plain", &["docs:read"]).await;
    add_member(&app, tenant.id, f.org.id, bob.id, &[plain.id]).await;
    let t = Some(f.token.as_str());

    let resp = call(
        &app,
        Method::DELETE,
        &f.path(&format!("/members/{}/roles/org-admins", f.admin.id)),
        t,
        None,
    )
    .await;
    assert_problem(&resp, 409);
    let resp = call(
        &app,
        Method::PATCH,
        &f.path("/roles/org-admins"),
        t,
        Some(json!({"permissions": ["docs:read"]})),
    )
    .await;
    assert_problem(&resp, 409);
    let resp = call(&app, Method::DELETE, &f.path("/roles/org-admins"), t, None).await;
    assert_problem(&resp, 409);
    // Nothing changed: the token still works.
    let resp = call(&app, Method::GET, &f.path("/members"), t, None).await;
    assert_eq!(resp.status, 200);
    // Edits keeping org:admin are fine.
    let resp = call(
        &app,
        Method::PATCH,
        &f.path("/roles/org-admins"),
        t,
        Some(json!({"permissions": ["org:admin", "docs:read"]})),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
}

#[tokio::test]
async fn tenant_admin_can_remove_last_org_admin() {
    let app = app().await;
    let tenant = default_tenant(&app);
    let f = org_with_admin(&app, &tenant, "acme", "admin@example.test").await;
    let admin = admin_token(&app, "admin:organizations:write").await;
    let resp = call(
        &app,
        Method::PATCH,
        &f.path("/roles/org-admins"),
        Some(&admin),
        Some(json!({"permissions": ["docs:read", "org:admin"]})),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let resp = call(
        &app,
        Method::DELETE,
        &f.path(&format!("/members/{}", f.admin.id)),
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(resp.status, 204, "{}", resp.text());
    // Recovery: a tenant administrator can make someone else org admin again.
    let carol = seed_user(&app, tenant.id, "carol@example.test").await;
    let resp = call(
        &app,
        Method::POST,
        &f.path("/members"),
        Some(&admin),
        Some(json!({"user_id": carol.id.0, "role_ids": [f.admin_role.id.0]})),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.text());
}

// ---------------------------------------------------------------------------------------------
// Invitations
// ---------------------------------------------------------------------------------------------

/// The keys of a JSON object, sorted.
fn keys(v: &Value) -> Vec<String> {
    let mut k: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
    k.sort();
    k
}

#[tokio::test]
async fn invitation_response_identical_for_known_and_unknown_email() {
    let app = app().await;
    let tenant = default_tenant(&app);
    let f = org_with_admin(&app, &tenant, "acme", "admin@example.test").await;
    seed_user(&app, tenant.id, "known@example.test").await;
    let mut answers = Vec::new();
    for email in ["known@example.test", "unknown@example.test"] {
        let resp = call(
            &app,
            Method::POST,
            &f.path("/invitations"),
            Some(&f.token),
            Some(json!({"email": email})),
        )
        .await;
        assert_eq!(resp.status, 201, "{}", resp.text());
        answers.push((resp.status, keys(&body_json(&resp)), body_json(&resp)));
    }
    assert_eq!(answers[0].0, answers[1].0);
    assert_eq!(answers[0].1, answers[1].1);
    for field in [
        "status",
        "role_ids",
        "accepted_at",
        "accepted_user_id",
        "revoked_at",
    ] {
        assert_eq!(answers[0].2[field], answers[1].2[field], "{field}");
    }
    // Both got an email; neither created a user.
    let users = app
        .storage()
        .users()
        .get_by_email(tenant.id, "unknown@example.test")
        .await
        .unwrap();
    assert!(users.is_none());
}

#[tokio::test]
async fn invitation_list_never_exposes_token_or_hash() {
    let app = app().await;
    let tenant = default_tenant(&app);
    let f = org_with_admin(&app, &tenant, "acme", "admin@example.test").await;
    let resp = call(
        &app,
        Method::POST,
        &f.path("/invitations"),
        Some(&f.token),
        Some(json!({"email": "bob@example.test"})),
    )
    .await;
    assert_eq!(resp.status, 201);
    let created = resp.text();
    let stored = app
        .storage()
        .organizations()
        .list_invitations(tenant.id, f.org.id, true)
        .await
        .unwrap();
    let hash = stored[0].token_hash.0;
    let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
    let b64 = anvil_jose::encoding::b64url(&hash);
    for path in [
        f.path("/invitations"),
        f.path("/invitations?include_closed=true"),
    ] {
        let list = call(&app, Method::GET, &path, Some(&f.token), None).await;
        assert_eq!(list.status, 200);
        let text = list.text();
        for body in [&text, &created] {
            assert!(!body.contains("token"), "{body}");
            assert!(!body.contains("hash"), "{body}");
            assert!(!body.contains(&hex), "{body}");
            assert!(!body.contains(&b64), "{body}");
        }
    }
}
