//! The org claim in tokens (ORG-02), end to end over HTTP on the selected backend: the
//! `organization` authorization parameter, the active org bound to the code and its family,
//! `org_id` / `org_slug` / `org_roles` / `org_permissions` in the ID token, JWT and opaque access
//! tokens, UserInfo and introspection, recomputed at every refresh, the `org:admin` scope bound
//! (decision Q1), and the 05-12 carry-over (role claims for opaque tokens and introspection).
//!
//! Orgs, memberships, org roles and client policies are seeded through the storage traits.
//! Every security check has a refusal test: non-members, removed members, `off` clients,
//! `prompt=none` with several orgs, `org:admin` without the permission or without an org,
//! client credentials, and spoofing through mapped attributes.

mod admin_support;
mod authz;
mod support;
mod token_support;

use admin_support::{API, admin_token, call};
use anvil_core::model::{
    AttributeDefinition, ClaimRule, ClientAuthMethod, GrantType, NewMembership, NewOrganization,
    NewRole, OrgClientPolicy, OrgId, OrgSettings, Organization, Role, RoleId, TenantId,
    TokenFormat, TokenTarget, User,
};
use anvil_core::ports::AddMemberOutcome;
use axum::http::Method;
use serde_json::{Value, json};
use support::{TestApp, TestResponse, json as body_json};
use token_support::*;

const SCOPE: &str = "openid roles";

// ---------------------------------------------------------------------------------------------
// Seeding
// ---------------------------------------------------------------------------------------------

/// A confidential web client using organizations with `policy`, issuing `format` access tokens,
/// allowed `roles` and `org:admin`, without a consent screen.
async fn org_client(
    app: &TestApp,
    tenant: TenantId,
    policy: OrgClientPolicy,
    format: TokenFormat,
) -> Rp {
    let mut input = web_input(ClientAuthMethod::ClientSecretBasic);
    input.scopes.push("roles".into());
    input.scopes.push("org:admin".into());
    register_with(app, tenant, input, |c| {
        c.organization = policy;
        c.token_format = format;
        c.consent_mode = anvil_core::model::ConsentMode::SkipFirstParty;
    })
    .await
}

async fn org(app: &TestApp, tenant: TenantId, slug: &str) -> Organization {
    app.storage()
        .organizations()
        .create(
            tenant,
            &NewOrganization {
                id: OrgId::new_v7(),
                slug: slug.into(),
                display_name: format!("{slug} Inc"),
                mfa_policy: None,
                settings: OrgSettings::default(),
                metadata: json!({}),
                created_at: app.clock_now(),
            },
        )
        .await
        .expect("org created")
}

/// A role: tenant-level with `org = None`, owned by `org` otherwise.
async fn role(
    app: &TestApp,
    tenant: TenantId,
    org: Option<OrgId>,
    name: &str,
    perms: &[&str],
) -> Role {
    app.storage()
        .roles()
        .create(
            tenant,
            &NewRole {
                id: RoleId::new_v7(),
                org_id: org,
                name: name.into(),
                description: String::new(),
                permissions: perms.iter().map(|p| (*p).to_owned()).collect(),
                created_at: app.clock_now(),
            },
        )
        .await
        .expect("role created")
}

async fn join(app: &TestApp, tenant: TenantId, org: &Organization, user: &User, roles: &[&Role]) {
    let outcome = app
        .storage()
        .organizations()
        .add_member(
            tenant,
            &NewMembership {
                org_id: org.id,
                user_id: user.id,
                role_ids: roles.iter().map(|r| r.id).collect(),
                created_at: app.clock_now(),
            },
        )
        .await
        .expect("add member");
    assert_eq!(outcome, AddMemberOutcome::Added);
}

async fn assign_in_org(
    app: &TestApp,
    tenant: TenantId,
    role: &Role,
    user: &User,
    org: &Organization,
) {
    assert!(
        app.storage()
            .roles()
            .assign_in_org(tenant, role.id, user.id, org.id, app.clock_now())
            .await
            .expect("assign in org")
    );
}

async fn unassign_in_org(
    app: &TestApp,
    tenant: TenantId,
    role: &Role,
    user: &User,
    org: &Organization,
) {
    assert!(
        app.storage()
            .roles()
            .unassign_in_org(tenant, role.id, user.id, org.id)
            .await
            .expect("unassign in org")
    );
}

/// The default tenant, a user `ada` with a session cookie.
struct Ctx {
    tenant: TenantId,
    user: User,
    cookie: String,
}

async fn ctx(app: &TestApp) -> Ctx {
    let tenant = default_tenant(app);
    let user = seed_user(app, tenant, "ada@example.test").await;
    let cookie = authz::session(app, &authz::default_tenant(app), user.id).await;
    Ctx {
        tenant,
        user,
        cookie,
    }
}

// ---------------------------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------------------------

/// `GET /authorize` for `rp` with `scope`, PKCE, `extra` parameters and the optional cookie.
async fn authorize(
    app: &TestApp,
    rp: &Rp,
    cookie: Option<&str>,
    scope: &str,
    extra: &[(&str, &str)],
) -> TestResponse {
    let mut pairs = vec![
        ("response_type", "code"),
        ("client_id", rp.id()),
        ("redirect_uri", REDIRECT),
        ("scope", scope),
        ("state", "st"),
        ("nonce", NONCE),
        ("code_challenge", CHALLENGE),
        ("code_challenge_method", "S256"),
    ];
    pairs.extend_from_slice(extra);
    authz::get(app, &authz::authorize_path("", &pairs), cookie).await
}

/// The `error` of an authorization error redirect to the client.
fn redirect_error(resp: &TestResponse) -> String {
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert!(
        support::location(resp).starts_with(REDIRECT),
        "{}",
        support::location(resp)
    );
    assert!(authz::param(resp, "code").is_none(), "no code on an error");
    authz::param(resp, "error").expect("error parameter")
}

/// Signs in through `/authorize` and exchanges the code; the token response.
async fn sign_in(app: &TestApp, c: &Ctx, rp: &Rp, scope: &str, extra: &[(&str, &str)]) -> Value {
    let resp = authorize(app, rp, Some(&c.cookie), scope, extra).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    let code = authz::param(&resp, "code")
        .unwrap_or_else(|| panic!("expected a code: {}", support::location(&resp)));
    let resp = exchange(app, rp, &code).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    body_json(&resp)
}

async fn refreshed(app: &TestApp, rp: &Rp, body: &Value) -> TestResponse {
    refresh(
        app,
        rp,
        body["refresh_token"].as_str().expect("refresh_token"),
        None,
    )
    .await
}

async fn introspect(app: &TestApp, rp: &Rp, token: &str) -> Value {
    let resp = token_at(app, "/introspect", &rp.auth(), &[("token", token)]).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    body_json(&resp)
}

async fn userinfo(app: &TestApp, token: &str) -> TestResponse {
    userinfo_get(app, token).await
}

fn access_token(body: &Value) -> &str {
    body["access_token"].as_str().expect("access_token")
}

fn id_token_claims(body: &Value) -> Value {
    jwt_claims(body["id_token"].as_str().expect("id_token"))
}

fn scopes(body: &Value) -> Vec<String> {
    let mut v: Vec<String> = body["scope"]
        .as_str()
        .expect("scope")
        .split(' ')
        .map(str::to_owned)
        .collect();
    v.sort();
    v
}

const ORG_CLAIMS: [&str; 4] = ["org_id", "org_slug", "org_roles", "org_permissions"];

fn assert_no_org_claims(claims: &Value) {
    for c in ORG_CLAIMS {
        assert!(claims.get(c).is_none(), "{c} must be absent: {claims}");
    }
}

// ---------------------------------------------------------------------------------------------
// Claims in every token surface
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn org_claims_in_id_token_access_token_userinfo_introspection() {
    let app = TestApp::new().await;
    let c = ctx(&app).await;
    let rp = org_client(&app, c.tenant, OrgClientPolicy::Optional, TokenFormat::Jwt).await;
    let acme = org(&app, c.tenant, "acme").await;
    let editor = role(&app, c.tenant, Some(acme.id), "editor", &["docs:write"]).await;
    join(&app, c.tenant, &acme, &c.user, &[&editor]).await;

    let body = sign_in(&app, &c, &rp, SCOPE, &[("organization", "acme")]).await;
    let org_id = acme.id.to_string();

    let id = id_token_claims(&body);
    assert_eq!(id["org_id"], org_id, "{id}");
    assert_eq!(id["org_slug"], "acme");
    assert_eq!(id["org_roles"], json!(["editor"]));
    assert!(
        id.get("org_permissions").is_none(),
        "access token only: {id}"
    );

    let at = jwt_claims(access_token(&body));
    assert_eq!(at["org_id"], org_id, "{at}");
    assert_eq!(at["org_slug"], "acme");
    assert_eq!(at["org_roles"], json!(["editor"]));
    assert_eq!(at["org_permissions"], json!(["docs:write"]));
    // Org roles never show up as tenant-wide roles.
    assert!(at.get("roles").is_none(), "{at}");

    let resp = userinfo(&app, access_token(&body)).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let ui = body_json(&resp);
    assert_eq!(ui["org_id"], org_id, "{ui}");
    assert_eq!(ui["org_slug"], "acme");
    assert_eq!(ui["org_roles"], json!(["editor"]));
    assert!(ui.get("org_permissions").is_none(), "{ui}");

    let intro = introspect(&app, &rp, access_token(&body)).await;
    assert_eq!(intro["active"], true, "{intro}");
    assert_eq!(intro["org_id"], org_id);
    assert_eq!(intro["org_slug"], "acme");
    assert_eq!(intro["org_roles"], json!(["editor"]));
    assert_eq!(intro["org_permissions"], json!(["docs:write"]));
}

#[tokio::test]
async fn opaque_token_introspection_and_userinfo_carry_roles_and_org_claims() {
    let app = TestApp::new().await;
    let c = ctx(&app).await;
    let rp = org_client(
        &app,
        c.tenant,
        OrgClientPolicy::Optional,
        TokenFormat::Opaque,
    )
    .await;
    let acme = org(&app, c.tenant, "acme").await;
    let viewer = role(&app, c.tenant, Some(acme.id), "viewer", &["docs:read"]).await;
    join(&app, c.tenant, &acme, &c.user, &[&viewer]).await;
    let staff = role(&app, c.tenant, None, "staff", &["tickets:read"]).await;
    assert!(
        app.storage()
            .roles()
            .assign(c.tenant, staff.id, c.user.id, app.clock_now())
            .await
            .expect("assign")
    );

    let body = sign_in(&app, &c, &rp, SCOPE, &[("organization", "acme")]).await;
    let token = access_token(&body);
    assert_eq!(token.split('.').count(), 1, "opaque token");

    let intro = introspect(&app, &rp, token).await;
    assert_eq!(intro["active"], true, "{intro}");
    assert_eq!(intro["roles"], json!(["staff"]), "{intro}");
    assert_eq!(intro["permissions"], json!(["tickets:read"]));
    assert_eq!(intro["org_id"], acme.id.to_string());
    assert_eq!(intro["org_slug"], "acme");
    assert_eq!(intro["org_roles"], json!(["viewer"]));
    assert_eq!(intro["org_permissions"], json!(["docs:read"]));

    let resp = userinfo(&app, token).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let ui = body_json(&resp);
    assert_eq!(ui["roles"], json!(["staff"]), "{ui}");
    assert_eq!(ui["org_id"], acme.id.to_string());
    assert_eq!(ui["org_roles"], json!(["viewer"]));
    assert!(ui.get("permissions").is_none() && ui.get("org_permissions").is_none());

    // Roles are read at introspection time: a removed tenant role disappears at once.
    assert!(
        app.storage()
            .roles()
            .unassign(c.tenant, staff.id, c.user.id)
            .await
            .expect("unassign")
    );
    let intro = introspect(&app, &rp, token).await;
    assert_eq!(intro["active"], true);
    assert!(intro.get("roles").is_none(), "{intro}");
}

#[tokio::test]
async fn no_org_claims_without_active_org() {
    let app = TestApp::new().await;
    let c = ctx(&app).await;
    let rp = org_client(&app, c.tenant, OrgClientPolicy::Optional, TokenFormat::Jwt).await;
    let acme = org(&app, c.tenant, "acme").await;
    let editor = role(&app, c.tenant, Some(acme.id), "editor", &["docs:write"]).await;
    join(&app, c.tenant, &acme, &c.user, &[&editor]).await;

    // Optional policy without the parameter: no org, even for a member of exactly one.
    let body = sign_in(&app, &c, &rp, SCOPE, &[]).await;
    assert_no_org_claims(&id_token_claims(&body));
    assert_no_org_claims(&jwt_claims(access_token(&body)));
    let resp = userinfo(&app, access_token(&body)).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_no_org_claims(&body_json(&resp));
    let intro = introspect(&app, &rp, access_token(&body)).await;
    assert_eq!(intro["active"], true);
    assert_no_org_claims(&intro);
    // ... and none after a refresh either.
    let resp = refreshed(&app, &rp, &body).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_no_org_claims(&jwt_claims(access_token(&body_json(&resp))));
}

// ---------------------------------------------------------------------------------------------
// Refresh
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn refresh_recomputes_org_roles() {
    let app = TestApp::new().await;
    let c = ctx(&app).await;
    let rp = org_client(&app, c.tenant, OrgClientPolicy::Required, TokenFormat::Jwt).await;
    let acme = org(&app, c.tenant, "acme").await;
    let viewer = role(&app, c.tenant, Some(acme.id), "viewer", &["docs:read"]).await;
    join(&app, c.tenant, &acme, &c.user, &[&viewer]).await;

    // Required with one membership and no parameter: that org.
    let body = sign_in(&app, &c, &rp, SCOPE, &[]).await;
    let at = jwt_claims(access_token(&body));
    assert_eq!(at["org_id"], acme.id.to_string(), "{at}");
    assert_eq!(at["org_roles"], json!(["viewer"]));

    // A tenant role assigned inside the org after issuance appears after the refresh.
    let publisher = role(&app, c.tenant, None, "publisher", &["docs:publish"]).await;
    assign_in_org(&app, c.tenant, &publisher, &c.user, &acme).await;
    let resp = refreshed(&app, &rp, &body).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let next = body_json(&resp);
    let at = jwt_claims(access_token(&next));
    assert_eq!(at["org_id"], acme.id.to_string());
    assert_eq!(at["org_roles"], json!(["publisher", "viewer"]), "{at}");
    assert_eq!(at["org_permissions"], json!(["docs:publish", "docs:read"]));
    // The tenant-wide claims stay tenant-wide.
    assert!(at.get("roles").is_none(), "{at}");
    let id = id_token_claims(&next);
    assert_eq!(id["org_roles"], json!(["publisher", "viewer"]), "{id}");

    // Removing it again shows on the following refresh.
    unassign_in_org(&app, c.tenant, &publisher, &c.user, &acme).await;
    let resp = refreshed(&app, &rp, &next).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let at = jwt_claims(access_token(&body_json(&resp)));
    assert_eq!(at["org_roles"], json!(["viewer"]), "{at}");
}

#[tokio::test]
async fn removed_member_refresh_is_invalid_grant() {
    let app = TestApp::new().await;
    let c = ctx(&app).await;
    let rp = org_client(&app, c.tenant, OrgClientPolicy::Optional, TokenFormat::Jwt).await;
    let acme = org(&app, c.tenant, "acme").await;
    join(&app, c.tenant, &acme, &c.user, &[]).await;

    let body = sign_in(&app, &c, &rp, SCOPE, &[("organization", "acme")]).await;
    assert!(
        app.storage()
            .organizations()
            .remove_member(c.tenant, acme.id, c.user.id, app.clock_now())
            .await
            .expect("remove member")
    );
    assert_oauth_error(&refreshed(&app, &rp, &body).await, 400, "invalid_grant");
    // The access token no longer works at UserInfo and introspects inactive.
    assert_invalid_token(&userinfo(&app, access_token(&body)).await);
    assert_eq!(
        introspect(&app, &rp, access_token(&body)).await,
        json!({"active": false})
    );
}

#[tokio::test]
async fn grant_bound_to_an_org_the_user_is_not_in_is_invalid_grant() {
    // Belt and braces: a family whose membership is gone without the family having been
    // revoked (any path other than OrgRepo::remove_member) is refused by the token endpoint's
    // own membership check. Bound here directly, bypassing the authorization endpoint.
    let app = TestApp::new().await;
    let c = ctx(&app).await;
    let rp = org_client(&app, c.tenant, OrgClientPolicy::Optional, TokenFormat::Jwt).await;
    let other = org(&app, c.tenant, "other").await;
    let session = seed_session(&app, c.tenant, &c.user).await;
    let code = issue_code_in_org(
        &app,
        c.tenant,
        &rp,
        &session,
        &params(SCOPE, Some(CHALLENGE)),
        Some(other.id),
    )
    .await;
    assert_oauth_error(&exchange(&app, &rp, &code).await, 400, "invalid_grant");

    // A member gets tokens from the same kind of code (positive control).
    join(&app, c.tenant, &other, &c.user, &[]).await;
    let code = issue_code_in_org(
        &app,
        c.tenant,
        &rp,
        &session,
        &params(SCOPE, Some(CHALLENGE)),
        Some(other.id),
    )
    .await;
    let resp = exchange(&app, &rp, &code).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(
        jwt_claims(access_token(&body_json(&resp)))["org_slug"],
        "other"
    );
}

// ---------------------------------------------------------------------------------------------
// org:admin (decision Q1)
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn org_admin_scope_only_with_org_admin_permission() {
    let app = TestApp::new().await;
    let c = ctx(&app).await;
    let rp = org_client(&app, c.tenant, OrgClientPolicy::Optional, TokenFormat::Jwt).await;
    let acme = org(&app, c.tenant, "acme").await;
    let admins = role(&app, c.tenant, Some(acme.id), "org-admins", &["org:admin"]).await;
    join(&app, c.tenant, &acme, &c.user, &[]).await;
    let scope = "openid org:admin";

    // Without the permission: dropped.
    let body = sign_in(&app, &c, &rp, scope, &[("organization", "acme")]).await;
    assert_eq!(scopes(&body), ["openid"]);
    assert_eq!(jwt_claims(access_token(&body))["scope"], "openid");

    // Granted in the org: kept at the next refresh (the refresh token keeps the full grant).
    assign_in_org(&app, c.tenant, &admins, &c.user, &acme).await;
    let resp = refreshed(&app, &rp, &body).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let next = body_json(&resp);
    assert_eq!(scopes(&next), ["openid", "org:admin"]);
    let at = jwt_claims(access_token(&next));
    assert_eq!(at["org_id"], acme.id.to_string());
    assert!(
        at["scope"]
            .as_str()
            .unwrap()
            .split(' ')
            .any(|s| s == "org:admin"),
        "{at}"
    );

    // Removed: dropped again at the following refresh.
    unassign_in_org(&app, c.tenant, &admins, &c.user, &acme).await;
    let resp = refreshed(&app, &rp, &next).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(scopes(&body_json(&resp)), ["openid"]);

    // With the permission from the start: kept at issuance.
    assign_in_org(&app, c.tenant, &admins, &c.user, &acme).await;
    let body = sign_in(&app, &c, &rp, scope, &[("organization", "acme")]).await;
    assert_eq!(scopes(&body), ["openid", "org:admin"]);
}

#[tokio::test]
async fn org_admin_scope_never_without_active_org() {
    let app = TestApp::new().await;
    let c = ctx(&app).await;
    let rp = org_client(&app, c.tenant, OrgClientPolicy::Optional, TokenFormat::Jwt).await;
    let acme = org(&app, c.tenant, "acme").await;
    let admins = role(&app, c.tenant, Some(acme.id), "org-admins", &["org:admin"]).await;
    join(&app, c.tenant, &acme, &c.user, &[&admins]).await;
    // A tenant-wide role carrying the string does not count either.
    let wide = role(&app, c.tenant, None, "wide", &["org:admin"]).await;
    assert!(
        app.storage()
            .roles()
            .assign(c.tenant, wide.id, c.user.id, app.clock_now())
            .await
            .expect("assign")
    );

    let body = sign_in(&app, &c, &rp, "openid org:admin", &[]).await;
    assert_eq!(scopes(&body), ["openid"]);
    let at = jwt_claims(access_token(&body));
    assert_eq!(at["scope"], "openid");
    assert_no_org_claims(&at);
    let resp = refreshed(&app, &rp, &body).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(scopes(&body_json(&resp)), ["openid"]);
}

#[tokio::test]
async fn client_credentials_never_grants_org_admin() {
    let app = TestApp::new().await;
    let tenant = default_tenant(&app);
    for format in [TokenFormat::Jwt, TokenFormat::Opaque] {
        let mut input = cc_input(ClientAuthMethod::ClientSecretBasic);
        input.scopes.push("org:admin".into());
        let rp = register_with(&app, tenant, input, |c| {
            c.organization = OrgClientPolicy::Optional;
            c.token_format = format;
        })
        .await;
        assert!(
            rp.client
                .grant_types
                .contains(&GrantType::ClientCredentials)
        );

        // Asked for explicitly, and implied by the default (every registered scope).
        for scope in [Some("api:read org:admin"), Some("org:admin"), None] {
            let mut pairs = vec![("grant_type", "client_credentials")];
            if let Some(s) = scope {
                pairs.push(("scope", s));
            }
            let resp = token(&app, &rp.auth(), &pairs).await;
            assert_eq!(resp.status, 200, "{}", resp.text());
            let body = body_json(&resp);
            let granted = body["scope"].as_str().expect("scope");
            assert!(
                !granted.split(' ').any(|s| s == "org:admin"),
                "{format:?} {scope:?}: {body}"
            );
            let token = access_token(&body);
            let claims = match format {
                TokenFormat::Jwt => jwt_claims(token),
                TokenFormat::Opaque => introspect(&app, &rp, token).await,
            };
            assert_no_org_claims(&claims);
            assert!(
                !claims["scope"]
                    .as_str()
                    .unwrap_or_default()
                    .split(' ')
                    .any(|s| s == "org:admin"),
                "{claims}"
            );
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Spoofing
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn mapped_attribute_cannot_spoof_org_claims() {
    let app = TestApp::new().await;
    let c = ctx(&app).await;

    // The admin API refuses a claim rule named org_id or org_slug (reserved, any case).
    let settings = admin_token(&app, "admin:settings:write").await;
    for name in ["org_id", "org_slug", "ORG_ID"] {
        let resp = call(
            &app,
            Method::PUT,
            &format!("{API}/tenants/default/attributes/tenant_org"),
            Some(&settings),
            Some(json!({
                "schema": {"type": "string"},
                "claim": {"claim": name, "tokens": ["access_token", "id_token", "userinfo"], "scope": null}
            })),
        )
        .await;
        assert_eq!(resp.status, 422, "{name}: {}", resp.text());
        assert_eq!(body_json(&resp)["errors"][0]["field"], "claim", "{name}");
    }

    // A definition stored around the API (as an older release might have) never wins either.
    app.storage()
        .attributes()
        .upsert(
            c.tenant,
            &AttributeDefinition {
                name: "tenant_org".into(),
                schema: json!({"type": "string"}),
                required: false,
                user_editable: true,
                claim: Some(ClaimRule {
                    claim: "org_id".into(),
                    tokens: vec![
                        TokenTarget::AccessToken,
                        TokenTarget::IdToken,
                        TokenTarget::Userinfo,
                    ],
                    scope: None,
                }),
                position: 0,
            },
            app.clock_now(),
        )
        .await
        .expect("definition stored");
    let mut values = serde_json::Map::new();
    values.insert("tenant_org".into(), json!("spoofed"));
    assert!(
        app.storage()
            .attributes()
            .set_user_values(c.tenant, c.user.id, &values, app.clock_now())
            .await
            .expect("values stored")
    );

    let rp = org_client(&app, c.tenant, OrgClientPolicy::Optional, TokenFormat::Jwt).await;
    let acme = org(&app, c.tenant, "acme").await;
    join(&app, c.tenant, &acme, &c.user, &[]).await;

    let body = sign_in(&app, &c, &rp, SCOPE, &[("organization", "acme")]).await;
    let real = acme.id.to_string();
    assert_eq!(id_token_claims(&body)["org_id"], real);
    assert_eq!(jwt_claims(access_token(&body))["org_id"], real);
    let ui = body_json(&userinfo(&app, access_token(&body)).await);
    assert_eq!(ui["org_id"], real, "{ui}");
    assert_eq!(
        introspect(&app, &rp, access_token(&body)).await["org_id"],
        real
    );

    // Without an org the attribute does not invent one.
    let body = sign_in(&app, &c, &rp, SCOPE, &[]).await;
    assert_no_org_claims(&id_token_claims(&body));
    assert_no_org_claims(&jwt_claims(access_token(&body)));
    assert_no_org_claims(&body_json(&userinfo(&app, access_token(&body)).await));
}

// ---------------------------------------------------------------------------------------------
// The authorization endpoint
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn organization_parameter_refused_for_off_client() {
    let app = TestApp::new().await;
    let c = ctx(&app).await;
    let rp = org_client(&app, c.tenant, OrgClientPolicy::Off, TokenFormat::Jwt).await;
    let acme = org(&app, c.tenant, "acme").await;
    join(&app, c.tenant, &acme, &c.user, &[]).await;

    let resp = authorize(
        &app,
        &rp,
        Some(&c.cookie),
        SCOPE,
        &[("organization", "acme")],
    )
    .await;
    assert_eq!(redirect_error(&resp), "invalid_request");
    // Also before sign-in: the request is refused, not stored for later.
    let resp = authorize(&app, &rp, None, SCOPE, &[("organization", "acme")]).await;
    assert_eq!(redirect_error(&resp), "invalid_request");

    // Repeated or oversized values are refused for any client.
    let opt = org_client(&app, c.tenant, OrgClientPolicy::Optional, TokenFormat::Jwt).await;
    let resp = authorize(
        &app,
        &opt,
        Some(&c.cookie),
        SCOPE,
        &[("organization", "acme"), ("organization", "acme")],
    )
    .await;
    assert_eq!(redirect_error(&resp), "invalid_request");
    let long = "a".repeat(129);
    let resp = authorize(
        &app,
        &opt,
        Some(&c.cookie),
        SCOPE,
        &[("organization", &long)],
    )
    .await;
    assert_eq!(redirect_error(&resp), "invalid_request");

    // The off client without the parameter: tokens without org claims (0.4 behaviour).
    let body = sign_in(&app, &c, &rp, SCOPE, &[]).await;
    assert_no_org_claims(&jwt_claims(access_token(&body)));
}

#[tokio::test]
async fn nonmember_organization_is_access_denied() {
    let app = TestApp::new().await;
    let c = ctx(&app).await;
    let rp = org_client(&app, c.tenant, OrgClientPolicy::Optional, TokenFormat::Jwt).await;
    let acme = org(&app, c.tenant, "acme").await;
    let other = org(&app, c.tenant, "other").await;
    join(&app, c.tenant, &acme, &c.user, &[]).await;

    // By slug and by id; an unknown org looks the same.
    for requested in [other.slug.clone(), other.id.to_string(), "nope".to_owned()] {
        let resp = authorize(
            &app,
            &rp,
            Some(&c.cookie),
            SCOPE,
            &[("organization", &requested)],
        )
        .await;
        assert_eq!(redirect_error(&resp), "access_denied", "{requested}");
    }
    // Required policy without any membership: access_denied.
    let required = org_client(&app, c.tenant, OrgClientPolicy::Required, TokenFormat::Jwt).await;
    let loner = seed_user(&app, c.tenant, "loner@example.test").await;
    let loner_cookie = authz::session(&app, &authz::default_tenant(&app), loner.id).await;
    let resp = authorize(&app, &required, Some(&loner_cookie), SCOPE, &[]).await;
    assert_eq!(redirect_error(&resp), "access_denied");

    // Positive control: the membership by id.
    let body = sign_in(
        &app,
        &c,
        &rp,
        SCOPE,
        &[("organization", &acme.id.to_string())],
    )
    .await;
    assert_eq!(jwt_claims(access_token(&body))["org_slug"], "acme");
}

#[tokio::test]
async fn prompt_none_multi_org_required_is_interaction_required() {
    let app = TestApp::new().await;
    let c = ctx(&app).await;
    let rp = org_client(&app, c.tenant, OrgClientPolicy::Required, TokenFormat::Jwt).await;
    let acme = org(&app, c.tenant, "acme").await;
    let beta = org(&app, c.tenant, "beta").await;
    join(&app, c.tenant, &acme, &c.user, &[]).await;
    join(&app, c.tenant, &beta, &c.user, &[]).await;

    let resp = authorize(&app, &rp, Some(&c.cookie), SCOPE, &[("prompt", "none")]).await;
    assert_eq!(redirect_error(&resp), "interaction_required");

    // prompt=none without a session is still login_required (the session comes first).
    let resp = authorize(&app, &rp, None, SCOPE, &[("prompt", "none")]).await;
    assert_eq!(redirect_error(&resp), "login_required");

    // Without prompt=none an org is never picked silently: an explicit page, no code.
    // TRANSITIONAL(06-19): becomes the organization switcher.
    let resp = authorize(&app, &rp, Some(&c.cookie), SCOPE, &[]).await;
    authz::assert_error_page(&resp, "invalid_request");
    assert!(resp.html().contains("organization selection required"));

    // Naming one of them works, with or without prompt=none.
    for extra in [
        vec![("organization", "beta"), ("prompt", "none")],
        vec![("organization", "beta")],
    ] {
        let body = sign_in(&app, &c, &rp, SCOPE, &extra).await;
        assert_eq!(
            jwt_claims(access_token(&body))["org_id"],
            beta.id.to_string()
        );
    }
}
