//! Helpers for the management API tests (test code only).
//!
//! Admin access tokens are minted with the production signing path (`sign_access_token` with the
//! tenant's active KEK-sealed key), exactly as `TokenService` does for client_credentials, so the
//! admin API's verifier is exercised with real tokens independently of the `/token` endpoint.

#![allow(dead_code)]

use anvil_core::model::{
    ApplicationType, ClientAuthMethod, ClientId, ClientType, GrantType, NewClient, Scope,
    SecretHash, TenantBase, issuer,
};
use anvil_core::ports::Clock as _;
use anvil_core::service::claims::{AccessTokenInput, IdTokenInput};
use anvil_core::service::key::open_key;
use anvil_core::service::token::{sign_access_token, sign_id_token};
use anvil_jose::encoding::{random_token, secret_hash};
use axum::body::Body;
use axum::http::{Method, Request, header};
use serde_json::Value;

use crate::support::{InstalledTenant, TestApp, TestResponse};

pub const API: &str = "/api/admin/v1";

/// The system tenant's issuer.
pub fn system_issuer(app: &TestApp) -> String {
    issuer(
        &app.config.public_url,
        &TenantBase::Path("system".to_owned()),
    )
}

/// Registers a confidential client_credentials client with `scopes` in the system tenant
/// (through the storage port, so no admin token is needed). Returns its client_id.
pub async fn system_client(app: &TestApp, scopes: &[&str]) -> String {
    let system = app.system.as_ref().expect("installed");
    let now = app.clock().now();
    let client_id = format!("adm-{}", &random_token()[..12]);
    app.storage()
        .clients()
        .create(
            system.tenant.id,
            &NewClient {
                id: ClientId::new_v7(),
                client_id: client_id.clone(),
                name: "test admin client".to_owned(),
                client_type: ClientType::Confidential,
                application_type: ApplicationType::Web,
                auth_method: ClientAuthMethod::ClientSecretBasic,
                secret_hash: Some(SecretHash(secret_hash(&random_token()))),
                jwks: None,
                redirect_uris: Vec::new(),
                grant_types: vec![GrantType::ClientCredentials],
                scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
                require_pkce: true,
                created_at: now,
                token_format: anvil_core::model::TokenFormat::Jwt,
                consent_mode: anvil_core::model::ConsentMode::Required,
                id_token_signed_response_alg: None,
                can_introspect: false,
                post_logout_redirect_uris: vec![],
                backchannel_logout_uri: None,
                backchannel_logout_session_required: false,
                allowed_resources: vec![],
                mfa_policy: None,
                metadata_expires_at: None,
                registration_access_token_hash: None,
                registration_source: anvil_core::model::ClientSource::Static,
                organization: anvil_core::model::OrgClientPolicy::Off,
                require_pushed_authorization_requests: false,
                client_kind: anvil_core::model::ClientKind::Application,
                headless_native: false,
            },
        )
        .await
        .expect("create the admin client");
    client_id
}

async fn signer(app: &TestApp, tenant: &InstalledTenant) -> anvil_jose::keys::SigningKey {
    let row = app
        .storage()
        .keys()
        .active(tenant.tenant.id, "RS256")
        .await
        .expect("key lookup")
        .expect("active RS256 key");
    open_key(app.kek(), &row).expect("open the signing key")
}

/// A client_credentials access token of `tenant` (issuer `iss`) for `client_id`.
pub async fn mint_access_token(
    app: &TestApp,
    tenant: &InstalledTenant,
    iss: &str,
    client_id: &str,
    scope: &str,
) -> String {
    let key = signer(app, tenant).await;
    let scope = Scope::parse(scope).expect("valid scope");
    sign_access_token(
        &key,
        &AccessTokenInput {
            issuer: iss,
            sub: client_id,
            client_id,
            scope: &scope,
            now: app.clock().now(),
            jti: random_token(),
            family_id: None,
            auth_time: None,
            acr: None,
            resource: &[],
        },
    )
    .expect("sign the access token")
}

/// An ID token of the system tenant for `client_id`.
pub async fn mint_system_id_token(app: &TestApp, client_id: &str) -> String {
    let system = app.system.as_ref().expect("installed");
    let key = signer(app, system).await;
    sign_id_token(
        &key,
        &IdTokenInput {
            issuer: &system_issuer(app),
            sub: client_id,
            client_id,
            now: app.clock().now(),
            auth_time: None,
            nonce: None,
            acr: None,
            amr: &[],
            sid: None,
            at_hash: None,
            extra: serde_json::Map::new(),
        },
    )
    .expect("sign the ID token")
}

/// A system-tenant admin access token with `scope` for a freshly registered client.
pub async fn admin_token(app: &TestApp, scope: &str) -> String {
    let scopes: Vec<&str> = scope.split(' ').collect();
    let client_id = system_client(app, &scopes).await;
    let system = app.system.as_ref().expect("installed");
    mint_access_token(app, system, &system_issuer(app), &client_id, scope).await
}

/// Sends a management API request with an optional bearer token and JSON body.
pub async fn call(
    app: &TestApp,
    method: Method,
    path: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> TestResponse {
    let mut req = Request::builder().method(method).uri(path);
    if let Some(t) = token {
        req = req.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    let req = match body {
        Some(b) => req
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(b.to_string())),
        None => req.body(Body::empty()),
    }
    .expect("request");
    app.send(req).await
}

/// Asserts an RFC 9457 problem response with `status`.
pub fn assert_problem(resp: &TestResponse, status: u16) -> Value {
    assert_eq!(resp.status.as_u16(), status, "{}", resp.text());
    assert_eq!(
        resp.header("content-type"),
        Some("application/problem+json"),
        "{}",
        resp.text()
    );
    let body: Value = serde_json::from_slice(&resp.body).expect("problem body is JSON");
    assert_eq!(body["status"], status);
    body
}

/// Asserts a 422 problem naming `field`.
pub fn assert_field_error(resp: &TestResponse, field: &str) {
    let body = assert_problem(resp, 422);
    assert_eq!(body["errors"][0]["field"], field, "{body}");
}

// ---------------------------------------------------------------------------------------------
// Organizations (06-12)
// ---------------------------------------------------------------------------------------------

/// The management API as an RFC 8707 resource (`{public_url}/api/admin/v1`).
pub fn admin_resource(app: &TestApp) -> String {
    format!("{}{API}", app.config.public_url.as_str())
}

/// Creates an organization through storage (no admin token needed).
pub async fn create_org(
    app: &TestApp,
    tenant: anvil_core::model::TenantId,
    slug: &str,
) -> anvil_core::model::Organization {
    app.storage()
        .organizations()
        .create(
            tenant,
            &anvil_core::model::NewOrganization {
                id: anvil_core::model::OrgId::new_v7(),
                slug: slug.to_owned(),
                display_name: slug.to_uppercase(),
                mfa_policy: None,
                settings: anvil_core::model::OrgSettings::default(),
                metadata: serde_json::json!({}),
                created_at: app.clock().now(),
            },
        )
        .await
        .expect("create the org")
}

/// Adds `user` to `org` with `roles` assigned in the org, through storage.
pub async fn add_member(
    app: &TestApp,
    tenant: anvil_core::model::TenantId,
    org: anvil_core::model::OrgId,
    user: anvil_core::model::UserId,
    roles: &[anvil_core::model::RoleId],
) {
    let outcome = app
        .storage()
        .organizations()
        .add_member(
            tenant,
            &anvil_core::model::NewMembership {
                org_id: org,
                user_id: user,
                role_ids: roles.to_vec(),
                created_at: app.clock().now(),
            },
        )
        .await
        .expect("add the member");
    assert_eq!(outcome, anvil_core::ports::AddMemberOutcome::Added);
}

/// Creates a role (tenant role when `org` is `None`) through storage.
pub async fn create_role(
    app: &TestApp,
    tenant: anvil_core::model::TenantId,
    org: Option<anvil_core::model::OrgId>,
    name: &str,
    permissions: &[&str],
) -> anvil_core::model::Role {
    app.storage()
        .roles()
        .create(
            tenant,
            &anvil_core::model::NewRole {
                id: anvil_core::model::RoleId::new_v7(),
                org_id: org,
                name: name.to_owned(),
                description: String::new(),
                permissions: permissions.iter().map(|p| (*p).to_owned()).collect(),
                created_at: app.clock().now(),
            },
        )
        .await
        .expect("create the role")
}

/// How a test org-admin token is built. The default is a valid org-admin token.
#[derive(Debug, Clone)]
pub struct OrgTokenOpts {
    /// Put the management API resource into `aud` (else the token is audience-bound to its
    /// client only).
    pub admin_audience: bool,
    pub scope: String,
    /// The `org_id` claim; `None` = the org the family is bound to.
    pub org_claim: Option<String>,
    /// Issue an opaque token instead of a JWT.
    pub opaque: bool,
}

impl Default for OrgTokenOpts {
    fn default() -> Self {
        Self {
            admin_audience: true,
            scope: "openid org:admin".to_owned(),
            org_claim: None,
            opaque: false,
        }
    }
}

/// A test org-admin access token and what it is bound to.
#[derive(Debug, Clone)]
pub struct OrgAdminToken {
    pub token: String,
    pub family_id: anvil_core::model::TokenFamilyId,
    pub client_id: String,
}

/// An org-admin access token of `tenant` for `user` in `org` (test-only issuance, decision Q1):
/// a JWT client allowed the management API resource, a token family bound to the org through
/// storage, and an `at+jwt` signed with the tenant's active key carrying `org_id` and
/// `aud` = the management API resource.
pub async fn org_admin_token(
    app: &TestApp,
    tenant: &anvil_core::model::Tenant,
    org: anvil_core::model::OrgId,
    user: anvil_core::model::UserId,
) -> OrgAdminToken {
    org_admin_token_with(app, tenant, org, user, OrgTokenOpts::default()).await
}

/// [`org_admin_token`] with options (negative tests).
pub async fn org_admin_token_with(
    app: &TestApp,
    tenant: &anvil_core::model::Tenant,
    org: anvil_core::model::OrgId,
    user: anvil_core::model::UserId,
    opts: OrgTokenOpts,
) -> OrgAdminToken {
    use anvil_core::model::{GrantType, NewTokenFamily, TokenFamilyId, TokenFormat};
    let now = app.clock().now();
    let resource = admin_resource(app);
    let client_id = format!("org-{}", &random_token()[..12]);
    app.storage()
        .clients()
        .create(
            tenant.id,
            &NewClient {
                id: ClientId::new_v7(),
                client_id: client_id.clone(),
                name: "org console".to_owned(),
                client_type: ClientType::Public,
                application_type: ApplicationType::Web,
                auth_method: ClientAuthMethod::None,
                secret_hash: None,
                jwks: None,
                redirect_uris: vec!["https://console.test/cb".to_owned()],
                grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
                scopes: vec!["openid".to_owned(), "org:admin".to_owned()],
                require_pkce: true,
                created_at: now,
                token_format: if opts.opaque {
                    TokenFormat::Opaque
                } else {
                    TokenFormat::Jwt
                },
                consent_mode: anvil_core::model::ConsentMode::Required,
                id_token_signed_response_alg: None,
                can_introspect: false,
                post_logout_redirect_uris: vec![],
                backchannel_logout_uri: None,
                backchannel_logout_session_required: false,
                allowed_resources: vec![resource.clone()],
                mfa_policy: None,
                metadata_expires_at: None,
                registration_access_token_hash: None,
                registration_source: anvil_core::model::ClientSource::Static,
                organization: anvil_core::model::OrgClientPolicy::Optional,
                require_pushed_authorization_requests: false,
                client_kind: anvil_core::model::ClientKind::Application,
                headless_native: false,
            },
        )
        .await
        .expect("create the org console client");
    let audience = if opts.admin_audience {
        vec![resource]
    } else {
        vec![]
    };
    let family_id = TokenFamilyId::new_v7();
    app.storage()
        .grants()
        .create_family(
            tenant.id,
            &NewTokenFamily {
                id: family_id,
                client_id: client_id.clone(),
                user_id: Some(user),
                scope: opts.scope.clone(),
                resource: audience.clone(),
                auth_time: Some(now),
                acr: None,
                amr: vec!["pwd".to_owned()],
                session_id: None,
                claims: None,
                org_id: Some(org),
                created_at: now,
                absolute_expires_at: now + time::Duration::days(1),
            },
        )
        .await
        .expect("create the org-bound family");
    let scope = Scope::parse(&opts.scope).expect("valid scope");
    if opts.opaque {
        let raw = random_token();
        app.storage()
            .grants()
            .create_access_token(
                tenant.id,
                &anvil_core::service::token::new_opaque_access_token(
                    &raw,
                    &client_id,
                    Some(family_id),
                    Some(user),
                    &scope,
                    &audience,
                    now,
                ),
            )
            .await
            .expect("store the opaque token");
        return OrgAdminToken {
            token: raw,
            family_id,
            client_id,
        };
    }
    let iss = anvil_core::service::logout::canonical_issuer(&app.config.public_url, tenant);
    let sub = user.to_string();
    let mut claims = anvil_core::service::claims::access_token_claims(&AccessTokenInput {
        issuer: &iss,
        sub: &sub,
        client_id: &client_id,
        scope: &scope,
        now,
        jti: random_token(),
        family_id: Some(family_id),
        auth_time: Some(now),
        acr: None,
        resource: &audience,
    });
    claims.insert(
        "org_id".to_owned(),
        Value::String(opts.org_claim.unwrap_or_else(|| org.to_string())),
    );
    let row = app
        .storage()
        .keys()
        .active(tenant.id, "RS256")
        .await
        .expect("key lookup")
        .expect("active RS256 key");
    let key = open_key(app.kek(), &row).expect("open the signing key");
    let token = key
        .sign_jwt(Some("at+jwt"), &claims)
        .expect("sign the org-admin token");
    OrgAdminToken {
        token,
        family_id,
        client_id,
    }
}
