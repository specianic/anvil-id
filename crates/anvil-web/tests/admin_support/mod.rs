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
