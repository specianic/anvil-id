//! Per-client ID-token signing algorithm (OIDC-11): `id_token_signed_response_alg` selects
//! RS256, ES256 or Ed25519 when the tenant has enabled it; `at_hash` follows the algorithm;
//! access tokens stay RS256; a client alg that cannot be served is a server error, never a
//! fallback. Runs on SQLite by default and on Postgres with `ANVILID_TEST_DB=postgres`.

mod support;
mod token_support;

use std::sync::Arc;

use anvil_core::model::{ClientAuthMethod, ClientUpdate, Tenant, TenantSettings, TenantUpdate};
use anvil_core::ports::Clock;
use anvil_core::service::key::KeyService;
use anvil_core::service::key_rotation::{KeyRotationService, RotationPolicy};
use anvil_jose::jws::verify_jwt;
use anvil_jose::keys::Alg;
use anvil_jose::{Jwks, token_hash};
use serde_json::Value;
use support::{TestApp, json};
use time::OffsetDateTime;
use token_support::*;

struct Frozen(OffsetDateTime);

impl Clock for Frozen {
    fn now(&self) -> OffsetDateTime {
        self.0
    }
}

/// Enables `algs` for the default tenant; with `ensure`, generates their active keys.
async fn tenant_with(app: &TestApp, algs: &[&str], ensure: bool) -> Tenant {
    let current = app.default.as_ref().expect("installed").tenant.clone();
    let tenant = app
        .storage()
        .tenants()
        .update(
            current.id,
            &TenantUpdate {
                settings: Some(TenantSettings {
                    signing_algs: algs.iter().map(|a| (*a).to_owned()).collect(),
                    ..current.settings.clone()
                }),
                ..TenantUpdate::default()
            },
        )
        .await
        .expect("update")
        .expect("tenant exists");
    if ensure {
        KeyRotationService {
            storage: app.storage_arc(),
            kek: app.kek_arc(),
            clock: Arc::new(Frozen(app.clock_now())),
            policy: RotationPolicy::default(),
        }
        .ensure_tenant(&tenant)
        .await
        .expect("ensure keys");
    }
    tenant
}

/// Registers a code-flow client with `alg` as its ID-token algorithm and runs the code
/// exchange, returning the raw response.
async fn exchange_with_alg(
    app: &TestApp,
    tenant: &Tenant,
    alg: Option<&str>,
) -> (Rp, support::TestResponse) {
    let mut rp = register(
        app,
        tenant.id,
        web_input(ClientAuthMethod::ClientSecretBasic),
    )
    .await;
    rp.client = app
        .storage()
        .clients()
        .update(
            tenant.id,
            rp.id(),
            &ClientUpdate {
                id_token_signed_response_alg: Some(alg.map(str::to_owned)),
                ..ClientUpdate::default()
            },
            app.clock_now(),
        )
        .await
        .expect("client update")
        .expect("client exists");
    assert_eq!(rp.client.id_token_signed_response_alg.as_deref(), alg);
    let user = seed_user(app, tenant.id, "ada@example.test").await;
    let session = seed_session(app, tenant.id, &user).await;
    let code = issue_code(
        app,
        tenant.id,
        &rp,
        &session,
        &params("openid offline_access", Some(CHALLENGE)),
    )
    .await;
    let resp = exchange(app, &rp, &code).await;
    (rp, resp)
}

async fn served_jwks(app: &TestApp) -> Jwks {
    let resp = app.get("/jwks").await;
    assert_eq!(resp.status, 200);
    serde_json::from_slice(&resp.body).expect("jwks")
}

async fn active_kid(app: &TestApp, tenant: &Tenant, alg: Alg) -> String {
    KeyService {
        storage: app.storage_arc(),
        kek: app.kek_arc(),
        clock: Arc::new(Frozen(app.clock_now())),
    }
    .signer_for(tenant.id, alg)
    .await
    .expect("active key")
    .kid()
    .to_owned()
}

/// Checks the ID token (alg, kid, signature against /jwks, at_hash) and that the access token is
/// RS256 from the tenant's RS256 key.
async fn assert_tokens(app: &TestApp, tenant: &Tenant, body: &Value, alg: Alg) {
    let id_token = body["id_token"].as_str().expect("id_token");
    let access_token = body["access_token"].as_str().expect("access_token");
    let jwks = served_jwks(app).await;

    let header = jwt_header(id_token);
    assert_eq!(header["alg"], alg.as_str());
    assert_eq!(header["kid"], active_kid(app, tenant, alg).await.as_str());
    let verified = verify_jwt(id_token, &jwks, &[alg]).expect("ID token verifies against /jwks");
    assert_eq!(
        verified.claims["at_hash"],
        token_hash(alg, access_token).as_str()
    );
    // Only the client's algorithm is accepted for its ID token.
    for other in [Alg::RS256, Alg::ES256, Alg::Ed25519] {
        if other != alg {
            assert!(verify_jwt(id_token, &jwks, &[other]).is_err());
        }
    }

    let at_header = jwt_header(access_token);
    assert_eq!(at_header["alg"], "RS256");
    assert_eq!(
        at_header["kid"],
        active_kid(app, tenant, Alg::RS256).await.as_str()
    );
    verify_jwt(access_token, &jwks, &[Alg::RS256]).expect("AT verifies");
    // The RS256 access token still works at /userinfo.
    assert_eq!(userinfo_get(app, access_token).await.status, 200);
}

#[tokio::test]
async fn es256_client_gets_an_es256_id_token() {
    let app = TestApp::new().await;
    let tenant = tenant_with(&app, &["RS256", "ES256"], true).await;
    let (rp, resp) = exchange_with_alg(&app, &tenant, Some("ES256")).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let body = json(&resp);
    assert_tokens(&app, &tenant, &body, Alg::ES256).await;

    // A refreshed ID token uses the same algorithm.
    let rt = body["refresh_token"].as_str().expect("refresh_token");
    let refreshed = refresh(&app, &rp, rt, None).await;
    assert_eq!(refreshed.status, 200, "{}", refreshed.text());
    assert_tokens(&app, &tenant, &json(&refreshed), Alg::ES256).await;
}

#[tokio::test]
async fn ed25519_client_gets_an_ed25519_id_token() {
    let app = TestApp::new().await;
    let tenant = tenant_with(&app, &["RS256", "Ed25519"], true).await;
    let (_, resp) = exchange_with_alg(&app, &tenant, Some("Ed25519")).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let body = json(&resp);
    let id_token = body["id_token"].as_str().expect("id_token");
    // RFC 9864 fully-specified name, never EdDSA.
    assert_eq!(jwt_header(id_token)["alg"], "Ed25519");
    let okp = json(&app.get("/jwks").await)["keys"]
        .as_array()
        .expect("keys")
        .iter()
        .any(|k| k["kty"] == "OKP" && k["crv"] == "Ed25519" && k["alg"] == "Ed25519");
    assert!(okp, "OKP key published");
    assert_tokens(&app, &tenant, &body, Alg::Ed25519).await;
    // at_hash is the left half of SHA-512 (32 bytes → 43 base64url chars), unlike SHA-256's 22.
    let at_hash = jwt_claims(id_token)["at_hash"]
        .as_str()
        .expect("at_hash")
        .to_owned();
    assert_eq!(at_hash.len(), 43);
}

#[tokio::test]
async fn client_without_alg_gets_rs256_even_when_other_algs_are_enabled() {
    let app = TestApp::new().await;
    let tenant = tenant_with(&app, &["RS256", "ES256", "Ed25519"], true).await;
    let (_, resp) = exchange_with_alg(&app, &tenant, None).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_tokens(&app, &tenant, &json(&resp), Alg::RS256).await;
}

#[tokio::test]
async fn alg_not_enabled_for_the_tenant_is_a_server_error() {
    let app = TestApp::new().await;
    let tenant = tenant_with(&app, &["RS256"], true).await;
    let (_, resp) = exchange_with_alg(&app, &tenant, Some("ES256")).await;
    assert_oauth_error(&resp, 500, "server_error");
    assert!(!resp.text().contains("id_token"));
}

#[tokio::test]
async fn enabled_alg_without_an_active_key_is_a_server_error() {
    let app = TestApp::new().await;
    // Enabled, but no ES256 key generated: no silent RS256 fallback.
    let tenant = tenant_with(&app, &["RS256", "ES256"], false).await;
    let (_, resp) = exchange_with_alg(&app, &tenant, Some("ES256")).await;
    assert_oauth_error(&resp, 500, "server_error");
}
