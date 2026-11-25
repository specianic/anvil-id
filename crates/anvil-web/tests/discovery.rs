//! Discovery (both well-known forms) and JWKS on the selected backend (`ANVILID_TEST_DB`).

mod support;

use anvil_core::model::{
    KeyState, NewSigningKey, NewTenant, SIGNING_KEY_PURPOSE, SigningKeyId, TenantId,
    TenantSettings, signing_key_aad,
};
use anvil_core::ports::Clock;
use serde_json::Value;
use support::{TestApp, json};

/// Every metadata name registered by OpenID Connect Discovery 1.0 §3 and RFC 8414 §2 (plus
/// RFC 9207's `authorization_response_iss_parameter_supported`). Publishing anything else makes
/// the conformance suite warn, and warnings fail CI.
const ALLOWED_METADATA: &[&str] = &[
    // OIDC Discovery 1.0 §3
    "issuer",
    "authorization_endpoint",
    "token_endpoint",
    "userinfo_endpoint",
    "jwks_uri",
    "registration_endpoint",
    "scopes_supported",
    "response_types_supported",
    "response_modes_supported",
    "grant_types_supported",
    "acr_values_supported",
    "subject_types_supported",
    "id_token_signing_alg_values_supported",
    "id_token_encryption_alg_values_supported",
    "id_token_encryption_enc_values_supported",
    "userinfo_signing_alg_values_supported",
    "userinfo_encryption_alg_values_supported",
    "userinfo_encryption_enc_values_supported",
    "request_object_signing_alg_values_supported",
    "request_object_encryption_alg_values_supported",
    "request_object_encryption_enc_values_supported",
    "token_endpoint_auth_methods_supported",
    "token_endpoint_auth_signing_alg_values_supported",
    "display_values_supported",
    "claim_types_supported",
    "claims_supported",
    "service_documentation",
    "claims_locales_supported",
    "ui_locales_supported",
    "claims_parameter_supported",
    "request_parameter_supported",
    "request_uri_parameter_supported",
    "require_request_uri_registration",
    "op_policy_uri",
    "op_tos_uri",
    // RFC 8414 §2
    "revocation_endpoint",
    "revocation_endpoint_auth_methods_supported",
    "revocation_endpoint_auth_signing_alg_values_supported",
    "introspection_endpoint",
    "introspection_endpoint_auth_methods_supported",
    "introspection_endpoint_auth_signing_alg_values_supported",
    "code_challenge_methods_supported",
    // RFC 9207 §3
    "authorization_response_iss_parameter_supported",
    // OIDC Discovery (prompt=create spec)
    "prompt_values_supported",
    // OIDC RP-Initiated Logout 1.0 §2.1
    "end_session_endpoint",
    // OIDC Back-Channel Logout 1.0 §2.1
    "backchannel_logout_supported",
    "backchannel_logout_session_supported",
];

async fn create_acme(app: &TestApp) {
    app.storage()
        .tenants()
        .create(&NewTenant {
            id: TenantId::new_v7(),
            slug: "acme".into(),
            display_name: "Acme".into(),
            host: None,
            settings: TenantSettings::default(),
            created_at: app.clock().now(),
        })
        .await
        .expect("create the acme tenant");
}

fn strings(v: &Value) -> Vec<&str> {
    v.as_array()
        .expect("array")
        .iter()
        .map(|s| s.as_str().expect("string"))
        .collect()
}

#[tokio::test]
async fn default_tenant_discovery() {
    let app = TestApp::new().await;
    let resp = app.get("/.well-known/openid-configuration").await;
    assert_eq!(resp.status, 200);
    assert!(
        resp.header("content-type")
            .is_some_and(|c| c.starts_with("application/json"))
    );
    let doc = json(&resp);
    assert_eq!(doc["issuer"], "https://op.test");
    assert_eq!(doc["authorization_endpoint"], "https://op.test/authorize");
    assert_eq!(doc["token_endpoint"], "https://op.test/token");
    assert_eq!(doc["userinfo_endpoint"], "https://op.test/userinfo");
    assert_eq!(doc["jwks_uri"], "https://op.test/jwks");
    assert_eq!(
        strings(&doc["id_token_signing_alg_values_supported"]),
        ["RS256"]
    );
    assert_eq!(strings(&doc["code_challenge_methods_supported"]), ["S256"]);
    assert_eq!(doc["authorization_response_iss_parameter_supported"], true);
    assert_eq!(doc["request_uri_parameter_supported"], false);
    assert_eq!(doc["request_parameter_supported"], false);
    // The test tenant has open registration, so `create` is advertised (per-tenant cases in
    // authorize_prompt.rs).
    assert_eq!(
        strings(&doc["prompt_values_supported"]),
        ["none", "login", "consent", "select_account", "create"]
    );
    assert_eq!(strings(&doc["response_types_supported"]), ["code"]);
    assert_eq!(
        strings(&doc["response_modes_supported"]),
        ["query", "form_post"]
    );
    assert_eq!(
        strings(&doc["acr_values_supported"]),
        [anvil_core::model::ACR_PWD, anvil_core::model::ACR_MFA]
    );
    assert_eq!(
        strings(&doc["token_endpoint_auth_signing_alg_values_supported"]),
        ["RS256", "PS256", "ES256"]
    );
}

#[tokio::test]
async fn issuer_has_no_trailing_slash_and_no_none_alg() {
    let app = TestApp::new().await;
    let doc = json(&app.get("/.well-known/openid-configuration").await);
    let issuer = doc["issuer"].as_str().expect("issuer");
    assert!(!issuer.ends_with('/'));
    for field in [
        "id_token_signing_alg_values_supported",
        "token_endpoint_auth_signing_alg_values_supported",
        "introspection_endpoint_auth_signing_alg_values_supported",
        "revocation_endpoint_auth_signing_alg_values_supported",
    ] {
        assert!(!strings(&doc[field]).contains(&"none"), "{field}");
    }
}

#[tokio::test]
async fn introspection_and_revocation_are_advertised() {
    let app = TestApp::new().await;
    let doc = json(&app.get("/.well-known/openid-configuration").await);
    assert_eq!(doc["introspection_endpoint"], "https://op.test/introspect");
    assert_eq!(doc["revocation_endpoint"], "https://op.test/revoke");
    let token_methods = strings(&doc["token_endpoint_auth_methods_supported"]);
    assert_eq!(
        token_methods,
        [
            "client_secret_basic",
            "client_secret_post",
            "private_key_jwt",
            "none"
        ]
    );
    // Revocation accepts every token-endpoint method (public clients revoke their own tokens).
    assert_eq!(
        strings(&doc["revocation_endpoint_auth_methods_supported"]),
        token_methods
    );
    // Introspection refuses public clients, so `none` is not advertised.
    assert_eq!(
        strings(&doc["introspection_endpoint_auth_methods_supported"]),
        [
            "client_secret_basic",
            "client_secret_post",
            "private_key_jwt"
        ]
    );
    for field in [
        "introspection_endpoint_auth_signing_alg_values_supported",
        "revocation_endpoint_auth_signing_alg_values_supported",
    ] {
        assert_eq!(
            doc[field], doc["token_endpoint_auth_signing_alg_values_supported"],
            "{field}"
        );
    }
    // The advertised endpoints exist (POST only).
    for path in ["/introspect", "/revoke"] {
        assert_eq!(app.get(path).await.status, 405, "{path}");
    }
}

#[tokio::test]
async fn id_token_algs_follow_the_tenant_settings() {
    let app = TestApp::new().await;
    app.storage()
        .tenants()
        .create(&NewTenant {
            id: TenantId::new_v7(),
            slug: "acme".into(),
            display_name: "Acme".into(),
            host: None,
            settings: TenantSettings {
                signing_algs: vec!["ES256".into(), "Ed25519".into()],
                ..TenantSettings::default()
            },
            created_at: app.clock().now(),
        })
        .await
        .expect("create the acme tenant");
    let doc = json(&app.get("/t/acme/.well-known/openid-configuration").await);
    // RS256 is always enabled.
    assert_eq!(
        strings(&doc["id_token_signing_alg_values_supported"]),
        ["RS256", "ES256", "Ed25519"]
    );
    // The default tenant still publishes RS256 only.
    let root = json(&app.get("/.well-known/openid-configuration").await);
    assert_eq!(
        strings(&root["id_token_signing_alg_values_supported"]),
        ["RS256"]
    );
}

#[tokio::test]
async fn path_tenant_both_forms_are_identical() {
    let app = TestApp::new().await;
    create_acme(&app).await;
    let a = app.get("/t/acme/.well-known/openid-configuration").await;
    let b = app
        .get("/.well-known/oauth-authorization-server/t/acme")
        .await;
    assert_eq!(a.status, 200);
    assert_eq!(b.status, 200);
    assert_eq!(json(&a), json(&b));
    assert_eq!(json(&a)["issuer"], "https://op.test/t/acme");
    assert_eq!(
        json(&a)["authorization_endpoint"],
        "https://op.test/t/acme/authorize"
    );
    assert_eq!(json(&a)["issuer"], app.issuer(Some("acme")));

    // The root RFC 8414 form serves the default tenant.
    let root = app.get("/.well-known/oauth-authorization-server").await;
    assert_eq!(
        json(&root),
        json(&app.get("/.well-known/openid-configuration").await)
    );
}

#[tokio::test]
async fn only_registered_metadata_is_published() {
    let app = TestApp::new().await;
    let doc = json(&app.get("/.well-known/openid-configuration").await);
    for key in doc.as_object().expect("object").keys() {
        assert!(
            ALLOWED_METADATA.contains(&key.as_str()),
            "unregistered metadata field {key}"
        );
    }
    assert!(!strings(&doc["scopes_supported"]).contains(&"offline_access"));
    let grants = strings(&doc["grant_types_supported"]);
    for g in ["authorization_code", "refresh_token", "client_credentials"] {
        assert!(grants.contains(&g), "{g}");
    }
}

#[tokio::test]
async fn cors_on_discovery_and_jwks() {
    let app = TestApp::new().await;
    for path in ["/.well-known/openid-configuration", "/jwks"] {
        let req = axum::http::Request::get(path)
            .header("origin", "https://rp.example")
            .body(axum::body::Body::empty())
            .expect("request");
        let resp = app.send(req).await;
        assert_eq!(resp.status, 200, "{path}");
        assert_eq!(
            resp.header("access-control-allow-origin"),
            Some("*"),
            "{path}"
        );
        assert!(
            resp.header("content-type")
                .is_some_and(|c| c.starts_with("application/json")),
            "{path}"
        );
    }
}

fn key_row(
    app: &TestApp,
    state: KeyState,
    expires_at: Option<time::OffsetDateTime>,
) -> NewSigningKey {
    let now = app.clock().now();
    let generated = anvil_jose::keys::generate_rs256().expect("RS256 key generation");
    let id = SigningKeyId::new_v7();
    let sealed = app
        .kek()
        .seal(SIGNING_KEY_PURPOSE, &signing_key_aad(id), &generated.pkcs8)
        .expect("seal");
    NewSigningKey {
        id,
        kid: generated.kid.clone(),
        alg: "RS256".into(),
        state,
        private_key_enc: sealed,
        public_jwk: serde_json::to_string(&generated.public_jwk).expect("jwk json"),
        created_at: now,
        activated_at: (state != KeyState::Next).then_some(now),
        retired_at: (state == KeyState::Retired).then_some(now),
        expires_at,
    }
}

#[tokio::test]
async fn jwks_lists_published_public_keys() {
    let app = TestApp::new().await;
    let tenant = app.default.as_ref().expect("default").tenant.id;
    let now = app.clock().now();
    let next = key_row(&app, KeyState::Next, None);
    let retired = key_row(&app, KeyState::Retired, Some(now + time::Duration::days(1)));
    let expired = key_row(
        &app,
        KeyState::Retired,
        Some(now - time::Duration::seconds(1)),
    );
    for k in [&next, &retired, &expired] {
        app.storage()
            .keys()
            .insert(tenant, k)
            .await
            .expect("insert key");
    }

    let resp = app.get("/jwks").await;
    assert_eq!(resp.status, 200);
    assert_eq!(resp.header("cache-control"), Some("public, max-age=3600"));
    let set = json(&resp);
    let keys = set["keys"].as_array().expect("keys array");
    let mut kids = Vec::new();
    for k in keys {
        assert_eq!(k["kty"], "RSA");
        assert_eq!(k["use"], "sig");
        assert_eq!(k["alg"], "RS256");
        assert!(k["n"].is_string() && k["e"].is_string());
        for private in ["d", "p", "q", "dp", "dq", "qi"] {
            assert!(k.get(private).is_none(), "private member {private}");
        }
        let jwk: anvil_jose::Jwk = serde_json::from_value(k.clone()).expect("jwk");
        let kid = k["kid"].as_str().expect("kid").to_owned();
        assert_eq!(kid, anvil_jose::thumbprint(&jwk).expect("thumbprint"));
        kids.push(kid);
    }
    let mut distinct = kids.clone();
    distinct.sort();
    distinct.dedup();
    assert_eq!(distinct.len(), kids.len(), "kids are distinct");

    let active = &app.default.as_ref().expect("default").kid;
    assert!(kids.contains(active), "active key listed");
    assert!(kids.contains(&next.kid), "next key listed");
    assert!(kids.contains(&retired.kid), "retired key listed");
    assert!(!kids.contains(&expired.kid), "expired key not listed");
    assert_eq!(kids.len(), 3);
}

#[tokio::test]
async fn jwks_is_per_tenant() {
    let app = TestApp::new().await;
    create_acme(&app).await;
    let set = json(&app.get("/t/acme/jwks").await);
    let default_kid = &app.default.as_ref().expect("default").kid;
    assert!(
        set["keys"]
            .as_array()
            .expect("keys")
            .iter()
            .all(|k| k["kid"] != default_kid.as_str())
    );
}
