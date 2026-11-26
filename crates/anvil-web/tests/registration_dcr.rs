//! Dynamic client registration (RFC 7591) and client configuration (RFC 7592) over HTTP on the
//! selected backend (`ANVILID_TEST_DB`): the 201 client information response, GET/PUT/DELETE
//! with the registration access token, hashes at rest, audit events, a code + PKCE flow with the
//! registered client (consent required), path tenants, and the initial access token path.
//! The refusals are in `security_registration.rs`.

mod authz;
mod dcr_support;
mod support;

use anvil_core::model::{
    AuditAction, ClientSource, ConsentId, ConsentMode, DcrPolicy, NewConsent, SecretHash,
};
use anvil_core::ports::Clock as _;
use anvil_jose::encoding::secret_hash;
use axum::http::{Method, StatusCode};
use dcr_support::{
    app, audit_actions, client_path, issue_iat, register, register_at, send_json, set_dcr_of,
    set_policy, web_request,
};
use serde_json::{Value, json};
use support::{json, location};

const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

fn hash(token: &str) -> SecretHash {
    SecretHash(secret_hash(token))
}

fn str_of<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} missing in {v}"))
}

#[tokio::test]
async fn register_read_update_delete() {
    let app = app().await;
    let tenant = set_policy(&app, DcrPolicy::Open).await;
    let iss = app.issuer(None);

    // Register: 201 with the client information response.
    let resp = register(&app, &web_request(), None).await;
    assert_eq!(resp.status, StatusCode::CREATED, "{}", resp.text());
    assert_eq!(resp.header("cache-control"), Some("no-store"));
    let body = json(&resp);
    let client_id = str_of(&body, "client_id").to_owned();
    let secret = str_of(&body, "client_secret").to_owned();
    let rat = str_of(&body, "registration_access_token").to_owned();
    let uri = str_of(&body, "registration_client_uri").to_owned();
    assert_eq!(uri, format!("{iss}/register/{client_id}"));
    assert_eq!(body["client_secret_expires_at"], 0);
    assert!(body["client_id_issued_at"].as_i64().is_some_and(|t| t > 0));
    assert_eq!(body["token_endpoint_auth_method"], "client_secret_basic");
    assert_eq!(body["grant_types"], json!(["authorization_code"]));
    assert_eq!(body["response_types"], json!(["code"]));
    assert_eq!(body["application_type"], "web");
    assert_eq!(body["client_name"], "Partner app");
    assert_eq!(body["redirect_uris"], json!([authz::RP]));
    // Default scopes: the tenant lists none, so the standard scopes apply.
    assert_eq!(body["scope"], "openid profile email address phone");
    assert!(rat.len() >= 43, "256-bit registration access token");

    // Stored: dynamic, consent required, secret and registration access token hashed.
    let row = app
        .storage()
        .clients()
        .get(tenant.id, &client_id)
        .await
        .unwrap()
        .expect("stored");
    assert_eq!(row.registration_source, ClientSource::Dynamic);
    assert_eq!(row.consent_mode, ConsentMode::Required);
    assert!(row.require_pkce);
    assert_eq!(row.secret_hash, Some(hash(&secret)));
    assert_eq!(row.registration_access_token_hash, Some(hash(&rat)));

    // Read.
    let path = client_path(&app, &uri);
    let resp = send_json(&app, Method::GET, &path, Some(&rat), None).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text());
    let read = json(&resp);
    assert_eq!(read["client_id"], client_id.as_str());
    assert_eq!(read["registration_client_uri"], uri.as_str());
    assert_eq!(read["redirect_uris"], body["redirect_uris"]);
    assert_eq!(read["scope"], body["scope"]);
    // Secrets are never returned again.
    assert!(read.get("client_secret").is_none());
    assert!(read.get("registration_access_token").is_none());

    // Update: replaces the metadata.
    let update = json!({
        "client_id": client_id,
        "redirect_uris": ["https://rp.example/other"],
        "client_name": "Renamed",
        "scope": "openid email",
    });
    let resp = send_json(&app, Method::PUT, &path, Some(&rat), Some(&update)).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text());
    let updated = json(&resp);
    assert_eq!(
        updated["redirect_uris"],
        json!(["https://rp.example/other"])
    );
    assert_eq!(updated["client_name"], "Renamed");
    assert_eq!(updated["scope"], "openid email");
    let resp = send_json(&app, Method::GET, &path, Some(&rat), None).await;
    assert_eq!(json(&resp)["client_name"], "Renamed");

    // Delete: 204, then the token no longer authenticates anything.
    let resp = send_json(&app, Method::DELETE, &path, Some(&rat), None).await;
    assert_eq!(resp.status, StatusCode::NO_CONTENT, "{}", resp.text());
    let resp = send_json(&app, Method::GET, &path, Some(&rat), None).await;
    assert_eq!(resp.status, StatusCode::UNAUTHORIZED);
    assert!(
        app.storage()
            .clients()
            .get(tenant.id, &client_id)
            .await
            .unwrap()
            .is_none()
    );

    assert_eq!(
        audit_actions(&app).await,
        [
            AuditAction::ClientRegistered,
            AuditAction::ClientRegistrationUpdated,
            AuditAction::ClientRegistrationDeleted,
        ]
    );
}

#[tokio::test]
async fn public_client_has_no_secret() {
    let app = app().await;
    set_policy(&app, DcrPolicy::Open).await;
    let req = json!({
        "redirect_uris": [authz::RP],
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code", "refresh_token"],
    });
    let resp = register(&app, &req, None).await;
    assert_eq!(resp.status, StatusCode::CREATED, "{}", resp.text());
    let body = json(&resp);
    assert!(body.get("client_secret").is_none());
    assert!(body.get("client_secret_expires_at").is_none());
    assert_eq!(body["token_endpoint_auth_method"], "none");
}

#[tokio::test]
async fn informational_uris_are_not_echoed() {
    let app = app().await;
    set_policy(&app, DcrPolicy::Open).await;
    let mut req = web_request();
    req["logo_uri"] = json!("https://rp.example/logo.png");
    req["client_uri"] = json!("https://rp.example/");
    req["policy_uri"] = json!("https://rp.example/privacy");
    req["tos_uri"] = json!("https://rp.example/tos");
    req["unknown_member"] = json!("ignored");
    let resp = register(&app, &req, None).await;
    assert_eq!(resp.status, StatusCode::CREATED, "{}", resp.text());
    let body = json(&resp);
    for key in [
        "logo_uri",
        "client_uri",
        "policy_uri",
        "tos_uri",
        "unknown_member",
    ] {
        assert!(body.get(key).is_none(), "{key} echoed");
    }
}

#[tokio::test]
async fn registered_client_completes_code_pkce_flow_with_consent() {
    let app = app().await;
    let tenant = set_policy(&app, DcrPolicy::Open).await;
    let req = json!({"redirect_uris": [authz::RP], "token_endpoint_auth_method": "none"});
    let body = json(&register(&app, &req, None).await);
    let client_id = str_of(&body, "client_id").to_owned();

    let user = authz::user(&app, &tenant, "ada@example.com").await;
    let session = authz::session(&app, &tenant, user).await;
    let iss = app.issuer(None);
    let path = authz::authorize_path("", &authz::pkce_params(&client_id));

    // Dynamic clients always ask for consent.
    let resp = authz::get(&app, &path, Some(&session)).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert!(
        location(&resp).starts_with(&format!("{iss}/ui/consent?request=")),
        "{}",
        location(&resp)
    );

    // The user consented (the consent screen itself is covered in consent.rs).
    app.storage()
        .grants()
        .upsert_consent(
            tenant.id,
            &NewConsent {
                id: ConsentId::new_v7(),
                user_id: user,
                client_id: client_id.clone(),
                scopes: vec!["openid".into(), "profile".into()],
                resources: vec![],
                created_at: app.clock().now(),
            },
            app.clock().now(),
        )
        .await
        .expect("consent");
    let resp = authz::get(&app, &path, Some(&session)).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    let code = authz::param(&resp, "code").unwrap_or_else(|| panic!("{}", location(&resp)));

    let resp = app
        .post_form(
            "/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", authz::RP),
                ("code_verifier", VERIFIER),
                ("client_id", &client_id),
            ],
        )
        .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert!(json(&resp)["id_token"].is_string());
}

#[tokio::test]
async fn allow_listed_registration_with_initial_access_token() {
    let app = app().await;
    set_dcr_of(&app, None, |d| {
        d.policy = DcrPolicy::AllowListed;
        d.allowed_redirect_hosts = vec!["rp.example".into()];
    })
    .await;
    let iat = issue_iat(&app, Some(2), None).await;
    let resp = register(&app, &web_request(), Some(&iat)).await;
    assert_eq!(resp.status, StatusCode::CREATED, "{}", resp.text());
    // The initial access token is not the registration access token.
    assert_ne!(json(&resp)["registration_access_token"], iat.as_str());
    let resp = register(&app, &web_request(), Some(&iat)).await;
    assert_eq!(resp.status, StatusCode::CREATED, "{}", resp.text());
    // Two uses, then it is used up.
    let resp = register(&app, &web_request(), Some(&iat)).await;
    assert_eq!(resp.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn path_tenant_registration_uses_its_issuer() {
    let app = app().await;
    authz::path_tenant(&app, "acme").await;
    set_dcr_of(&app, Some("acme"), |d| d.policy = DcrPolicy::Open).await;
    let resp = register_at(&app, "/t/acme", &web_request(), None).await;
    assert_eq!(resp.status, StatusCode::CREATED, "{}", resp.text());
    let body = json(&resp);
    let iss = app.issuer(Some("acme"));
    let uri = str_of(&body, "registration_client_uri");
    assert!(uri.starts_with(&format!("{iss}/register/")), "{uri}");
    let rat = str_of(&body, "registration_access_token");
    let resp = send_json(&app, Method::GET, &client_path(&app, uri), Some(rat), None).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text());

    // The default tenant (still disabled) has no such endpoint.
    let resp = register(&app, &web_request(), None).await;
    assert_eq!(resp.status, StatusCode::NOT_FOUND);
}
