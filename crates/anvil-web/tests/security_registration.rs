//! Dynamic client registration abuse controls (OIDC-17) over HTTP on the selected backend
//! (`ANVILID_TEST_DB`). Each test proves a refusal: the disabled policy and the system tenant
//! have no endpoint (404, no discovery entry), `allow_listed` needs a valid, unexpired, unused
//! initial access token (401), the redirect-host allow-list, software statements and admin
//! scopes are refused (400, RFC 7591 JSON), RFC 7592 management needs the registration access
//! token (401 with `WWW-Authenticate: Bearer`), registration is rate limited in the `Auth` class
//! and capped by `max_clients`. Refused requests store no client.

mod authz;
mod dcr_support;
mod support;

use std::net::SocketAddr;

use anvil_core::model::{ClientSource, DcrPolicy};
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Method, Request, StatusCode, header};
use dcr_support::{
    app, client_path, issue_iat, register, register_at, send_json, set_dcr_of, set_policy, tenant,
    web_request,
};
use serde_json::{Value, json};
use support::{TestApp, TestResponse, json};
use time::Duration;

/// Asserts an RFC 7591 error: 400 with `error` = `code` and an `error_description`.
fn assert_registration_error(resp: &TestResponse, code: &str) {
    assert_eq!(resp.status, StatusCode::BAD_REQUEST, "{}", resp.text());
    let body = json(resp);
    assert_eq!(body["error"], code, "{body}");
    assert!(body["error_description"].is_string(), "{body}");
}

/// Asserts an RFC 6750 token error: 401 `invalid_token` with a Bearer challenge.
fn assert_invalid_token(resp: &TestResponse) {
    assert_eq!(resp.status, StatusCode::UNAUTHORIZED, "{}", resp.text());
    assert_eq!(json(resp)["error"], "invalid_token");
    let challenge = resp.header("www-authenticate").unwrap_or_default();
    assert!(challenge.starts_with("Bearer"), "{challenge}");
}

/// Number of dynamic clients of the default tenant.
async fn dynamic_clients(app: &TestApp) -> u64 {
    let t = tenant(app, None).await;
    app.storage()
        .registration()
        .count_clients_by_source(t.id, ClientSource::Dynamic)
        .await
        .expect("count")
}

/// Registers an open-policy client; returns (client path, registration access token, body).
async fn registered(app: &TestApp) -> (String, String, Value) {
    let resp = register(app, &web_request(), None).await;
    assert_eq!(resp.status, StatusCode::CREATED, "{}", resp.text());
    let body = json(&resp);
    let path = client_path(app, body["registration_client_uri"].as_str().unwrap());
    let rat = body["registration_access_token"]
        .as_str()
        .unwrap()
        .to_owned();
    (path, rat, body)
}

#[tokio::test]
async fn dcr_disabled_returns_404() {
    let app = app().await; // default policy: disabled
    let resp = register(&app, &web_request(), None).await;
    assert_eq!(resp.status, StatusCode::NOT_FOUND, "{}", resp.text());
    // Same 404 page as a route that does not exist, for every method, whatever the body or token.
    let none = app.get("/no-such-route").await;
    assert_eq!(none.status, StatusCode::NOT_FOUND);
    for r in [&resp, &none] {
        assert!(
            r.html().contains("data-error-key=\"not_found\""),
            "{}",
            r.html()
        );
    }
    assert_eq!(resp.header("content-type"), none.header("content-type"));
    for method in [Method::GET, Method::PUT, Method::DELETE] {
        let resp = send_json(&app, method.clone(), "/register/abc", Some("t"), None).await;
        assert_eq!(resp.status, StatusCode::NOT_FOUND, "{method}");
    }
    let doc = json(&app.get("/.well-known/openid-configuration").await);
    assert!(doc.get("registration_endpoint").is_none());
    assert_eq!(dynamic_clients(&app).await, 0);

    // A client registered while open is not manageable once the policy is disabled again.
    set_policy(&app, DcrPolicy::Open).await;
    let (path, rat, _) = registered(&app).await;
    set_policy(&app, DcrPolicy::Disabled).await;
    let resp = send_json(&app, Method::GET, &path, Some(&rat), None).await;
    assert_eq!(resp.status, StatusCode::NOT_FOUND);
    let resp = register(&app, &web_request(), None).await;
    assert_eq!(resp.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn dcr_system_tenant_always_disabled() {
    let app = app().await;
    for policy in [DcrPolicy::Open, DcrPolicy::AllowListed] {
        set_dcr_of(&app, Some("system"), |d| d.policy = policy).await;
        let resp = register_at(&app, "/t/system", &web_request(), None).await;
        assert_eq!(resp.status, StatusCode::NOT_FOUND, "{policy:?}");
        let doc = json(&app.get("/t/system/.well-known/openid-configuration").await);
        assert!(doc.get("registration_endpoint").is_none(), "{policy:?}");
    }
    let system = tenant(&app, Some("system")).await;
    assert_eq!(
        app.storage()
            .registration()
            .count_clients_by_source(system.id, ClientSource::Dynamic)
            .await
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn dcr_allow_listed_requires_initial_access_token() {
    let app = app().await;
    set_policy(&app, DcrPolicy::AllowListed).await;
    // No token, an unknown token, a malformed header, a non-Bearer scheme.
    assert_invalid_token(&register(&app, &web_request(), None).await);
    assert_invalid_token(&register(&app, &web_request(), Some("guessed-token")).await);
    for value in ["Bearer", "Basic dXNlcjpwYXNz", "Bearer a b"] {
        let req = Request::post("/register")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, value)
            .body(Body::from(web_request().to_string()))
            .unwrap();
        assert_invalid_token(&app.send(req).await);
    }
    // A registration access token is not an initial access token.
    set_policy(&app, DcrPolicy::Open).await;
    let (_, rat, _) = registered(&app).await;
    set_policy(&app, DcrPolicy::AllowListed).await;
    assert_invalid_token(&register(&app, &web_request(), Some(&rat)).await);
    // Unauthenticated requests learn nothing about the metadata rules: 401 before validation.
    assert_invalid_token(&register(&app, &json!({"redirect_uris": "bad"}), None).await);
    assert_eq!(dynamic_clients(&app).await, 1);
    // A token issued for another tenant does not work here.
    authz::path_tenant(&app, "acme").await;
    set_dcr_of(&app, Some("acme"), |d| d.policy = DcrPolicy::AllowListed).await;
    let iat = issue_iat(&app, None, None).await; // default tenant's token
    assert_invalid_token(&register_at(&app, "/t/acme", &web_request(), Some(&iat)).await);
}

#[tokio::test]
async fn dcr_initial_access_token_single_use() {
    let app = app().await;
    set_policy(&app, DcrPolicy::AllowListed).await;
    let iat = issue_iat(&app, Some(1), None).await;
    let resp = register(&app, &web_request(), Some(&iat)).await;
    assert_eq!(resp.status, StatusCode::CREATED, "{}", resp.text());
    assert_invalid_token(&register(&app, &web_request(), Some(&iat)).await);
    assert_eq!(dynamic_clients(&app).await, 1);
}

#[tokio::test]
async fn dcr_rejected_metadata_keeps_the_single_use_token() {
    let app = app().await;
    set_policy(&app, DcrPolicy::AllowListed).await;
    let iat = issue_iat(&app, Some(1), None).await;
    let bad = json!({"redirect_uris": ["http://rp.example/cb"]});
    assert_registration_error(
        &register(&app, &bad, Some(&iat)).await,
        "invalid_redirect_uri",
    );
    let resp = register(&app, &web_request(), Some(&iat)).await;
    assert_eq!(resp.status, StatusCode::CREATED, "{}", resp.text());
}

#[tokio::test]
async fn dcr_expired_initial_access_token_refused() {
    let app = app().await;
    set_policy(&app, DcrPolicy::AllowListed).await;
    let iat = issue_iat(&app, None, Some(Duration::minutes(5))).await;
    app.clock().advance(std::time::Duration::from_secs(5 * 60));
    assert_invalid_token(&register(&app, &web_request(), Some(&iat)).await);
    assert_eq!(dynamic_clients(&app).await, 0);
}

#[tokio::test]
async fn dcr_revoked_initial_access_token_refused() {
    use anvil_core::ports::Clock as _;
    let app = app().await;
    let t = set_policy(&app, DcrPolicy::AllowListed).await;
    let iat = issue_iat(&app, None, None).await;
    let id = app.storage().registration().list_iats(t.id).await.unwrap()[0].id;
    assert!(
        app.storage()
            .registration()
            .revoke_iat(t.id, id, app.clock().now())
            .await
            .unwrap()
    );
    assert_invalid_token(&register(&app, &web_request(), Some(&iat)).await);
}

#[tokio::test]
async fn dcr_initial_access_token_hashed_at_rest() {
    let app = app().await;
    let t = set_policy(&app, DcrPolicy::AllowListed).await;
    let iat = issue_iat(&app, None, None).await;
    let rows = app.storage().registration().list_iats(t.id).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].token_hash.0,
        anvil_jose::encoding::secret_hash(&iat)
    );
    assert!(!format!("{:?}", rows[0]).contains(&iat));
}

#[tokio::test]
async fn dcr_redirect_host_allow_list_enforced() {
    let app = app().await;
    set_dcr_of(&app, None, |d| {
        d.policy = DcrPolicy::AllowListed;
        d.allowed_redirect_hosts = vec!["partner.example".into()];
    })
    .await;
    let iat = issue_iat(&app, None, None).await;
    // rp.example is not listed.
    assert_registration_error(
        &register(&app, &web_request(), Some(&iat)).await,
        "invalid_redirect_uri",
    );
    let mixed = json!({"redirect_uris": ["https://partner.example/cb", "https://evil.example/cb"]});
    assert_registration_error(
        &register(&app, &mixed, Some(&iat)).await,
        "invalid_redirect_uri",
    );
    let logout = json!({
        "redirect_uris": ["https://partner.example/cb"],
        "post_logout_redirect_uris": ["https://evil.example/bye"],
    });
    assert_registration_error(
        &register(&app, &logout, Some(&iat)).await,
        "invalid_client_metadata",
    );
    assert_eq!(dynamic_clients(&app).await, 0);

    // A listed host registers; an update cannot move the redirect to an unlisted host.
    let ok = json!({"redirect_uris": ["https://partner.example/cb"]});
    let resp = register(&app, &ok, Some(&iat)).await;
    assert_eq!(resp.status, StatusCode::CREATED, "{}", resp.text());
    let body = json(&resp);
    let path = client_path(&app, body["registration_client_uri"].as_str().unwrap());
    let rat = body["registration_access_token"].as_str().unwrap();
    let update =
        json!({"client_id": body["client_id"], "redirect_uris": ["https://evil.example/cb"]});
    assert_registration_error(
        &send_json(&app, Method::PUT, &path, Some(rat), Some(&update)).await,
        "invalid_redirect_uri",
    );
}

#[tokio::test]
async fn dcr_software_statement_rejected() {
    let app = app().await;
    set_policy(&app, DcrPolicy::Open).await;
    let mut req = web_request();
    req["software_statement"] = json!("eyJhbGciOiJSUzI1NiJ9.e30.sig");
    assert_registration_error(
        &register(&app, &req, None).await,
        "invalid_software_statement",
    );
    assert_eq!(dynamic_clients(&app).await, 0);
}

#[tokio::test]
async fn dcr_admin_scope_never_registrable() {
    let app = app().await;
    // Even when the tenant (mis)lists admin scopes as registrable.
    set_dcr_of(&app, None, |d| {
        d.policy = DcrPolicy::Open;
        d.allowed_scopes = vec!["openid".into(), "admin:write".into(), "admin:read".into()];
    })
    .await;
    for scope in ["openid admin:write", "admin:read", "admin:clients:write"] {
        let req = json!({"redirect_uris": [authz::RP], "scope": scope});
        assert_registration_error(&register(&app, &req, None).await, "invalid_client_metadata");
    }
    assert_eq!(dynamic_clients(&app).await, 0);
    // The default scope drops them.
    let resp = register(&app, &web_request(), None).await;
    assert_eq!(resp.status, StatusCode::CREATED, "{}", resp.text());
    assert_eq!(json(&resp)["scope"], "openid");
}

#[tokio::test]
async fn dcr_metadata_and_request_shape_rejected() {
    let app = app().await;
    set_policy(&app, DcrPolicy::Open).await;
    let cases = [
        (json!({}), "invalid_redirect_uri"),
        (
            json!({"redirect_uris": ["http://rp.example/cb"]}),
            "invalid_redirect_uri",
        ),
        (
            json!({"redirect_uris": ["https://rp.example/*"]}),
            "invalid_redirect_uri",
        ),
        (
            json!({"redirect_uris": [authz::RP], "jwks_uri": "https://rp.example/jwks"}),
            "invalid_client_metadata",
        ),
        (
            json!({"redirect_uris": [authz::RP], "grant_types": ["password"]}),
            "invalid_client_metadata",
        ),
        (
            json!({"redirect_uris": [authz::RP], "grant_types": ["client_credentials"]}),
            "invalid_client_metadata",
        ),
        (
            json!({"redirect_uris": [authz::RP], "token_endpoint_auth_method": "tls_client_auth"}),
            "invalid_client_metadata",
        ),
        (
            json!({"redirect_uris": [authz::RP], "scope": "openid unknown"}),
            "invalid_client_metadata",
        ),
        (
            json!({"redirect_uris": [authz::RP], "allowed_resources": ["https://api.example/"]}),
            "invalid_client_metadata",
        ),
        (
            json!({"redirect_uris": [authz::RP], "logo_uri": "http://rp.example/logo.png"}),
            "invalid_client_metadata",
        ),
        (json!(["not", "an", "object"]), "invalid_client_metadata"),
    ];
    for (req, code) in cases {
        let resp = register(&app, &req, None).await;
        assert_registration_error(&resp, code);
    }
    // Not JSON, or not sent as application/json (a cross-site form cannot register).
    let req = Request::post("/register")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{not json"))
        .unwrap();
    assert_registration_error(&app.send(req).await, "invalid_client_metadata");
    for ct in ["text/plain", "application/x-www-form-urlencoded"] {
        let req = Request::post("/register")
            .header(header::CONTENT_TYPE, ct)
            .body(Body::from(web_request().to_string()))
            .unwrap();
        assert_registration_error(&app.send(req).await, "invalid_client_metadata");
    }
    // Oversized bodies are refused by the body limit.
    let big = json!({"redirect_uris": [authz::RP], "client_name": "x".repeat(70 * 1024)});
    let resp = register(&app, &big, None).await;
    assert_eq!(resp.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(dynamic_clients(&app).await, 0);
}

#[tokio::test]
async fn dcr_registration_access_token_required() {
    let app = app().await;
    set_policy(&app, DcrPolicy::Open).await;
    let (path, rat, body) = registered(&app).await;
    let update = json!({"client_id": body["client_id"], "redirect_uris": [authz::RP]});
    assert_invalid_token(&send_json(&app, Method::GET, &path, None, None).await);
    assert_invalid_token(&send_json(&app, Method::PUT, &path, None, Some(&update)).await);
    assert_invalid_token(&send_json(&app, Method::DELETE, &path, None, None).await);
    // A token in the query string is not a token.
    let resp = app.get(&format!("{path}?access_token={rat}")).await;
    assert_invalid_token(&resp);
    assert_eq!(dynamic_clients(&app).await, 1);
}

#[tokio::test]
async fn dcr_wrong_registration_access_token_401() {
    let app = app().await;
    set_policy(&app, DcrPolicy::Open).await;
    let (path_a, rat_a, body_a) = registered(&app).await;
    let (_, rat_b, _) = registered(&app).await;
    // Another client's token, a random token, an unknown client.
    let update = json!({"client_id": body_a["client_id"], "redirect_uris": [authz::RP]});
    assert_invalid_token(&send_json(&app, Method::GET, &path_a, Some(&rat_b), None).await);
    assert_invalid_token(&send_json(&app, Method::PUT, &path_a, Some(&rat_b), Some(&update)).await);
    assert_invalid_token(&send_json(&app, Method::DELETE, &path_a, Some(&rat_b), None).await);
    assert_invalid_token(&send_json(&app, Method::GET, &path_a, Some("forged-token"), None).await);
    assert_invalid_token(
        &send_json(&app, Method::GET, "/register/unknown", Some(&rat_a), None).await,
    );
    // The client secret is not a registration access token.
    let secret = body_a["client_secret"].as_str().unwrap();
    assert_invalid_token(&send_json(&app, Method::GET, &path_a, Some(secret), None).await);
    // Without the token, a PUT is refused before its body is looked at.
    let resp = send_json(&app, Method::PUT, &path_a, Some(&rat_b), Some(&json!("x"))).await;
    assert_invalid_token(&resp);
    assert_eq!(dynamic_clients(&app).await, 2);
}

#[tokio::test]
async fn dcr_static_client_not_manageable() {
    let app = app().await;
    let t = set_policy(&app, DcrPolicy::Open).await;
    let client = authz::web_client(&app, &t).await;
    let resp = send_json(
        &app,
        Method::GET,
        &format!("/register/{}", client.client_id),
        Some("any-token"),
        None,
    )
    .await;
    assert_invalid_token(&resp);
    let resp = send_json(
        &app,
        Method::DELETE,
        &format!("/register/{}", client.client_id),
        Some("any-token"),
        None,
    )
    .await;
    assert_invalid_token(&resp);
    assert!(
        app.storage()
            .clients()
            .get(t.id, &client.client_id)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn dcr_update_constraints_rejected() {
    let app = app().await;
    set_policy(&app, DcrPolicy::Open).await;
    let (path, rat, body) = registered(&app).await;
    let id = body["client_id"].clone();
    let with = |k: &str, v: Value| {
        let mut b = json!({"client_id": id, "redirect_uris": [authz::RP]});
        b[k] = v;
        b
    };
    let cases = [
        json!({"redirect_uris": [authz::RP]}),
        with("client_id", json!("another-client")),
        with("registration_access_token", json!(rat)),
        with(
            "registration_client_uri",
            json!("https://op.test/register/x"),
        ),
        with("client_id_issued_at", json!(1)),
        with("client_secret_expires_at", json!(0)),
        with("client_secret", json!("not-the-secret")),
        with("token_endpoint_auth_method", json!("none")),
    ];
    for case in cases {
        let resp = send_json(&app, Method::PUT, &path, Some(&rat), Some(&case)).await;
        assert_registration_error(&resp, "invalid_client_metadata");
    }
    // The matching secret is accepted.
    let ok = with("client_secret", body["client_secret"].clone());
    let resp = send_json(&app, Method::PUT, &path, Some(&rat), Some(&ok)).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text());
}

#[tokio::test]
async fn dcr_rate_limited() {
    // Rate limiting on (the default): `Auth` class, burst 5 per IP.
    let app = TestApp::new().await;
    set_policy(&app, DcrPolicy::Open).await;
    let peer: SocketAddr = "198.51.100.7:40000".parse().unwrap();
    let request = || {
        let mut req = Request::post("/register")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(web_request().to_string()))
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(peer));
        req
    };
    let mut created = 0;
    let mut limited = None;
    for _ in 0..20 {
        let resp = app.send(request()).await;
        if resp.status == StatusCode::TOO_MANY_REQUESTS {
            limited = Some(resp);
            break;
        }
        assert_eq!(resp.status, StatusCode::CREATED, "{}", resp.text());
        created += 1;
    }
    let resp = limited.expect("registration must be rate limited");
    assert!(created <= 10, "{created} registrations before the limit");
    assert!(resp.header("retry-after").is_some());
    assert_eq!(json(&resp)["error"], "invalid_request");
    // The management endpoint shares the class.
    let mut req = Request::get("/register/abc").body(Body::empty()).unwrap();
    req.extensions_mut().insert(ConnectInfo(peer));
    assert_eq!(app.send(req).await.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(dynamic_clients(&app).await, created);
}

#[tokio::test]
async fn dcr_max_clients_enforced() {
    let app = app().await;
    set_dcr_of(&app, None, |d| {
        d.policy = DcrPolicy::Open;
        d.max_clients = 2;
    })
    .await;
    for _ in 0..2 {
        let resp = register(&app, &web_request(), None).await;
        assert_eq!(resp.status, StatusCode::CREATED, "{}", resp.text());
    }
    let resp = register(&app, &web_request(), None).await;
    assert_registration_error(&resp, "invalid_client_metadata");
    assert!(
        json(&resp)["error_description"]
            .as_str()
            .unwrap()
            .contains("limit of 2"),
        "{}",
        resp.text()
    );
    assert_eq!(dynamic_clients(&app).await, 2);
    // Static clients do not count against the cap.
    let t = tenant(&app, None).await;
    authz::web_client(&app, &t).await;
    assert_eq!(dynamic_clients(&app).await, 2);
}
