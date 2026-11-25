//! Seeding and request helpers for the authorization-endpoint tests (test code only).
//!
//! Clients are validated with the production rules (`validate_client` with
//! `validate_redirect_uri`) before they are stored, exactly like `ClientService::create`; the
//! harness exposes storage only as `&dyn Storage`, so the repository is called directly.
//! Users and sessions go through the storage ports; the session cookie carries a known token whose
//! `secret_hash` is stored, under the name from `CookiePolicy::session_name`.

#![allow(dead_code)]

use anvil_core::model::{
    ACR_PWD, ApplicationType, Client, ClientAuthMethod, ClientId, ClientType, GrantType,
    NewBrowserSession, NewClient, NewTenant, NewUser, SecretHash, SessionId, StandardClaims,
    Tenant, TenantId, TenantSettings, UserId, UserStatus,
};
use anvil_core::oauth::redirect::validate_redirect_uri;
use anvil_core::ports::Clock;
use anvil_core::service::client::{
    ClientInput, new_client_id, new_client_secret, uses_secret, validate_client,
};
use anvil_web::cookies::CookiePolicy;
use axum::body::Body;
use axum::http::{Method, Request, header};

use crate::support::{TestApp, TestResponse, location};

/// A valid S256 challenge (RFC 7636 appendix B).
pub const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
/// The registered redirect URI of [`web_client`].
pub const RP: &str = "https://rp.example/cb";

/// The default tenant installed by the harness.
pub fn default_tenant(app: &TestApp) -> Tenant {
    app.default.as_ref().expect("default tenant").tenant.clone()
}

/// Creates the path tenant `slug` (no signing keys; the authorization endpoint does not sign).
pub async fn path_tenant(app: &TestApp, slug: &str) -> Tenant {
    app.storage()
        .tenants()
        .create(&NewTenant {
            id: TenantId::new_v7(),
            slug: slug.into(),
            display_name: slug.into(),
            host: None,
            settings: TenantSettings::default(),
            created_at: app.clock().now(),
        })
        .await
        .expect("create tenant")
}

/// Validates and stores a client.
pub async fn client(app: &TestApp, tenant: &Tenant, input: ClientInput) -> Client {
    validate_client(&input, validate_redirect_uri).expect("valid client input");
    let secret_hash = uses_secret(input.auth_method).then(|| new_client_secret().1);
    let new = NewClient {
        id: ClientId::new_v7(),
        client_id: new_client_id(),
        name: input.name.clone(),
        client_type: input.client_type,
        application_type: input.application_type,
        auth_method: input.auth_method,
        secret_hash,
        jwks: input.jwks.clone(),
        redirect_uris: input.redirect_uris.clone(),
        grant_types: input.grant_types.clone(),
        scopes: input.scopes.clone(),
        require_pkce: input.require_pkce.unwrap_or(true),
        created_at: app.clock().now(),
        token_format: anvil_core::model::TokenFormat::Jwt,
        // The authorization-endpoint tests are about the protocol, not the consent screen
        // (tests/consent.rs switches clients to `required`).
        consent_mode: anvil_core::model::ConsentMode::SkipFirstParty,
        id_token_signed_response_alg: None,
        can_introspect: false,
        post_logout_redirect_uris: vec![],
        backchannel_logout_uri: None,
        backchannel_logout_session_required: false,
        allowed_resources: vec![],
        mfa_policy: None,
    };
    app.storage()
        .clients()
        .create(tenant.id, &new)
        .await
        .expect("create client")
}

fn input(
    client_type: ClientType,
    application_type: ApplicationType,
    redirect_uris: &[&str],
    require_pkce: Option<bool>,
) -> ClientInput {
    ClientInput {
        name: "Test RP".into(),
        client_type,
        application_type,
        auth_method: match client_type {
            ClientType::Confidential => ClientAuthMethod::ClientSecretBasic,
            ClientType::Public => ClientAuthMethod::None,
        },
        redirect_uris: redirect_uris.iter().map(|s| (*s).to_owned()).collect(),
        grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
        scopes: vec!["openid".into(), "profile".into(), "email".into()],
        require_pkce,
        jwks: None,
        jwks_uri: None,
    }
}

/// A confidential web client (PKCE required) with redirect URI [`RP`].
pub async fn web_client(app: &TestApp, tenant: &Tenant) -> Client {
    client(
        app,
        tenant,
        input(ClientType::Confidential, ApplicationType::Web, &[RP], None),
    )
    .await
}

/// A confidential web client with `require_pkce = false` (nonce rule applies).
pub async fn no_pkce_client(app: &TestApp, tenant: &Tenant) -> Client {
    client(
        app,
        tenant,
        input(
            ClientType::Confidential,
            ApplicationType::Web,
            &[RP],
            Some(false),
        ),
    )
    .await
}

/// A confidential web client with the given redirect URIs.
pub async fn web_client_with(app: &TestApp, tenant: &Tenant, uris: &[&str]) -> Client {
    client(
        app,
        tenant,
        input(ClientType::Confidential, ApplicationType::Web, uris, None),
    )
    .await
}

/// A public native client with the given redirect URIs.
pub async fn native_client(app: &TestApp, tenant: &Tenant, uris: &[&str]) -> Client {
    client(
        app,
        tenant,
        input(ClientType::Public, ApplicationType::Native, uris, None),
    )
    .await
}

/// Creates an active user.
pub async fn user(app: &TestApp, tenant: &Tenant, email: &str) -> UserId {
    let id = UserId::new_v7();
    app.storage()
        .users()
        .create(
            tenant.id,
            &NewUser {
                id,
                email: email.into(),
                email_verified: true,
                username: None,
                claims: StandardClaims::default(),
                status: UserStatus::Active,
                created_at: app.clock().now(),
            },
            None,
            None,
            None,
        )
        .await
        .expect("create user");
    id
}

/// Creates a session for `user` authenticated now; returns the `Cookie` header value.
pub async fn session(app: &TestApp, tenant: &Tenant, user: UserId) -> String {
    let now = app.clock().now();
    let token = anvil_jose::encoding::random_token();
    app.storage()
        .sessions()
        .create(
            tenant.id,
            &NewBrowserSession {
                id: SessionId::new_v7(),
                user_id: user,
                token_hash: SecretHash(anvil_jose::encoding::secret_hash(&token)),
                auth_time: now,
                acr: ACR_PWD.into(),
                amr: vec!["pwd".into()],
                created_at: now,
                expires_at: now + time::Duration::days(14),
                idle_expires_at: now + time::Duration::hours(12),
                ip: None,
                user_agent: None,
            },
        )
        .await
        .expect("create session");
    let name = CookiePolicy::new(app.config.is_https()).session_name(tenant);
    format!("{name}={token}")
}

/// `{base}/authorize?{pairs}` (`base` is `""` or `/t/{slug}`).
pub fn authorize_path(base: &str, pairs: &[(&str, &str)]) -> String {
    let q = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish();
    format!("{base}/authorize?{q}")
}

/// The standard parameters of a valid PKCE request.
pub fn pkce_params(client_id: &str) -> Vec<(&str, &str)> {
    vec![
        ("response_type", "code"),
        ("client_id", client_id),
        ("redirect_uri", RP),
        ("scope", "openid profile"),
        ("state", "st-1"),
        ("code_challenge", CHALLENGE),
        ("code_challenge_method", "S256"),
    ]
}

/// GET with an optional `Cookie` header (bypasses the harness jar).
pub async fn get(app: &TestApp, path: &str, cookie: Option<&str>) -> TestResponse {
    let mut req = Request::get(path);
    if let Some(c) = cookie {
        req = req.header(header::COOKIE, c);
    }
    app.send(req.body(Body::empty()).expect("request")).await
}

/// A cross-site form POST (what an RP's auto-submitting form produces).
pub async fn post(
    app: &TestApp,
    path: &str,
    pairs: &[(&str, &str)],
    cookie: Option<&str>,
) -> TestResponse {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish();
    let mut req = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("sec-fetch-site", "cross-site")
        .header(header::ORIGIN, "https://rp.example")
        .header(header::CONTENT_LENGTH, body.len());
    if let Some(c) = cookie {
        req = req.header(header::COOKIE, c);
    }
    let req = req.body(Body::from(body)).expect("request");
    app.send(req).await
}

/// The query parameters of a redirect `Location`.
pub fn query(resp: &TestResponse) -> Vec<(String, String)> {
    let loc = location(resp);
    let url = url::Url::parse(&loc).unwrap_or_else(|e| panic!("absolute Location ({e}): {loc}"));
    url.query_pairs().into_owned().collect()
}

/// The single value of a redirect query parameter.
pub fn param(resp: &TestResponse, name: &str) -> Option<String> {
    let all: Vec<String> = query(resp)
        .into_iter()
        .filter(|(k, _)| k == name)
        .map(|(_, v)| v)
        .collect();
    assert!(all.len() <= 1, "{name} appears more than once");
    all.into_iter().next()
}

/// Asserts a 303 error redirect to `redirect_uri` with `error` and the tenant's `iss`.
pub fn assert_error_redirect(resp: &TestResponse, redirect_uri: &str, error: &str, iss: &str) {
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert!(
        location(resp).starts_with(redirect_uri),
        "{}",
        location(resp)
    );
    assert_eq!(param(resp, "error").as_deref(), Some(error));
    assert_eq!(param(resp, "iss").as_deref(), Some(iss));
}

/// Asserts the themed 400 error page for `key` and **no** `Location` header.
pub fn assert_error_page(resp: &TestResponse, key: &str) {
    assert_eq!(resp.status, 400, "{}", resp.text());
    assert!(
        resp.headers.get(header::LOCATION).is_none(),
        "error page must not redirect"
    );
    assert!(
        resp.html().contains(&format!("data-error-key=\"{key}\"")),
        "{}",
        resp.html()
    );
}

/// Asserts a 303 to the tenant's login page; returns the authorization request id.
pub fn assert_login_redirect(resp: &TestResponse, iss: &str) -> String {
    assert_eq!(resp.status, 303, "{}", resp.text());
    let loc = location(resp);
    let prefix = format!("{iss}/ui/login?request=");
    assert!(loc.starts_with(&prefix), "{loc}");
    loc[prefix.len()..].to_owned()
}
