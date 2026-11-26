//! Pushed authorization request helpers (RFC 9126) for `par.rs` and `security_par.rs`. Test
//! code only.
//!
//! Clients are registered through `token_support::register_with` (the production registration
//! rules) with consent skipped, so a pushed request with a session goes straight to a code.
//! Sessions come from `authz::session` (a cookie header value).

#![allow(dead_code)]

use anvil_core::model::{
    ClientAuthMethod, ConsentMode, NewClient, Tenant, TenantSettings, TenantUpdate,
};
use anvil_core::service::client::ClientInput;
use anvil_jose::encoding::random_token;
use serde_json::{Value, json};

use crate::authz;
use crate::support::{TestApp, TestResponse, json as body_json, location, start_time};
use crate::token_support::{
    Auth, CHALLENGE, ClientKey, NONCE, REDIRECT, Rp, client_key, post_raw, public_input,
    register_with, token_at, web_input,
};

/// The PAR endpoint of the default (root) tenant.
pub const PAR: &str = "/par";
/// The URN prefix of every pushed `request_uri`.
pub const PREFIX: &str = "urn:ietf:params:oauth:request_uri:";

/// A registered client and how it authenticates at `/par` and `/token`.
pub struct ParClient {
    pub rp: Rp,
    /// The signing key of a `private_key_jwt` client.
    pub key: Option<ClientKey>,
}

impl ParClient {
    pub fn id(&self) -> &str {
        self.rp.id()
    }

    /// Fresh client authentication (a new assertion for `private_key_jwt`).
    pub fn auth(&self, issuer: &str) -> Auth {
        match &self.key {
            Some(key) => Auth::Assertion(assertion(key, self.id(), issuer)),
            None => self.rp.auth(),
        }
    }
}

/// A signed client assertion for `client_id` with audience `aud`.
pub fn assertion(key: &ClientKey, client_id: &str, aud: &str) -> String {
    assertion_with(key, client_id, aud, &random_token())
}

/// [`assertion`] with a chosen `jti`.
pub fn assertion_with(key: &ClientKey, client_id: &str, aud: &str, jti: &str) -> String {
    let now = start_time().unix_timestamp();
    let claims: Value = json!({
        "iss": client_id,
        "sub": client_id,
        "aud": aud,
        "iat": now,
        "exp": now + 60,
        "jti": jti,
    });
    key.signer
        .sign_jwt(Some("client-authentication+jwt"), &claims)
        .expect("sign")
}

/// Registers a code-flow client using `method` (consent skipped). `customise` sets stored
/// fields such as `require_pushed_authorization_requests`.
pub async fn par_client_with(
    app: &TestApp,
    method: ClientAuthMethod,
    customise: impl FnOnce(&mut NewClient),
) -> ParClient {
    let tenant = authz::default_tenant(app).id;
    let key = (method == ClientAuthMethod::PrivateKeyJwt).then(client_key);
    let input = match method {
        ClientAuthMethod::None => public_input(),
        m => ClientInput {
            jwks: key.as_ref().map(|k| k.jwks.clone()),
            ..web_input(m)
        },
    };
    let rp = register_with(app, tenant, input, |c| {
        c.consent_mode = ConsentMode::SkipFirstParty;
        customise(c);
    })
    .await;
    ParClient { rp, key }
}

pub async fn par_client(app: &TestApp, method: ClientAuthMethod) -> ParClient {
    par_client_with(app, method, |_| {}).await
}

/// The authorization parameters a client pushes (without `client_id`, which the client
/// authentication adds for `client_secret_post` and `none`).
pub fn pushed_params() -> Vec<(&'static str, &'static str)> {
    vec![
        ("response_type", "code"),
        ("redirect_uri", REDIRECT),
        ("scope", "openid profile"),
        ("state", "pushed-state"),
        ("nonce", NONCE),
        ("code_challenge", CHALLENGE),
        ("code_challenge_method", "S256"),
    ]
}

/// `POST /par` with `auth` and `pairs`.
pub async fn push(app: &TestApp, auth: &Auth, pairs: &[(&str, &str)]) -> TestResponse {
    token_at(app, PAR, auth, pairs).await
}

/// Pushes `pairs` and returns the `request_uri` (asserting the RFC 9126 §2.2 answer).
pub async fn push_ok(app: &TestApp, auth: &Auth, pairs: &[(&str, &str)]) -> String {
    let resp = push(app, auth, pairs).await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    assert_eq!(resp.header("cache-control"), Some("no-store"));
    assert!(resp.header("location").is_none());
    let body = body_json(&resp);
    assert_eq!(body["expires_in"], 60, "{body}");
    let uri = body["request_uri"]
        .as_str()
        .expect("request_uri")
        .to_owned();
    let random = uri.strip_prefix(PREFIX).expect("urn prefix");
    assert_eq!(random.len(), 43, "{uri}");
    assert!(
        random
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
        "{uri}"
    );
    uri
}

/// Pushes the standard parameters for `client`.
pub async fn push_default(app: &TestApp, client: &ParClient) -> String {
    push_ok(app, &client.auth(&app.issuer(None)), &pushed_params()).await
}

/// `GET /authorize?client_id=…&request_uri=…&{extra}` with an optional session cookie.
pub async fn authorize(
    app: &TestApp,
    client_id: &str,
    request_uri: &str,
    extra: &[(&str, &str)],
    cookie: Option<&str>,
) -> TestResponse {
    let mut pairs = vec![("client_id", client_id), ("request_uri", request_uri)];
    pairs.extend_from_slice(extra);
    authz::get(app, &authz::authorize_path("", &pairs), cookie).await
}

/// A user of the default tenant with a session; returns the cookie header value.
pub async fn signed_in(app: &TestApp, email: &str) -> String {
    let tenant = authz::default_tenant(app);
    let user = authz::user(app, &tenant, email).await;
    authz::session(app, &tenant, user).await
}

/// The code of a successful authorization response to [`REDIRECT`] with the pushed state.
pub fn code_of(resp: &TestResponse, issuer: &str) -> String {
    assert_eq!(resp.status, 303, "{}", resp.text());
    let loc = location(resp);
    assert!(loc.starts_with(&format!("{REDIRECT}?")), "{loc}");
    assert_eq!(authz::param(resp, "error"), None, "{loc}");
    assert_eq!(authz::param(resp, "state").as_deref(), Some("pushed-state"));
    assert_eq!(authz::param(resp, "iss").as_deref(), Some(issuer));
    authz::param(resp, "code").expect("code")
}

/// Exchanges `code` at `/token` with the PKCE verifier and the client's authentication.
pub async fn exchange(app: &TestApp, client: &ParClient, code: &str) -> TestResponse {
    token_at(
        app,
        "/token",
        &client.auth(&app.issuer(None)),
        &[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", REDIRECT),
            ("code_verifier", crate::token_support::VERIFIER),
        ],
    )
    .await
}

/// Sets the default tenant's `par.require_pushed_authorization_requests`.
pub async fn require_par_for_tenant(app: &TestApp, on: bool) -> Tenant {
    let tenant = authz::default_tenant(app);
    let mut settings: TenantSettings = tenant.settings.clone();
    settings.par.require_pushed_authorization_requests = on;
    app.storage()
        .tenants()
        .update(
            tenant.id,
            &TenantUpdate {
                display_name: None,
                host: None,
                settings: Some(settings),
            },
        )
        .await
        .expect("tenant update")
        .expect("tenant exists")
}

/// A raw `POST /par` (custom header and body).
pub async fn push_raw(
    app: &TestApp,
    authorization: Option<&str>,
    pairs: &[(&str, &str)],
) -> TestResponse {
    post_raw(app, PAR, authorization, pairs).await
}
