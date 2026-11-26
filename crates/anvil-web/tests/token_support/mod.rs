//! Seeding and request helpers for the token-side tests (`/token`, `/userinfo`). Test code only.
//!
//! No browser: clients are registered through the core registration rules
//! (`service::client::validate_client` + `new_client_id`/`new_client_secret`, i.e. what
//! `ClientService::create` does; the harness exposes storage only by reference), users and
//! sessions through the storage ports, and codes with the pure
//! `service::authorize::build_code` + `GrantRepo::create_code`.

#![allow(dead_code)]

use anvil_core::model::{
    ACR_PWD, AMR_PWD, ApplicationType, AuthorizationParams, BrowserSession, ClaimsRequest, Client,
    ClientAuthMethod, ClientId, ClientType, GrantType, KeyState, NewBrowserSession, NewClient,
    NewPasswordCredential, NewSigningKey, NewTenant, NewUser, OrgId, SIGNING_KEY_PURPOSE,
    SecretHash, SessionId, SigningKeyId, StandardClaims, Tenant, TenantId, TenantSettings, User,
    UserId, UserStatus, signing_key_aad,
};
use anvil_core::oauth::redirect::validate_redirect_uri;
use anvil_core::service::authorize::build_code;
use anvil_core::service::client::{
    ClientInput, new_client_id, new_client_secret, uses_secret, validate_client,
};
use anvil_core::service::key::published_jwks;
use anvil_jose::encoding::{b64url, b64url_decode, random_token, secret_hash};
use anvil_jose::jwk::Jwks;
use anvil_jose::keys::{Alg, SigningKey};
use axum::body::Body;
use axum::http::{Method, Request, header};
use secrecy::ExposeSecret;
use serde_json::Value;

use crate::support::{TestApp, TestResponse, json};

pub const REDIRECT: &str = "https://rp.test/cb";
pub const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
pub const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
pub const NONCE: &str = "n-0S6_WzA2Mj";

/// A registered client and its plaintext secret (secret-based methods only).
#[derive(Debug, Clone)]
pub struct Rp {
    pub client: Client,
    pub secret: Option<String>,
}

impl Rp {
    pub fn id(&self) -> &str {
        &self.client.client_id
    }

    pub fn secret(&self) -> &str {
        self.secret.as_deref().expect("client has a secret")
    }

    /// The client-authentication part of a token request, per the registered method.
    pub fn auth(&self) -> Auth {
        match self.client.auth_method {
            ClientAuthMethod::ClientSecretBasic => {
                Auth::Basic(self.id().into(), self.secret().into())
            }
            ClientAuthMethod::ClientSecretPost => {
                Auth::Post(self.id().into(), self.secret().into())
            }
            ClientAuthMethod::None => Auth::None(self.id().into()),
            ClientAuthMethod::PrivateKeyJwt => panic!("build the assertion with assertion_auth"),
        }
    }
}

/// How a token request authenticates.
#[derive(Debug, Clone)]
pub enum Auth {
    Basic(String, String),
    Post(String, String),
    None(String),
    Assertion(String),
    /// Raw `Authorization` header plus body pairs.
    Raw(Option<String>, Vec<(String, String)>),
}

pub fn default_tenant(app: &TestApp) -> TenantId {
    app.default.as_ref().expect("installed").tenant.id
}

/// A confidential web client (code + refresh, openid profile email address phone).
pub fn web_input(method: ClientAuthMethod) -> ClientInput {
    ClientInput {
        name: "Test RP".into(),
        client_type: ClientType::Confidential,
        application_type: ApplicationType::Web,
        auth_method: method,
        redirect_uris: vec![REDIRECT.into()],
        grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
        scopes: [
            "openid",
            "profile",
            "email",
            "address",
            "phone",
            "offline_access",
        ]
        .map(String::from)
        .to_vec(),
        require_pkce: None,
        jwks: None,
        jwks_uri: None,
    }
}

/// A public (auth `none`) native-style web client with the code grant.
pub fn public_input() -> ClientInput {
    ClientInput {
        client_type: ClientType::Public,
        auth_method: ClientAuthMethod::None,
        ..web_input(ClientAuthMethod::None)
    }
}

/// A confidential client-credentials client.
pub fn cc_input(method: ClientAuthMethod) -> ClientInput {
    ClientInput {
        redirect_uris: vec![],
        grant_types: vec![GrantType::ClientCredentials],
        scopes: vec!["api:read".into(), "api:write".into()],
        ..web_input(method)
    }
}

/// Registers a client the way `ClientService::create` does.
pub async fn register(app: &TestApp, tenant: TenantId, input: ClientInput) -> Rp {
    register_with(app, tenant, input, |_| {}).await
}

/// Registers a client like [`register`], letting `customise` set the stored fields the client
/// input does not carry (organization policy, token format, consent mode, ...).
pub async fn register_with(
    app: &TestApp,
    tenant: TenantId,
    input: ClientInput,
    customise: impl FnOnce(&mut NewClient),
) -> Rp {
    validate_client(&input, validate_redirect_uri).expect("valid client registration");
    let (secret, hash) = if uses_secret(input.auth_method) {
        let (s, h) = new_client_secret();
        (Some(s.expose_secret().to_owned()), Some(h))
    } else {
        (None, None)
    };
    let mut grants = input.grant_types.clone();
    grants.sort();
    grants.dedup();
    let mut new = NewClient {
        id: ClientId::new_v7(),
        client_id: new_client_id(),
        name: input.name,
        client_type: input.client_type,
        application_type: input.application_type,
        auth_method: input.auth_method,
        secret_hash: hash,
        jwks: input.jwks,
        redirect_uris: input.redirect_uris,
        grant_types: grants,
        scopes: input.scopes,
        require_pkce: input.require_pkce.unwrap_or(true),
        created_at: app.clock_now(),
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
    };
    customise(&mut new);
    let client = app
        .storage()
        .clients()
        .create(tenant, &new)
        .await
        .expect("client created");
    Rp { client, secret }
}

/// Small extension so helpers read the test clock without naming the trait everywhere.
pub trait ClockNow {
    fn clock_now(&self) -> time::OffsetDateTime;
}

impl ClockNow for TestApp {
    fn clock_now(&self) -> time::OffsetDateTime {
        use anvil_core::ports::Clock;
        self.clock().now()
    }
}

/// A user with every standard claim filled in.
pub fn full_claims() -> StandardClaims {
    StandardClaims {
        name: Some("Ada Lovelace".into()),
        given_name: Some("Ada".into()),
        family_name: Some("Lovelace".into()),
        nickname: Some("ada".into()),
        preferred_username: Some("ada".into()),
        locale: Some("en-GB".into()),
        zoneinfo: Some("Europe/London".into()),
        phone_number: Some("+44 20 7946 0000".into()),
        phone_number_verified: true,
        address: Some(anvil_core::model::Address {
            formatted: Some("1 Example Street, London".into()),
            street_address: Some("1 Example Street".into()),
            locality: Some("London".into()),
            region: None,
            postal_code: Some("N1 1AA".into()),
            country: Some("GB".into()),
        }),
        ..StandardClaims::default()
    }
}

pub async fn seed_user(app: &TestApp, tenant: TenantId, email: &str) -> User {
    let now = app.clock_now();
    app.storage()
        .users()
        .create(
            tenant,
            &NewUser {
                id: UserId::new_v7(),
                email: email.into(),
                email_verified: true,
                username: None,
                claims: full_claims(),
                status: UserStatus::Active,
                created_at: now,
            },
            Some(&NewPasswordCredential {
                phc: "$argon2id$v=19$m=256,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA".into(),
                created_at: now,
            }),
            None,
            None,
        )
        .await
        .expect("user created")
}

/// An active password session for `user` (auth_time = now).
pub async fn seed_session(app: &TestApp, tenant: TenantId, user: &User) -> BrowserSession {
    let now = app.clock_now();
    let token = random_token();
    let new = NewBrowserSession {
        id: SessionId::new_v7(),
        user_id: user.id,
        token_hash: SecretHash(secret_hash(&token)),
        auth_time: now,
        acr: ACR_PWD.into(),
        amr: vec![AMR_PWD.into()],
        created_at: now,
        expires_at: now + time::Duration::hours(12),
        idle_expires_at: now + time::Duration::hours(1),
        ip: None,
        user_agent: None,
    };
    app.storage()
        .sessions()
        .create(tenant, &new)
        .await
        .expect("session created");
    app.storage()
        .sessions()
        .get_active(tenant, &new.token_hash, now)
        .await
        .expect("session lookup")
        .expect("session is active")
}

/// Authorization parameters as the authorize endpoint would have validated them.
pub fn params(scope: &str, challenge: Option<&str>) -> AuthorizationParams {
    AuthorizationParams {
        redirect_uri: REDIRECT.into(),
        scope: scope.into(),
        state: Some("st".into()),
        nonce: Some(NONCE.into()),
        code_challenge: challenge.map(str::to_owned),
        prompt: vec![],
        max_age: None,
        login_hint: None,
        acr_values: vec![],
        ui_locales: None,
        claims: None,
        response_mode: Default::default(),
        resource: vec![],
        organization: None,
    }
}

pub fn params_with_claims(scope: &str, claims: ClaimsRequest) -> AuthorizationParams {
    AuthorizationParams {
        claims: Some(claims),
        ..params(scope, Some(CHALLENGE))
    }
}

/// Stores a code (and its family) and returns the plaintext code. The code records the
/// tenant's canonical issuer (as if the authorization request came through it).
pub async fn issue_code(
    app: &TestApp,
    tenant: TenantId,
    rp: &Rp,
    session: &BrowserSession,
    p: &AuthorizationParams,
) -> String {
    issue_code_in_org(app, tenant, rp, session, p, None).await
}

/// [`issue_code`] with `org` bound to the code and its family, without any membership check
/// (the authorization endpoint's resolution is bypassed on purpose).
pub async fn issue_code_in_org(
    app: &TestApp,
    tenant: TenantId,
    rp: &Rp,
    session: &BrowserSession,
    p: &AuthorizationParams,
    org: Option<OrgId>,
) -> String {
    let t = app
        .storage()
        .tenants()
        .get(tenant)
        .await
        .expect("tenant lookup")
        .expect("tenant exists");
    let issuer = anvil_core::service::logout::canonical_issuer(&app.config.public_url, &t);
    let (plain, mut code, mut family) =
        build_code(&rp.client, p, session, &issuer, app.clock_now());
    code.org_id = org;
    family.org_id = org;
    app.storage()
        .grants()
        .create_code(tenant, &code, &family)
        .await
        .expect("code stored");
    plain.expose_secret().to_owned()
}

/// RFC 6749 §2.3.1 Basic credentials: base64(urlencode(id) ":" urlencode(secret)).
pub fn basic(id: &str, secret: &str) -> String {
    let enc = |s: &str| url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>();
    let raw = format!("{}:{}", enc(id), enc(secret));
    format!("Basic {}", anvil_jose::encoding::b64std(raw.as_bytes()))
}

/// A form POST without browser headers (as an RP back channel sends it).
pub async fn post_raw(
    app: &TestApp,
    path: &str,
    authorization: Option<&str>,
    pairs: &[(&str, &str)],
) -> TestResponse {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish();
    let mut b = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::CONTENT_LENGTH, body.len());
    if let Some(a) = authorization {
        b = b.header(header::AUTHORIZATION, a);
    }
    app.send(b.body(Body::from(body)).expect("request")).await
}

/// `POST {path}` with the client authentication `auth` added to `pairs`.
pub async fn token_at(
    app: &TestApp,
    path: &str,
    auth: &Auth,
    pairs: &[(&str, &str)],
) -> TestResponse {
    let mut all: Vec<(String, String)> = pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    let mut header = None;
    match auth {
        Auth::Basic(id, secret) => header = Some(basic(id, secret)),
        Auth::Post(id, secret) => {
            all.push(("client_id".into(), id.clone()));
            all.push(("client_secret".into(), secret.clone()));
        }
        Auth::None(id) => all.push(("client_id".into(), id.clone())),
        Auth::Assertion(a) => {
            all.push((
                "client_assertion_type".into(),
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".into(),
            ));
            all.push(("client_assertion".into(), a.clone()));
        }
        Auth::Raw(h, extra) => {
            header = h.clone();
            all.extend(extra.iter().cloned());
        }
    }
    let refs: Vec<(&str, &str)> = all.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    post_raw(app, path, header.as_deref(), &refs).await
}

pub async fn token(app: &TestApp, auth: &Auth, pairs: &[(&str, &str)]) -> TestResponse {
    token_at(app, "/token", auth, pairs).await
}

/// Exchanges a code (with the PKCE verifier) at the default `/token`.
pub async fn exchange(app: &TestApp, rp: &Rp, code: &str) -> TestResponse {
    token(
        app,
        &rp.auth(),
        &[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", REDIRECT),
            ("code_verifier", VERIFIER),
        ],
    )
    .await
}

pub async fn refresh(app: &TestApp, rp: &Rp, rt: &str, scope: Option<&str>) -> TestResponse {
    let mut pairs = vec![("grant_type", "refresh_token"), ("refresh_token", rt)];
    if let Some(s) = scope {
        pairs.push(("scope", s));
    }
    token(app, &rp.auth(), &pairs).await
}

/// Everything a code-flow test starts from: a basic client, a user, a session and a code.
pub struct CodeFlow {
    pub tenant: TenantId,
    pub rp: Rp,
    pub user: User,
    pub session: BrowserSession,
    pub code: String,
}

pub async fn code_flow(app: &TestApp, method: ClientAuthMethod, scope: &str) -> CodeFlow {
    let tenant = default_tenant(app);
    let rp = register(app, tenant, web_input(method)).await;
    let user = seed_user(app, tenant, "ada@example.test").await;
    let session = seed_session(app, tenant, &user).await;
    let code = issue_code(app, tenant, &rp, &session, &params(scope, Some(CHALLENGE))).await;
    CodeFlow {
        tenant,
        rp,
        user,
        session,
        code,
    }
}

/// Runs a code flow to the token response (asserting 200).
pub async fn tokens(app: &TestApp, scope: &str) -> (CodeFlow, Value) {
    let flow = code_flow(app, ClientAuthMethod::ClientSecretBasic, scope).await;
    let resp = exchange(app, &flow.rp, &flow.code).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let body = json(&resp);
    (flow, body)
}

/// Asserts an OAuth error response.
pub fn assert_oauth_error(resp: &TestResponse, status: u16, error: &str) {
    assert_eq!(resp.status.as_u16(), status, "{}", resp.text());
    assert_eq!(json(resp)["error"], error, "{}", resp.text());
    assert_eq!(resp.header("cache-control"), Some("no-store"));
}

/// The JOSE header of a compact JWS.
pub fn jwt_header(jwt: &str) -> Value {
    let h = jwt.split('.').next().expect("header segment");
    serde_json::from_slice(&b64url_decode(h).expect("b64")).expect("header json")
}

/// The (unverified) claims of a compact JWS.
pub fn jwt_claims(jwt: &str) -> Value {
    let p = jwt.split('.').nth(1).expect("payload segment");
    serde_json::from_slice(&b64url_decode(p).expect("b64")).expect("claims json")
}

/// The tenant's published JWK Set as `/jwks` serves it (`service::key::published_jwks`).
pub async fn published(app: &TestApp, tenant: TenantId) -> Jwks {
    published_jwks(app.storage(), app.clock(), tenant)
        .await
        .expect("published keys")
}

/// A second tenant `acme` (path-based, `/t/acme`) with its own active RS256 key.
pub async fn acme(app: &TestApp) -> Tenant {
    let now = app.clock_now();
    let id = TenantId::new_v7();
    let tenant = app
        .storage()
        .tenants()
        .create(&NewTenant {
            id,
            slug: "acme".into(),
            display_name: "Acme".into(),
            host: None,
            settings: TenantSettings::default(),
            created_at: now,
        })
        .await
        .expect("acme tenant");
    let generated = anvil_jose::keys::generate_rs256().expect("key");
    let key_id = SigningKeyId::new_v7();
    let sealed = app
        .kek()
        .seal(
            SIGNING_KEY_PURPOSE,
            &signing_key_aad(key_id),
            &generated.pkcs8,
        )
        .expect("seal");
    app.storage()
        .keys()
        .insert(
            id,
            &NewSigningKey {
                id: key_id,
                kid: generated.kid.clone(),
                alg: generated.alg.as_str().to_owned(),
                state: KeyState::Active,
                private_key_enc: sealed,
                public_jwk: serde_json::to_string(&generated.public_jwk).expect("jwk"),
                created_at: now,
                activated_at: Some(now),
                retired_at: None,
                expires_at: None,
            },
        )
        .await
        .expect("acme key");
    tenant
}

// ---------------------------------------------------------------------------------------------
// private_key_jwt
// ---------------------------------------------------------------------------------------------

/// A client key pair generated in the test: the signer and its public JWK Set JSON.
pub struct ClientKey {
    pub signer: SigningKey,
    pub jwks: String,
    pub kid: String,
}

pub fn client_key() -> ClientKey {
    let g = anvil_jose::keys::generate_rs256().expect("client key");
    let signer = SigningKey::from_pkcs8(&g.kid, Alg::RS256, &g.pkcs8).expect("signer");
    let jwks = serde_json::json!({ "keys": [g.public_jwk] }).to_string();
    ClientKey {
        signer,
        jwks,
        kid: g.kid,
    }
}

/// An unsigned-style token with an arbitrary header (for `none`/HS256 attacks).
pub fn forged(header: &Value, claims: &Value, sig: &[u8]) -> String {
    format!(
        "{}.{}.{}",
        b64url(header.to_string().as_bytes()),
        b64url(claims.to_string().as_bytes()),
        b64url(sig)
    )
}

// ---------------------------------------------------------------------------------------------
// UserInfo
// ---------------------------------------------------------------------------------------------

/// `GET {path}` with an `Authorization` header value.
pub async fn get_with_auth(app: &TestApp, path: &str, authorization: &str) -> TestResponse {
    app.send(
        Request::get(path)
            .header(header::AUTHORIZATION, authorization)
            .body(Body::empty())
            .expect("request"),
    )
    .await
}

/// `GET /userinfo` with `Authorization: Bearer {token}`.
pub async fn userinfo_get(app: &TestApp, token: &str) -> TestResponse {
    get_with_auth(app, "/userinfo", &format!("Bearer {token}")).await
}

/// `POST /userinfo` with the token in the header and an empty form body.
pub async fn userinfo_post_header(app: &TestApp, token: &str) -> TestResponse {
    post_raw(app, "/userinfo", Some(&format!("Bearer {token}")), &[]).await
}

/// `POST /userinfo` with the token as the `access_token` form field (RFC 6750 §2.2).
pub async fn userinfo_post_body(app: &TestApp, token: &str) -> TestResponse {
    post_raw(app, "/userinfo", None, &[("access_token", token)]).await
}

/// Asserts a 401 RFC 6750 `invalid_token` response.
pub fn assert_invalid_token(resp: &TestResponse) {
    assert_eq!(resp.status, 401, "{}", resp.text());
    assert_eq!(
        resp.header("www-authenticate"),
        Some("Bearer error=\"invalid_token\"")
    );
    assert_eq!(json(resp)["error"], "invalid_token");
}
