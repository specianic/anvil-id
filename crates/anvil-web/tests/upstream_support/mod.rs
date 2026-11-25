//! A mock upstream identity provider for integration tests (test code only).
//!
//! [`MockProvider::start`] binds a wiremock server on 127.0.0.1 (reachable from test apps in
//! development mode, whose outbound policy allow-lists loopback) and serves, depending on the
//! [`MockKind`]:
//!
//! | Path | Kinds | Notes |
//! |------|-------|-------|
//! | `/.well-known/openid-configuration` | Oidc, Google, Apple | issuer = [`MockProvider::issuer`] (the base URL) |
//! | `/common/v2.0/.well-known/openid-configuration` | Microsoft | issuer is the `{tenantid}` template |
//! | `/{tid}/v2.0/.well-known/openid-configuration` | Microsoft | issuer `{base}/{tid}/v2.0` |
//! | `/jwks` | all | current RS256 + ES256 public keys; `Cache-Control` configurable |
//! | `/token` | all | configurable reply; every request is recorded |
//! | `/userinfo` | all but Github | needs `Authorization: Bearer`; configurable JSON |
//! | `/user`, `/user/emails` | Github | need Bearer and the GitHub REST headers |
//!
//! Test keys are generated per provider at runtime (nothing is committed). ID tokens are built
//! with [`MockProvider::id_token`] (RS256) or [`MockProvider::id_token_es256`] from default
//! claims plus overrides (a `null` override removes the claim); attack tokens come from
//! [`MockProvider::id_token_with_alg_none`] and [`MockProvider::id_token_hs256_with_public_key`].
//! The time used for `iat`/`exp` follows [`MockProvider::set_now`] (default: system time), so it
//! can match a test app's clock.

#![allow(dead_code)]

use std::sync::{Arc, Mutex, MutexGuard};

use anvil_jose::encoding::b64url;
use anvil_jose::{Alg, Jwk, SigningKey, generate_es256, generate_rs256};
use anvil_web::adapters::outbound::{OutboundClient, OutboundPolicy};
use anvil_web::adapters::upstream::UpstreamHttp;
use serde_json::{Map, Value, json};
use wiremock::matchers::{header, header_regex, method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

/// The provider flavour the mock imitates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MockKind {
    Oidc,
    Google,
    Microsoft,
    Apple,
    Github,
    Oauth2,
}

impl MockKind {
    fn is_oidc(self) -> bool {
        !matches!(self, Self::Github | Self::Oauth2)
    }
}

/// Default upstream subject of [`MockProvider::id_token`] and the userinfo document.
pub const MOCK_SUBJECT: &str = "upstream-user-1";
/// Default upstream email (verified).
pub const MOCK_EMAIL: &str = "alice@example.com";
/// Default client id the mock expects as `aud`.
pub const MOCK_CLIENT_ID: &str = "mock-client";
/// Microsoft tenant id used in `tid` and the tenant-specific issuer.
pub const MOCK_TENANT_ID: &str = "9188040d-6c67-4c5b-b112-36a304b66dad";
/// Default access token handed out by the token endpoint.
pub const MOCK_ACCESS_TOKEN: &str = "mock-access-token";
/// GitHub numeric user id of the default `/user` document.
pub const MOCK_GITHUB_ID: u64 = 4242;

struct TestKey {
    signer: SigningKey,
    jwk: Jwk,
}

fn rs256_key() -> TestKey {
    let g = generate_rs256().expect("generate RS256 test key");
    TestKey {
        signer: SigningKey::from_pkcs8(&g.kid, Alg::RS256, &g.pkcs8).expect("load RS256 key"),
        jwk: g.public_jwk,
    }
}

fn es256_key() -> TestKey {
    let g = generate_es256().expect("generate ES256 test key");
    TestKey {
        signer: SigningKey::from_pkcs8(&g.kid, Alg::ES256, &g.pkcs8).expect("load ES256 key"),
        jwk: g.public_jwk,
    }
}

/// A canned HTTP reply.
#[derive(Clone)]
struct Reply {
    status: u16,
    body: Vec<u8>,
    content_type: &'static str,
}

impl Reply {
    fn json(status: u16, v: &Value) -> Self {
        Self {
            status,
            body: serde_json::to_vec(v).expect("json"),
            content_type: "application/json",
        }
    }

    fn template(&self) -> ResponseTemplate {
        ResponseTemplate::new(self.status)
            .insert_header("content-type", self.content_type)
            .set_body_bytes(self.body.clone())
    }
}

struct State {
    rs256: TestKey,
    es256: TestKey,
    jwks_cache_control: Option<String>,
    /// Replaces the generated JWKS document when set.
    jwks_reply: Option<Reply>,
    token_reply: Reply,
    userinfo: Value,
    github_user: Value,
    github_emails: Value,
    now: Option<i64>,
}

/// A running mock upstream provider. Dropping it stops the server.
pub struct MockProvider {
    pub server: MockServer,
    pub kind: MockKind,
    state: Arc<Mutex<State>>,
}

struct Dynamic {
    state: Arc<Mutex<State>>,
    what: fn(&State) -> ResponseTemplate,
}

impl Respond for Dynamic {
    fn respond(&self, _req: &Request) -> ResponseTemplate {
        let st = self.state.lock().expect("mock state");
        (self.what)(&st)
    }
}

fn jwks_response(st: &State) -> ResponseTemplate {
    let mut t = match &st.jwks_reply {
        Some(r) => r.template(),
        None => Reply::json(200, &json!({ "keys": [st.rs256.jwk, st.es256.jwk] })).template(),
    };
    if let Some(cc) = &st.jwks_cache_control {
        t = t.insert_header("cache-control", cc.as_str());
    }
    t
}

impl MockProvider {
    /// Starts a mock of `kind` on 127.0.0.1 with fresh RS256 and ES256 test keys.
    pub async fn start(kind: MockKind) -> Self {
        let server = MockServer::start().await;
        let state = Arc::new(Mutex::new(State {
            rs256: rs256_key(),
            es256: es256_key(),
            jwks_cache_control: None,
            jwks_reply: None,
            token_reply: Reply::json(500, &json!({"error": "not configured"})),
            userinfo: json!({
                "sub": MOCK_SUBJECT,
                "email": MOCK_EMAIL,
                "email_verified": true,
                "name": "Alice Example",
            }),
            github_user: json!({
                "id": MOCK_GITHUB_ID,
                "login": "octo",
                "name": "Octo Cat",
                "email": null,
            }),
            github_emails: json!([
                { "email": "octo-secondary@example.com", "primary": false, "verified": true },
                { "email": MOCK_EMAIL, "primary": true, "verified": true },
            ]),
            now: None,
        }));
        let mock = Self {
            server,
            kind,
            state,
        };
        mock.set_default_token_reply();
        mock.mount().await;
        mock
    }

    async fn mount(&self) {
        let dynamic = |what: fn(&State) -> ResponseTemplate| Dynamic {
            state: Arc::clone(&self.state),
            what,
        };
        match self.kind {
            MockKind::Oidc | MockKind::Google | MockKind::Apple => {
                Mock::given(method("GET"))
                    .and(path("/.well-known/openid-configuration"))
                    .respond_with(
                        ResponseTemplate::new(200)
                            .set_body_json(self.discovery_document(&self.issuer())),
                    )
                    .mount(&self.server)
                    .await;
            }
            MockKind::Microsoft => {
                let template = format!("{}/{{tenantid}}/v2.0", self.base_url());
                Mock::given(method("GET"))
                    .and(path("/common/v2.0/.well-known/openid-configuration"))
                    .respond_with(
                        ResponseTemplate::new(200)
                            .set_body_json(self.discovery_document(&template)),
                    )
                    .mount(&self.server)
                    .await;
                Mock::given(method("GET"))
                    .and(path(format!(
                        "/{MOCK_TENANT_ID}/v2.0/.well-known/openid-configuration"
                    )))
                    .respond_with(
                        ResponseTemplate::new(200)
                            .set_body_json(self.discovery_document(&self.issuer())),
                    )
                    .mount(&self.server)
                    .await;
            }
            MockKind::Github | MockKind::Oauth2 => {}
        }
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(dynamic(jwks_response))
            .mount(&self.server)
            .await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(dynamic(|st| st.token_reply.template()))
            .mount(&self.server)
            .await;
        if self.kind == MockKind::Github {
            for (p, what) in [
                (
                    "/user",
                    (|st: &State| ResponseTemplate::new(200).set_body_json(&st.github_user))
                        as fn(&State) -> ResponseTemplate,
                ),
                ("/user/emails", |st: &State| {
                    ResponseTemplate::new(200).set_body_json(&st.github_emails)
                }),
            ] {
                Mock::given(method("GET"))
                    .and(path(p))
                    .and(header_regex("authorization", "^Bearer .+"))
                    .and(header("accept", "application/vnd.github+json"))
                    .and(header("x-github-api-version", "2022-11-28"))
                    .and(header_regex("user-agent", ".+"))
                    .respond_with(dynamic(what))
                    .mount(&self.server)
                    .await;
            }
        } else {
            Mock::given(method("GET"))
                .and(path("/userinfo"))
                .and(header_regex("authorization", "^Bearer .+"))
                .respond_with(dynamic(|st| {
                    ResponseTemplate::new(200).set_body_json(&st.userinfo)
                }))
                .mount(&self.server)
                .await;
        }
        // Anything else (wrong headers, no bearer): 401 so a missing header is visible.
        Mock::given(method("GET"))
            .and(path("/userinfo"))
            .respond_with(ResponseTemplate::new(401))
            .with_priority(10)
            .mount(&self.server)
            .await;
        Mock::given(method("GET"))
            .and(path("/user"))
            .respond_with(ResponseTemplate::new(401))
            .with_priority(10)
            .mount(&self.server)
            .await;
        Mock::given(method("GET"))
            .and(path("/user/emails"))
            .respond_with(ResponseTemplate::new(401))
            .with_priority(10)
            .mount(&self.server)
            .await;
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().expect("mock state")
    }

    fn discovery_document(&self, issuer: &str) -> Value {
        json!({
            "issuer": issuer,
            "authorization_endpoint": self.authorization_endpoint(),
            "token_endpoint": self.token_endpoint(),
            "userinfo_endpoint": self.userinfo_endpoint(),
            "jwks_uri": self.jwks_uri(),
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256", "ES256"],
            "code_challenge_methods_supported": ["S256"],
            "authorization_response_iss_parameter_supported": true,
        })
    }

    // ----- URLs -------------------------------------------------------------------------------

    /// `http://127.0.0.1:{port}` (no trailing slash).
    pub fn base_url(&self) -> String {
        self.server.uri()
    }

    /// The `iss` of tokens this mock signs. Microsoft: `{base}/{MOCK_TENANT_ID}/v2.0`
    /// (matches the `{tenantid}` template); every other kind: the base URL.
    pub fn issuer(&self) -> String {
        match self.kind {
            MockKind::Microsoft => format!("{}/{MOCK_TENANT_ID}/v2.0", self.base_url()),
            _ => self.base_url(),
        }
    }

    /// The issuer a discovery call should be made with: the base URL (Microsoft: the
    /// multi-tenant `{base}/common/v2.0`, whose document carries the `{tenantid}` template).
    pub fn discovery_issuer(&self) -> String {
        match self.kind {
            MockKind::Microsoft => format!("{}/common/v2.0", self.base_url()),
            _ => self.base_url(),
        }
    }

    /// Microsoft only: the issuer template (`{base}/{tenantid}/v2.0`).
    pub fn issuer_template(&self) -> String {
        format!("{}/{{tenantid}}/v2.0", self.base_url())
    }

    /// Not served: the browser is sent here and tests drive the callback themselves.
    pub fn authorization_endpoint(&self) -> String {
        format!("{}/authorize", self.base_url())
    }

    pub fn token_endpoint(&self) -> String {
        format!("{}/token", self.base_url())
    }

    /// `/userinfo` (Github: `/user`).
    pub fn userinfo_endpoint(&self) -> String {
        match self.kind {
            MockKind::Github => format!("{}/user", self.base_url()),
            _ => format!("{}/userinfo", self.base_url()),
        }
    }

    pub fn jwks_uri(&self) -> String {
        format!("{}/jwks", self.base_url())
    }

    /// GitHub-style API base (`/user`, `/user/emails` live under it).
    pub fn api_base_url(&self) -> String {
        self.base_url()
    }

    // ----- Keys and tokens --------------------------------------------------------------------

    /// Sets the Unix time used for `iat`/`exp` (default: system time).
    pub fn set_now(&self, unix: i64) {
        self.lock().now = Some(unix);
    }

    fn now(&self) -> i64 {
        self.lock()
            .now
            .unwrap_or_else(|| time::OffsetDateTime::now_utc().unix_timestamp())
    }

    /// The default ID-token claims: iss, sub, aud = [`MOCK_CLIENT_ID`], iat, exp (+5 min),
    /// email (verified), name; Microsoft adds `tid`/`oid`.
    pub fn default_claims(&self) -> Map<String, Value> {
        let now = self.now();
        let mut c = json!({
            "iss": self.issuer(),
            "sub": MOCK_SUBJECT,
            "aud": MOCK_CLIENT_ID,
            "iat": now,
            "exp": now + 300,
            "email": MOCK_EMAIL,
            "email_verified": true,
            "name": "Alice Example",
            "given_name": "Alice",
            "family_name": "Example",
        });
        if self.kind == MockKind::Microsoft {
            c["tid"] = json!(MOCK_TENANT_ID);
            c["oid"] = json!("00000000-0000-0000-66f3-3332eca7ea81");
        }
        match c {
            Value::Object(m) => m,
            _ => unreachable!(),
        }
    }

    fn claims_with(&self, overrides: Value) -> Map<String, Value> {
        let mut claims = self.default_claims();
        if let Value::Object(o) = overrides {
            for (k, v) in o {
                if v.is_null() {
                    claims.remove(&k);
                } else {
                    claims.insert(k, v);
                }
            }
        }
        claims
    }

    /// An RS256 ID token: [`Self::default_claims`] merged with `overrides` (`null` removes).
    pub fn id_token(&self, overrides: Value) -> String {
        let claims = self.claims_with(overrides);
        self.lock()
            .rs256
            .signer
            .sign_jwt(Some("JWT"), &claims)
            .expect("sign RS256")
    }

    /// Like [`Self::id_token`], signed with the ES256 key.
    pub fn id_token_es256(&self, overrides: Value) -> String {
        let claims = self.claims_with(overrides);
        self.lock()
            .es256
            .signer
            .sign_jwt(Some("JWT"), &claims)
            .expect("sign ES256")
    }

    /// An unsigned token (`alg: none`, empty signature) with the default claims and the RS256 kid.
    pub fn id_token_with_alg_none(&self) -> String {
        let header = json!({ "alg": "none", "typ": "JWT", "kid": self.rs256_kid() });
        format!(
            "{}.{}.",
            b64url(&serde_json::to_vec(&header).expect("json")),
            b64url(&serde_json::to_vec(&self.default_claims()).expect("json")),
        )
    }

    /// Algorithm confusion: an HS256 token keyed with the RS256 public key (its JWK JSON and,
    /// separately, the raw modulus are both plausible attacker choices; this uses the JWK JSON).
    pub fn id_token_hs256_with_public_key(&self) -> String {
        use aws_lc_rs::hmac;
        let jwk = serde_json::to_vec(&self.lock().rs256.jwk).expect("json");
        let header = json!({ "alg": "HS256", "typ": "JWT", "kid": self.rs256_kid() });
        let input = format!(
            "{}.{}",
            b64url(&serde_json::to_vec(&header).expect("json")),
            b64url(&serde_json::to_vec(&self.default_claims()).expect("json")),
        );
        let key = hmac::Key::new(hmac::HMAC_SHA256, &jwk);
        let tag = hmac::sign(&key, input.as_bytes());
        format!("{input}.{}", b64url(tag.as_ref()))
    }

    /// The kid of the current RS256 key.
    pub fn rs256_kid(&self) -> String {
        self.lock().rs256.signer.kid().to_owned()
    }

    /// The kid of the ES256 key.
    pub fn es256_kid(&self) -> String {
        self.lock().es256.signer.kid().to_owned()
    }

    /// Replaces the RS256 key: the JWKS stops publishing the old one and new tokens use the new
    /// kid. Returns the new kid.
    pub fn rotate_key(&self) -> String {
        let key = rs256_key();
        let kid = key.signer.kid().to_owned();
        self.lock().rs256 = key;
        kid
    }

    // ----- JWKS knobs -------------------------------------------------------------------------

    /// The `Cache-Control` header of `/jwks` (`None`: no header).
    pub fn set_jwks_cache_control(&self, value: Option<&str>) {
        self.lock().jwks_cache_control = value.map(str::to_owned);
    }

    /// Serves `body` with `status` at `/jwks` instead of the generated set.
    pub fn set_jwks_reply(&self, status: u16, body: Value) {
        self.lock().jwks_reply = Some(Reply::json(status, &body));
    }

    /// Back to the generated set.
    pub fn reset_jwks_reply(&self) {
        self.lock().jwks_reply = None;
    }

    // ----- Token endpoint knobs ---------------------------------------------------------------

    /// Default reply: `{access_token, token_type: "Bearer", scope}` plus, for OIDC kinds, an
    /// RS256 ID token with the default claims (no `nonce`; use [`Self::respond_with_id_token`]
    /// to add the nonce of the flow under test).
    pub fn set_default_token_reply(&self) {
        let id_token = self.kind.is_oidc().then(|| self.id_token(json!({})));
        self.set_token_reply(200, self.token_body(id_token));
    }

    fn token_body(&self, id_token: Option<String>) -> Value {
        let mut body = json!({
            "access_token": MOCK_ACCESS_TOKEN,
            "token_type": if self.kind == MockKind::Github { "bearer" } else { "Bearer" },
            "scope": "openid email profile",
        });
        if let Some(t) = id_token {
            body["id_token"] = json!(t);
        }
        body
    }

    /// The next token replies carry an RS256 ID token with these claim overrides (e.g.
    /// `json!({"nonce": nonce})`).
    pub fn respond_with_id_token(&self, overrides: Value) {
        let token = self.id_token(overrides);
        self.set_token_reply(200, self.token_body(Some(token)));
    }

    /// The next token replies carry exactly this ID token string.
    pub fn respond_with_raw_id_token(&self, id_token: &str) {
        self.set_token_reply(200, self.token_body(Some(id_token.to_owned())));
    }

    /// The next token replies are `status` with this JSON body.
    pub fn set_token_reply(&self, status: u16, body: Value) {
        self.lock().token_reply = Reply::json(status, &body);
    }

    /// The next token replies are `status` with these raw bytes (any content type).
    pub fn set_token_reply_raw(&self, status: u16, body: Vec<u8>, content_type: &'static str) {
        self.lock().token_reply = Reply {
            status,
            body,
            content_type,
        };
    }

    // ----- API knobs --------------------------------------------------------------------------

    pub fn set_userinfo(&self, v: Value) {
        self.lock().userinfo = v;
    }

    pub fn set_github_user(&self, v: Value) {
        self.lock().github_user = v;
    }

    pub fn set_github_emails(&self, v: Value) {
        self.lock().github_emails = v;
    }

    // ----- Recorded requests ------------------------------------------------------------------

    async fn requests_to(&self, p: &str) -> Vec<Request> {
        self.server
            .received_requests()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|r| r.url.path() == p)
            .collect()
    }

    /// Every POST to `/token`, oldest first.
    pub async fn received_token_requests(&self) -> Vec<Request> {
        self.requests_to("/token").await
    }

    /// Number of `/jwks` fetches so far.
    pub async fn jwks_requests(&self) -> usize {
        self.requests_to("/jwks").await.len()
    }

    /// Number of requests to `path` so far.
    pub async fn request_count(&self, p: &str) -> usize {
        self.requests_to(p).await.len()
    }
}

/// The form fields of a recorded token request.
pub fn form_fields(req: &Request) -> Vec<(String, String)> {
    url::form_urlencoded::parse(&req.body)
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

/// The value of form field `name` of a recorded request.
pub fn form_field(req: &Request, name: &str) -> Option<String> {
    form_fields(req)
        .into_iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v)
}

/// An upstream adapter on the development-mode outbound policy (loopback allowed).
pub fn dev_upstream() -> UpstreamHttp {
    upstream_with(&OutboundPolicy::loopback_dev())
}

/// An upstream adapter on `policy`.
pub fn upstream_with(policy: &OutboundPolicy) -> UpstreamHttp {
    UpstreamHttp::new(Arc::new(
        OutboundClient::new(policy).expect("outbound client"),
    ))
}
