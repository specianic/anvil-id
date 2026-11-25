//! Integration-test harness for anvil-web (test code only).
//!
//! - Backend from `ANVILID_TEST_DB`: `sqlite` (default, `sqlite::memory:`) or `postgres` (one shared
//!   Postgres 18 testcontainer per test binary, a fresh database per test).
//! - [`TestClock`]: settable clock.
//! - [`TestApp`]: the full `anvil_web::app` on that backend, installed with the `system` and
//!   `default` tenants and one active RS256 key each, plus a cookie jar and HTTP helpers.
//!
//! Key installation duplicates the sealing done by the production bootstrap on purpose: the
//! harness must not depend on core services written in parallel.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anvil_core::model::{
    DEFAULT_TENANT_SLUG, InstallPlan, KeyState, NewSetupToken, NewSigningKey, NewTenant, PublicUrl,
    SIGNING_KEY_PURPOSE, SYSTEM_TENANT_SLUG, SecretHash, SigningKeyId, Tenant, TenantBase,
    TenantId, TenantSettings, issuer, signing_key_aad, truncate_to_ms,
};
use anvil_core::ports::{Clock, InstallOutcome, Storage};
use anvil_jose::kek::Kek;
use anvil_web::adapters::argon2::Argon2Pool;
use anvil_web::adapters::hibp::{BreachCheckMode, breach_checker};
use anvil_web::{AppConfig, AppDeps};
use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use http_body_util::BodyExt;
use time::OffsetDateTime;
use tower::ServiceExt;

/// Default public URL of [`TestApp::new`] (production mode: https).
pub const PROD_URL: &str = "https://op.test";
/// Public URL of [`TestApp::dev`] (development mode).
pub const DEV_URL: &str = "http://localhost:8080";

// ---------------------------------------------------------------------------------------------
// Backend selection
// ---------------------------------------------------------------------------------------------

/// The storage backend under test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Sqlite,
    Postgres,
}

impl Backend {
    /// Reads `ANVILID_TEST_DB` (`sqlite` when unset).
    pub fn from_env() -> Self {
        match std::env::var("ANVILID_TEST_DB").as_deref() {
            Ok("postgres") => Self::Postgres,
            Ok("sqlite") | Err(_) => Self::Sqlite,
            Ok(other) => panic!("ANVILID_TEST_DB must be sqlite or postgres, got {other:?}"),
        }
    }

    /// A fresh, migrated storage.
    pub async fn storage(self) -> Arc<dyn Storage> {
        match self {
            Self::Sqlite => {
                let s = anvil_storage_sqlite::SqliteStorage::connect("sqlite::memory:")
                    .await
                    .expect("in-memory SQLite opens");
                s.migrate().await.expect("SQLite migrations apply");
                Arc::new(s)
            }
            Self::Postgres => pg::fresh().await,
        }
    }
}

mod pg {
    use std::sync::Arc;

    use anvil_core::ports::Storage;
    use anvil_storage_postgres::PostgresStorage;
    use sqlx::Connection;
    use testcontainers_modules::postgres::Postgres;
    use testcontainers_modules::testcontainers::{ContainerAsync, ImageExt, runners::AsyncRunner};
    use uuid::Uuid;

    const MAX_CONNECTIONS: u32 = 10;

    static PG: tokio::sync::OnceCell<(ContainerAsync<Postgres>, String)> =
        tokio::sync::OnceCell::const_new();

    async fn server_url() -> &'static str {
        let (_, url) = PG
            .get_or_init(|| async {
                let container = Postgres::default()
                    .with_tag("18-alpine")
                    .with_cmd(["postgres", "-c", "max_connections=500"])
                    .start()
                    .await
                    .expect("docker must be running for ANVILID_TEST_DB=postgres");
                let host = container.get_host().await.expect("container host");
                let port = container
                    .get_host_port_ipv4(5432)
                    .await
                    .expect("container port 5432");
                // Default credentials of the throwaway testcontainers image, not a secret.
                let url = format!("postgres://postgres:postgres@{host}:{port}");
                (container, url)
            })
            .await;
        url
    }

    pub(super) async fn fresh() -> Arc<dyn Storage> {
        let server = server_url().await;
        let db = format!("test_{}", Uuid::now_v7().simple());
        let mut admin = sqlx::PgConnection::connect(&format!("{server}/postgres"))
            .await
            .expect("admin connection to the test Postgres");
        // `db` contains only a UUID's hex digits, so interpolating it is safe.
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {db}")))
            .execute(&mut admin)
            .await
            .expect("create the per-test database");
        admin.close().await.expect("close the admin connection");
        let storage = PostgresStorage::connect(&format!("{server}/{db}"), MAX_CONNECTIONS)
            .await
            .expect("connect to the per-test database");
        storage.migrate().await.expect("Postgres migrations apply");
        Arc::new(storage)
    }
}

// ---------------------------------------------------------------------------------------------
// Clock
// ---------------------------------------------------------------------------------------------

/// A settable clock (millisecond precision, like the system clock).
#[derive(Debug)]
pub struct TestClock(Mutex<OffsetDateTime>);

impl TestClock {
    pub fn new(start: OffsetDateTime) -> Self {
        Self(Mutex::new(truncate_to_ms(start)))
    }

    pub fn set(&self, t: OffsetDateTime) {
        *self.0.lock().expect("clock lock") = truncate_to_ms(t);
    }

    pub fn advance(&self, d: Duration) {
        let mut now = self.0.lock().expect("clock lock");
        *now = truncate_to_ms(*now + d);
    }
}

impl Clock for TestClock {
    fn now(&self) -> OffsetDateTime {
        *self.0.lock().expect("clock lock")
    }
}

// ---------------------------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------------------------

/// A buffered response.
#[derive(Debug, Clone)]
pub struct TestResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl TestResponse {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// The body with minijinja's `&#x2f;` escapes decoded (browsers see `/`).
    pub fn html(&self) -> String {
        self.text().replace("&#x2f;", "/")
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }
}

/// The `Location` header.
pub fn location(resp: &TestResponse) -> String {
    resp.header("location")
        .expect("response has a Location header")
        .to_owned()
}

/// The response body as JSON.
pub fn json(resp: &TestResponse) -> serde_json::Value {
    serde_json::from_slice(&resp.body)
        .unwrap_or_else(|e| panic!("body is JSON ({e}): {}", resp.text()))
}

/// The value of the hidden `csrf_token` input of a rendered form.
pub fn csrf_from(html: &str) -> String {
    let marker = "name=\"csrf_token\" value=\"";
    let start = html.find(marker).expect("page contains a csrf_token input") + marker.len();
    let end = html[start..].find('"').expect("csrf_token value is quoted") + start;
    html[start..end].to_owned()
}

// ---------------------------------------------------------------------------------------------
// TestApp
// ---------------------------------------------------------------------------------------------

/// A tenant installed by the harness.
#[derive(Debug, Clone)]
pub struct InstalledTenant {
    pub tenant: Tenant,
    pub key_id: SigningKeyId,
    pub kid: String,
}

/// The full application on the selected backend.
pub struct TestApp {
    pub backend: Backend,
    pub config: AppConfig,
    router: Router,
    storage: Arc<dyn Storage>,
    clock: Arc<TestClock>,
    kek: Arc<Kek>,
    jar: Mutex<BTreeMap<String, String>>,
    pub system: Option<InstalledTenant>,
    pub default: Option<InstalledTenant>,
}

/// Start time of every test clock (fixed, so time-dependent tests are reproducible).
pub fn start_time() -> OffsetDateTime {
    // 2026-11-25T12:00:00Z
    OffsetDateTime::from_unix_timestamp(1_795_608_000).expect("valid timestamp")
}

impl TestApp {
    /// Installed app with the production-mode public URL `https://op.test`.
    pub async fn new() -> Self {
        Self::with(|_| {}).await
    }

    /// Installed app in development mode (`http://localhost:8080`).
    pub async fn dev() -> Self {
        Self::build(DEV_URL, true, |_| {}).await
    }

    /// Installed app with a customised configuration.
    pub async fn with(f: impl FnOnce(&mut AppConfig)) -> Self {
        Self::build(PROD_URL, true, f).await
    }

    /// Migrated but not installed (no tenants, no keys).
    pub async fn uninstalled() -> Self {
        Self::build(PROD_URL, false, |_| {}).await
    }

    /// Uninstalled, in development mode.
    pub async fn uninstalled_dev() -> Self {
        Self::build(DEV_URL, false, |_| {}).await
    }

    async fn build(public_url: &str, install: bool, f: impl FnOnce(&mut AppConfig)) -> Self {
        let backend = Backend::from_env();
        let storage = backend.storage().await;
        let clock = Arc::new(TestClock::new(start_time()));
        let kek = Arc::new(Kek::generate());
        let mut config = AppConfig::new(PublicUrl::parse(public_url).expect("valid public url"));
        f(&mut config);

        let (system, default) = if install {
            let (s, d) = install_tenants(storage.as_ref(), &kek, clock.now()).await;
            (Some(s), Some(d))
        } else {
            (None, None)
        };

        let hasher = Argon2Pool::new(
            argon2::Params::new(256, 1, 1, None).expect("test argon2 params"),
            4,
        )
        .expect("argon2 pool");
        let deps = AppDeps {
            storage: Arc::clone(&storage),
            clock: Arc::clone(&clock) as Arc<dyn Clock>,
            hasher: Arc::new(hasher),
            breach: breach_checker(BreachCheckMode::Off),
            kek: Arc::clone(&kek),
        };
        let router = anvil_web::app(config.clone(), deps).expect("app builds");
        Self {
            backend,
            config,
            router,
            storage,
            clock,
            kek,
            jar: Mutex::new(BTreeMap::new()),
            system,
            default,
        }
    }

    pub fn storage(&self) -> &dyn Storage {
        self.storage.as_ref()
    }

    pub fn clock(&self) -> &TestClock {
        &self.clock
    }

    pub fn kek(&self) -> &Kek {
        &self.kek
    }

    /// The issuer of the root (`None`, the default tenant) or of a path tenant.
    pub fn issuer(&self, slug: Option<&str>) -> String {
        let base = match slug {
            None => TenantBase::Root,
            Some(s) => TenantBase::Path(s.to_owned()),
        };
        issuer(&self.config.public_url, &base)
    }

    /// The current cookie jar (name → value).
    pub fn cookies(&self) -> BTreeMap<String, String> {
        self.jar.lock().expect("jar lock").clone()
    }

    pub fn clear_cookies(&self) {
        self.jar.lock().expect("jar lock").clear();
    }

    /// Sends a request: adds the public Host (unless set) and the jar's cookies, stores
    /// `Set-Cookie` answers in the jar.
    pub async fn send(&self, mut req: Request<Body>) -> TestResponse {
        if !req.headers().contains_key(header::HOST) {
            let host = self.config.public_url.host_port().to_owned();
            req.headers_mut()
                .insert(header::HOST, host.parse().expect("host header"));
        }
        let cookie_header = {
            let jar = self.jar.lock().expect("jar lock");
            jar.iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; ")
        };
        if !cookie_header.is_empty() && !req.headers().contains_key(header::COOKIE) {
            req.headers_mut().insert(
                header::COOKIE,
                cookie_header.parse().expect("cookie header"),
            );
        }
        let resp = self
            .router
            .clone()
            .oneshot(req)
            .await
            .expect("the router is infallible");
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = resp
            .into_body()
            .collect()
            .await
            .expect("response body")
            .to_bytes()
            .to_vec();
        self.store_cookies(&headers);
        TestResponse {
            status,
            headers,
            body,
        }
    }

    fn store_cookies(&self, headers: &HeaderMap) {
        let mut jar = self.jar.lock().expect("jar lock");
        for v in headers.get_all(header::SET_COOKIE) {
            let Ok(raw) = v.to_str() else { continue };
            let Ok(c) = axum_extra::extract::cookie::Cookie::parse(raw.to_owned()) else {
                continue;
            };
            let expired = c.max_age().is_some_and(|m| m.is_zero() || m.is_negative());
            if expired || c.value().is_empty() {
                jar.remove(c.name());
            } else {
                jar.insert(c.name().to_owned(), c.value().to_owned());
            }
        }
    }

    pub async fn get(&self, path: &str) -> TestResponse {
        self.send(Request::get(path).body(Body::empty()).expect("request"))
            .await
    }

    /// A same-origin form POST (`Sec-Fetch-Site: same-origin`, like a browser).
    pub async fn post_form(&self, path: &str, pairs: &[(&str, &str)]) -> TestResponse {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(pairs)
            .finish();
        self.send(
            Request::builder()
                .method(Method::POST)
                .uri(path)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header("sec-fetch-site", "same-origin")
                .header(header::CONTENT_LENGTH, body.len())
                .body(Body::from(body))
                .expect("request"),
        )
        .await
    }

    /// Follows a redirect: GETs the `Location` (absolute URLs on the public origin become paths).
    pub async fn follow(&self, resp: &TestResponse) -> TestResponse {
        let loc = location(resp);
        let origin = format!(
            "{}://{}",
            self.config.public_url.scheme(),
            self.config.public_url.host_port()
        );
        let path = loc.strip_prefix(&origin).unwrap_or(&loc);
        assert!(
            path.starts_with('/'),
            "redirect leaves the server, cannot follow: {loc}"
        );
        self.get(path).await
    }
}

/// Installs `system` and `default` through `SetupRepo::install`, one active RS256 key each.
async fn install_tenants(
    storage: &dyn Storage,
    kek: &Kek,
    now: OffsetDateTime,
) -> (InstalledTenant, InstalledTenant) {
    let mut tenants = Vec::new();
    let mut keys = Vec::new();
    let mut meta = Vec::new();
    for (slug, name) in [
        (SYSTEM_TENANT_SLUG, "System"),
        (DEFAULT_TENANT_SLUG, "Default"),
    ] {
        let id = TenantId::new_v7();
        tenants.push(NewTenant {
            id,
            slug: slug.to_owned(),
            display_name: name.to_owned(),
            host: None,
            settings: TenantSettings::default(),
            created_at: now,
        });
        let generated = anvil_jose::keys::generate_rs256().expect("RS256 key generation");
        let key_id = SigningKeyId::new_v7();
        let sealed = kek
            .seal(
                SIGNING_KEY_PURPOSE,
                &signing_key_aad(key_id),
                &generated.pkcs8,
            )
            .expect("seal the private key");
        keys.push((
            id,
            NewSigningKey {
                id: key_id,
                kid: generated.kid.clone(),
                alg: generated.alg.as_str().to_owned(),
                state: KeyState::Active,
                private_key_enc: sealed,
                public_jwk: serde_json::to_string(&generated.public_jwk).expect("jwk json"),
                created_at: now,
                activated_at: Some(now),
                retired_at: None,
                expires_at: None,
            },
        ));
        meta.push((slug, key_id, generated.kid));
    }
    let token = anvil_jose::encoding::random_token();
    let plan = InstallPlan {
        tenants,
        keys,
        setup_token: NewSetupToken {
            token_hash: SecretHash(anvil_jose::encoding::secret_hash(&token)),
            created_at: now,
            expires_at: now + time::Duration::hours(1),
        },
    };
    let outcome = storage
        .setup()
        .install(&plan)
        .await
        .expect("SetupRepo::install succeeds");
    assert!(
        matches!(outcome, InstallOutcome::Installed),
        "fresh database installs"
    );

    let mut installed = Vec::new();
    for (slug, key_id, kid) in meta {
        let tenant = storage
            .tenants()
            .get_by_slug(slug)
            .await
            .expect("tenant lookup")
            .expect("installed tenant exists");
        installed.push(InstalledTenant {
            tenant,
            key_id,
            kid,
        });
    }
    let default = installed.pop().expect("default tenant");
    let system = installed.pop().expect("system tenant");
    (system, default)
}
