//! Helpers for driving the self-service pages through the harness (test code only).
//! Used by the `flow_*` and `security_*` test binaries next to `mod support;`.

#![allow(dead_code)]

use std::collections::BTreeMap;

use anvil_core::model::{
    NewTenant, Tenant, TenantId, TenantSettings, TenantUpdate, UserStatus, UserUpdate, open_payload,
};
use anvil_core::ports::Clock as _;
use time::Duration;

use std::sync::{Arc, Mutex};

use anvil_core::model::PublicUrl;
use anvil_core::ports::Storage;
use anvil_core::service::bootstrap::{BootstrapService, InstallResult};
use anvil_jose::kek::Kek;
use anvil_web::adapters::PasswordDispatcher;
use anvil_web::adapters::argon2::Argon2Pool;
use anvil_web::adapters::hibp::{BreachCheckMode, breach_checker};
use anvil_web::{AppConfig, AppDeps};
use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, header};
use http_body_util::BodyExt;
use secrecy::ExposeSecret as _;
use tower::ServiceExt;

use crate::support::{Backend, PROD_URL, TestApp, TestClock, TestResponse, start_time};

/// What the form helpers need from an app under test.
pub trait Client {
    /// `scheme://host[:port]` of the public URL.
    fn origin(&self) -> String;
    fn get(&self, path: &str) -> impl std::future::Future<Output = TestResponse>;
    fn post_form(
        &self,
        path: &str,
        pairs: &[(&str, &str)],
    ) -> impl std::future::Future<Output = TestResponse>;
    fn clear_cookies(&self);
}

impl Client for TestApp {
    fn origin(&self) -> String {
        format!(
            "{}://{}",
            self.config.public_url.scheme(),
            self.config.public_url.host_port()
        )
    }
    async fn get(&self, path: &str) -> TestResponse {
        TestApp::get(self, path).await
    }
    async fn post_form(&self, path: &str, pairs: &[(&str, &str)]) -> TestResponse {
        TestApp::post_form(self, path, pairs).await
    }
    fn clear_cookies(&self) {
        TestApp::clear_cookies(self);
    }
}

/// The `action` of the first form in a page, as a path on the public origin.
pub fn form_action<C: Client>(app: &C, html: &str) -> String {
    let marker = "action=\"";
    let start = html.find(marker).expect("page has a form action") + marker.len();
    let end = html[start..].find('"').expect("action is quoted") + start;
    let action = html[start..end]
        .replace("&#x2f;", "/")
        .replace("&amp;", "&");
    to_path(app, &action)
}

/// An absolute URL on the public origin as a path (other values unchanged).
pub fn to_path<C: Client>(app: &C, url: &str) -> String {
    let origin = app.origin();
    url.strip_prefix(&origin).unwrap_or(url).to_owned()
}

/// The `data-message-key` values in a page (form, field and message-page messages).
pub fn message_keys(html: &str) -> Vec<String> {
    attr_values(html, "data-message-key=\"")
}

/// The `data-error-key` of an error page.
pub fn error_key(html: &str) -> Option<String> {
    attr_values(html, "data-error-key=\"").into_iter().next()
}

fn attr_values(html: &str, marker: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = html;
    while let Some(i) = rest.find(marker) {
        rest = &rest[i + marker.len()..];
        let end = rest.find('"').expect("attribute is quoted");
        out.push(rest[..end].to_owned());
        rest = &rest[end..];
    }
    out
}

/// The text content of the element with `id` (first `>` after the id up to the next `<`).
pub fn element_text(html: &str, id: &str) -> String {
    let marker = format!("id=\"{id}\"");
    let start = html
        .find(&marker)
        .unwrap_or_else(|| panic!("element #{id}"));
    let open = html[start..].find('>').expect("tag closes") + start + 1;
    let close = html[open..].find('<').expect("text ends") + open;
    html[open..close].to_owned()
}

/// GETs a form page (expects 200) and returns `(action path, csrf token)`.
pub async fn open_form<C: Client>(app: &C, path: &str) -> (String, String) {
    let resp = app.get(path).await;
    assert_eq!(resp.status, 200, "GET {path}: {}", resp.text());
    let html = resp.html();
    (form_action(app, &html), crate::support::csrf_from(&html))
}

/// The hidden inputs of a page (`name`, `value`), excluding the CSRF token, decoded.
pub fn hidden_inputs(html: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut rest = html;
    let marker = "<input type=\"hidden\" id=\"";
    while let Some(i) = rest.find(marker) {
        rest = &rest[i + marker.len()..];
        let tag_end = rest.find('>').expect("input closes");
        let tag = &rest[..tag_end];
        let name = attr_values(tag, "name=\"")
            .into_iter()
            .next()
            .unwrap_or_default();
        let value = attr_values(tag, "value=\"")
            .into_iter()
            .next()
            .unwrap_or_default();
        out.push((name, value.replace("&#x2f;", "/")));
        rest = &rest[tag_end..];
    }
    out
}

/// Opens a form page and submits it like a browser: the CSRF token, the form's hidden inputs and
/// `pairs` (a pair overrides a hidden input of the same name).
pub async fn submit_form<C: Client>(app: &C, path: &str, pairs: &[(&str, &str)]) -> TestResponse {
    let resp = app.get(path).await;
    assert_eq!(resp.status, 200, "GET {path}: {}", resp.text());
    let html = resp.html();
    let action = form_action(app, &html);
    let csrf = crate::support::csrf_from(&html);
    let hidden: Vec<(String, String)> = hidden_inputs(&html)
        .into_iter()
        .filter(|(n, _)| !pairs.iter().any(|(k, _)| k == n))
        .collect();
    let mut all: Vec<(&str, &str)> = vec![("csrf_token", &csrf)];
    all.extend(hidden.iter().map(|(k, v)| (k.as_str(), v.as_str())));
    all.extend_from_slice(pairs);
    app.post_form(&action, &all).await
}

/// Self-registers `email` / `password` on the tenant at `base` (`""` or `/t/{slug}`) and forgets
/// the resulting cookies. Returns the registration response.
pub async fn register<C: Client>(app: &C, base: &str, email: &str, password: &str) -> TestResponse {
    let resp = submit_form(
        app,
        &format!("{base}/ui/registration"),
        &[("email", email), ("password", password)],
    )
    .await;
    assert!(
        resp.status == 200 || resp.status == 303,
        "registration succeeds: {} {}",
        resp.status,
        resp.text()
    );
    app.clear_cookies();
    resp
}

/// Submits the login form of the tenant at `base`.
pub async fn login<C: Client>(
    app: &C,
    base: &str,
    identifier: &str,
    password: &str,
) -> TestResponse {
    submit_form(
        app,
        &format!("{base}/ui/login"),
        &[("identifier", identifier), ("password", password)],
    )
    .await
}

/// The session cookie in the jar (name, value), if any.
pub fn session_cookie(app: &TestApp) -> Option<(String, String)> {
    app.cookies()
        .into_iter()
        .find(|(k, _)| k.contains("anvil_session_"))
}

/// The flow cookie in the jar (name, value), if any.
pub fn flow_cookie(app: &TestApp) -> Option<(String, String)> {
    app.cookies()
        .into_iter()
        .find(|(k, _)| k.contains("anvil_flow_"))
}

/// An outbox email with its payload opened.
#[derive(Debug, Clone)]
pub struct SentEmail {
    pub tenant: TenantId,
    pub to: String,
    pub template: String,
    pub payload: BTreeMap<String, String>,
}

/// Claims every due outbox email (through the storage port) and opens the sealed payloads with
/// the KEK. Claimed emails are leased, so each email is returned once.
pub async fn take_emails(app: &TestApp) -> Vec<SentEmail> {
    let now = app.clock().now() + Duration::seconds(1);
    let claimed = app
        .storage()
        .outbox()
        .claim_due(now, 100, std::time::Duration::from_secs(3600))
        .await
        .expect("claim outbox emails");
    claimed
        .into_iter()
        .map(|e| SentEmail {
            tenant: e.tenant_id,
            payload: open_payload(app.kek(), e.tenant_id, &e.payload)
                .expect("outbox payload opens with the KEK"),
            to: e.to,
            template: e.template,
        })
        .collect()
}

/// The `link` of the only email with `template`, as a path.
pub fn link_of(app: &TestApp, emails: &[SentEmail], template: &str) -> String {
    let found: Vec<_> = emails.iter().filter(|e| e.template == template).collect();
    assert_eq!(found.len(), 1, "exactly one {template} email: {emails:?}");
    to_path(app, &found[0].payload["link"])
}

/// The default tenant of the harness.
pub fn default_tenant(app: &TestApp) -> Tenant {
    app.default.as_ref().expect("installed").tenant.clone()
}

/// The system tenant of the harness.
pub fn system_tenant(app: &TestApp) -> Tenant {
    app.system.as_ref().expect("installed").tenant.clone()
}

/// Replaces the settings of a tenant (through the storage port).
pub async fn set_settings(app: &TestApp, tenant: TenantId, settings: TenantSettings) {
    app.storage()
        .tenants()
        .update(
            tenant,
            &TenantUpdate {
                settings: Some(settings),
                ..TenantUpdate::default()
            },
        )
        .await
        .expect("tenant update")
        .expect("tenant exists");
}

/// Creates a path tenant `slug` (through the storage port).
pub async fn create_tenant(app: &TestApp, slug: &str) -> Tenant {
    app.storage()
        .tenants()
        .create(&NewTenant {
            id: TenantId::new_v7(),
            slug: slug.to_owned(),
            display_name: slug.to_owned(),
            host: None,
            settings: TenantSettings::default(),
            created_at: app.clock().now(),
        })
        .await
        .expect("tenant create")
}

/// Blocks a user by email (through the storage port).
pub async fn block_user(app: &TestApp, tenant: TenantId, email: &str) {
    let users = app.storage().users();
    let user = users
        .get_by_email(tenant, email)
        .await
        .expect("lookup")
        .expect("user exists");
    users
        .update(
            tenant,
            user.id,
            &UserUpdate {
                status: Some(UserStatus::Blocked),
                ..UserUpdate::default()
            },
            app.clock().now(),
        )
        .await
        .expect("user update")
        .expect("user exists");
}

/// A page with its per-flow values (CSRF token, flow id in the form action) replaced by fixed
/// placeholders, so two responses can be compared byte for byte.
pub fn normalize(html: &str) -> String {
    let mut out = html.replace("&#x2f;", "/");
    if out.contains("name=\"csrf_token\" value=\"") {
        let csrf = crate::support::csrf_from(&out);
        out = out.replace(&csrf, "CSRF");
    }
    while let Some(i) = out.find("?flow=") {
        let start = i + "?flow=".len();
        let end = out[start..]
            .find(['"', '&'])
            .map_or(out.len(), |e| start + e);
        out.replace_range(i..end, "?FLOW");
    }
    out
}

/// The `<form …>…</form>` fragment of a page, normalised.
pub fn form_fragment(html: &str) -> String {
    let n = normalize(html);
    let start = n.find("<form").expect("page has a form");
    let end = n[start..].find("</form>").expect("form closes") + start + "</form>".len();
    n[start..end].to_owned()
}

// ---------------------------------------------------------------------------------------------
// OwnApp: the application installed through the production BootstrapService, with handles the
// harness does not expose (shared storage `Arc`, the Argon2 pool and its verification counter,
// the setup URL printed at install).
// ---------------------------------------------------------------------------------------------

/// The application installed by `BootstrapService::ensure_installed` (production first start).
pub struct OwnApp {
    pub router: Router,
    pub storage: Arc<dyn Storage>,
    pub clock: Arc<TestClock>,
    pub kek: Arc<Kek>,
    pub hasher: Arc<PasswordDispatcher>,
    pub config: AppConfig,
    /// The setup token from the install-time setup URL.
    pub setup_token: String,
    jar: Mutex<BTreeMap<String, String>>,
}

impl OwnApp {
    pub async fn installed() -> Self {
        let storage = Backend::from_env().storage().await;
        let clock = Arc::new(TestClock::new(start_time()));
        let kek = Arc::new(Kek::generate());
        let config = AppConfig::new(PublicUrl::parse(PROD_URL).expect("valid public url"));
        let hasher = Arc::new(PasswordDispatcher::new(
            Argon2Pool::new(
                argon2::Params::new(256, 1, 1, None).expect("test argon2 params"),
                4,
            )
            .expect("argon2 pool"),
        ));
        let bootstrap = BootstrapService {
            storage: Arc::clone(&storage),
            clock: Arc::clone(&clock) as Arc<dyn anvil_core::ports::Clock>,
            kek: Arc::clone(&kek),
            hasher: Arc::clone(&hasher) as Arc<dyn anvil_core::ports::PasswordHasher>,
            policy: config.password_policy,
            public_url: config.public_url.clone(),
        };
        let setup_url = match bootstrap.ensure_installed().await.expect("install") {
            InstallResult::Installed { setup_url } => setup_url.expose_secret().to_owned(),
            InstallResult::AlreadyInstalled => panic!("fresh database installs"),
        };
        let setup_token = setup_url
            .split_once("token=")
            .expect("setup url carries the token")
            .1
            .to_owned();
        let deps = AppDeps {
            storage: Arc::clone(&storage),
            clock: Arc::clone(&clock) as Arc<dyn anvil_core::ports::Clock>,
            hasher: Arc::clone(&hasher) as Arc<dyn anvil_core::ports::PasswordHasher>,
            breach: breach_checker(BreachCheckMode::Off),
            kek: Arc::clone(&kek),
            domain_txt: Arc::new(crate::support::FakeTxt::default()),
        };
        let router = anvil_web::app(config.clone(), deps).expect("app builds");
        Self {
            router,
            storage,
            clock,
            kek,
            hasher,
            config,
            setup_token,
            jar: Mutex::new(BTreeMap::new()),
        }
    }

    pub async fn tenant(&self, slug: &str) -> Tenant {
        self.storage
            .tenants()
            .get_by_slug(slug)
            .await
            .expect("tenant lookup")
            .expect("installed tenant")
    }

    pub fn cookies(&self) -> BTreeMap<String, String> {
        self.jar.lock().expect("jar lock").clone()
    }

    /// Sends a request with the public Host and the jar's cookies; stores `Set-Cookie` answers.
    pub async fn send(&self, mut req: Request<Body>) -> TestResponse {
        req.headers_mut().insert(
            header::HOST,
            self.config.public_url.host_port().parse().expect("host"),
        );
        // The production router needs the TCP peer (rate limiting, audit context); mirror
        // `support::TestApp::send`, which adds DEFAULT_PEER unless the test set its own.
        if req
            .extensions()
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            .is_none()
        {
            req.extensions_mut()
                .insert(axum::extract::ConnectInfo(crate::support::DEFAULT_PEER));
        }
        let cookie_header = self
            .jar
            .lock()
            .expect("jar lock")
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ");
        if !cookie_header.is_empty() {
            req.headers_mut()
                .insert(header::COOKIE, cookie_header.parse().expect("cookie"));
        }
        let resp = self.router.clone().oneshot(req).await.expect("infallible");
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = resp
            .into_body()
            .collect()
            .await
            .expect("body")
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
            if c.value().is_empty() || c.max_age().is_some_and(|m| m.is_zero()) {
                jar.remove(c.name());
            } else {
                jar.insert(c.name().to_owned(), c.value().to_owned());
            }
        }
    }
}

impl Client for OwnApp {
    fn origin(&self) -> String {
        format!(
            "{}://{}",
            self.config.public_url.scheme(),
            self.config.public_url.host_port()
        )
    }

    async fn get(&self, path: &str) -> TestResponse {
        self.send(Request::get(path).body(Body::empty()).expect("request"))
            .await
    }

    async fn post_form(&self, path: &str, pairs: &[(&str, &str)]) -> TestResponse {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(pairs)
            .finish();
        self.send(
            Request::builder()
                .method(Method::POST)
                .uri(path)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header("sec-fetch-site", "same-origin")
                .body(Body::from(body))
                .expect("request"),
        )
        .await
    }

    fn clear_cookies(&self) {
        self.jar.lock().expect("jar lock").clear();
    }
}
