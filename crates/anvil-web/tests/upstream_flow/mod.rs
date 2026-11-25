//! Helpers for driving upstream sign-in through the built-in pages against a [`MockProvider`]
//! (test code only). Used by `upstream_login.rs` and `security_linking.rs` next to
//! `mod support; mod ui_helpers; mod upstream_support;`.
//!
//! The app runs with the production public URL (`https://op.test`, `__Host-` cookies) and the
//! development outbound policy so it can reach the mock on loopback; the route-class limit for
//! auth POSTs is raised so many sign-ins from the one test peer are not cut off by it.

#![allow(dead_code)]

use anvil_cache::limiter::RateQuota;
use anvil_core::model::{
    AuditAction, AuditEvent, AuditQuery, BrowserSession, Connection, ConnectionConfig,
    ConnectionId, IdentityLink, NewConnection, OidcConfig, SecretHash, Tenant, TenantSettings,
    User, UserUpdate,
};
use anvil_core::ports::Clock as _;
use anvil_core::service::connection::seal_secret;
use anvil_web::adapters::outbound::OutboundPolicy;
use axum::body::Body;
use axum::http::{Method, Request, header};
use secrecy::SecretString;
use serde_json::{Value, json};

use crate::support::{TestApp, TestResponse, csrf_from, location};
use crate::ui_helpers::{default_tenant, form_action, set_settings};
use crate::upstream_support::{MOCK_CLIENT_ID, MockKind, MockProvider};

/// Slug of the generic OIDC connection [`setup`] creates.
pub const SLUG: &str = "acme-id";
/// Its display name.
pub const NAME: &str = "Acme ID";
/// The connection secret (test value).
pub const SECRET: &str = "test-client-secret";

/// An app with a mock provider and one connection to it.
pub struct Upstream {
    pub app: TestApp,
    pub mock: MockProvider,
    pub conn: Connection,
}

/// The test app (see the module docs).
pub async fn app() -> TestApp {
    TestApp::with(|c| {
        c.outbound = OutboundPolicy::loopback_dev();
        c.rate_limits.auth = RateQuota::per_minute(6000, 1000);
    })
    .await
}

/// App + generic OIDC mock + connection [`SLUG`] (`trust_email_verified = trust`).
pub async fn setup(trust: bool) -> Upstream {
    let app = app().await;
    let mock = MockProvider::start(MockKind::Oidc).await;
    mock.set_now(app.clock().now().unix_timestamp());
    let config = ConnectionConfig::Oidc(OidcConfig {
        issuer: mock.issuer(),
        client_id: MOCK_CLIENT_ID.into(),
        scopes: vec![],
        use_pkce: true,
        fetch_userinfo: false,
    });
    let conn = add_connection(&app, SLUG, NAME, config, trust).await;
    Upstream { app, mock, conn }
}

/// Creates an enabled connection on the default tenant with [`SECRET`] sealed like production.
pub async fn add_connection(
    app: &TestApp,
    slug: &str,
    name: &str,
    config: ConnectionConfig,
    trust: bool,
) -> Connection {
    let tenant = default_tenant(app).id;
    let id = ConnectionId::new_v7();
    let secret = seal_secret(app.kek(), tenant, id, &SecretString::from(SECRET)).expect("seal");
    app.storage()
        .connections()
        .create(
            tenant,
            &NewConnection {
                id,
                slug: slug.into(),
                display_name: name.into(),
                enabled: true,
                config,
                secret_enc: Some(secret),
                trust_email_verified: trust,
                created_at: app.clock().now(),
            },
        )
        .await
        .expect("create connection")
}

/// Changes the default tenant's settings.
pub async fn tenant_settings(app: &TestApp, f: impl FnOnce(&mut TenantSettings)) {
    let t = default_tenant(app);
    let mut s = t.settings.clone();
    f(&mut s);
    set_settings(app, t.id, s).await;
}

/// A started upstream sign-in: the provider URL and its parameters.
#[derive(Debug)]
pub struct Started {
    pub location: url::Url,
    pub state: String,
    pub nonce: Option<String>,
}

impl Started {
    pub fn param(&self, name: &str) -> Option<String> {
        self.location
            .query_pairs()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.into_owned())
    }
}

/// The `action` of the upstream button form of `slug` in a sign-in page, as a path.
pub fn button_action(app: &TestApp, html: &str, slug: &str) -> String {
    let marker = format!("id=\"upstream-{slug}-form\"");
    let start = html
        .find(&marker)
        .unwrap_or_else(|| panic!("button for {slug} in {html}"));
    form_action(app, &html[start..])
}

/// Posts a start route (`path`, with `csrf`) and expects the 303 to the provider.
pub async fn post_start(app: &TestApp, path: &str, csrf: &str) -> Started {
    let resp = app.post_form(path, &[("csrf_token", csrf)]).await;
    assert_eq!(resp.status, 303, "start: {}", resp.text());
    let location = url::Url::parse(&location(&resp)).expect("provider URL");
    let find = |n: &str| {
        location
            .query_pairs()
            .find(|(k, _)| k == n)
            .map(|(_, v)| v.into_owned())
    };
    Started {
        state: find("state").expect("state"),
        nonce: find("nonce"),
        location,
    }
}

/// Opens the sign-in page and presses the button of `slug`.
pub async fn start(app: &TestApp, slug: &str) -> Started {
    let page = app.get("/ui/login").await;
    assert_eq!(page.status, 200, "{}", page.text());
    let html = page.html();
    let action = button_action(app, &html, slug);
    post_start(app, &action, &csrf_from(&html)).await
}

/// The callback path of `slug` with query `pairs`.
pub fn callback_path(slug: &str, pairs: &[(&str, &str)]) -> String {
    let q = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish();
    format!("/ui/login/upstream/{slug}/callback?{q}")
}

/// The provider returns to the callback (`GET`, with the jar's cookies) with `code`, `state`
/// and the mock's `iss`.
pub async fn callback(u: &Upstream, started: &Started) -> TestResponse {
    let iss = u.mock.issuer();
    u.app
        .get(&callback_path(
            SLUG,
            &[("code", "code-1"), ("state", &started.state), ("iss", &iss)],
        ))
        .await
}

/// The token endpoint answers with an ID token for the started flow's nonce plus `overrides`.
pub fn reply_for(u: &Upstream, started: &Started, overrides: Value) {
    let mut claims = json!({ "nonce": started.nonce.clone().expect("nonce") });
    if let (Value::Object(c), Value::Object(o)) = (&mut claims, overrides) {
        c.extend(o);
    }
    u.mock.respond_with_id_token(claims);
}

/// A full upstream sign-in: start, token reply with `overrides`, callback.
pub async fn sign_in(u: &Upstream, overrides: Value) -> TestResponse {
    let started = start(&u.app, SLUG).await;
    reply_for(u, &started, overrides);
    callback(u, &started).await
}

/// A GET with exactly the jar's cookies accepted by `keep` (cookie name -> keep?).
pub async fn get_with_cookies(
    app: &TestApp,
    path: &str,
    keep: impl Fn(&str) -> bool,
    extra: Option<(&str, &str)>,
) -> TestResponse {
    let mut cookies: Vec<String> = app
        .cookies()
        .into_iter()
        .filter(|(k, _)| keep(k))
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    if let Some((k, v)) = extra {
        cookies.push(format!("{k}={v}"));
    }
    let mut req = Request::builder().method(Method::GET).uri(path);
    // An empty Cookie header still stops the harness from adding the jar.
    req = req.header(header::COOKIE, cookies.join("; "));
    app.send(req.body(Body::empty()).expect("request")).await
}

/// The name of the binding cookie in the jar.
pub fn binding_cookie_name(app: &TestApp) -> String {
    app.cookies()
        .into_keys()
        .find(|k| k.contains("anvil_upstream_"))
        .expect("binding cookie in the jar")
}

/// The browser session behind the jar's session cookie.
pub async fn session(app: &TestApp) -> Option<BrowserSession> {
    let (_, value) = crate::ui_helpers::session_cookie(app)?;
    app.storage()
        .sessions()
        .get_active(
            default_tenant(app).id,
            &SecretHash(anvil_jose::encoding::secret_hash(&value)),
            app.clock().now(),
        )
        .await
        .expect("session lookup")
}

pub async fn user(app: &TestApp, email: &str) -> Option<User> {
    app.storage()
        .users()
        .get_by_email(default_tenant(app).id, email)
        .await
        .expect("user lookup")
}

pub async fn mark_verified(app: &TestApp, email: &str) {
    let u = user(app, email).await.expect("user");
    app.storage()
        .users()
        .update(
            default_tenant(app).id,
            u.id,
            &UserUpdate {
                email_verified: Some(true),
                ..UserUpdate::default()
            },
            app.clock().now(),
        )
        .await
        .expect("update")
        .expect("user");
}

pub async fn links(app: &TestApp, user: &User) -> Vec<IdentityLink> {
    app.storage()
        .connections()
        .links_for_user(default_tenant(app).id, user.id)
        .await
        .expect("links")
}

pub async fn audit(app: &TestApp, action: AuditAction) -> Vec<AuditEvent> {
    app.storage()
        .audit()
        .query(
            default_tenant(app).id,
            &AuditQuery {
                action: Some(action),
                limit: 100,
                ..AuditQuery::default()
            },
        )
        .await
        .expect("audit query")
        .items
}

/// The `reason` details of the `upstream_login_failed` events, newest first.
pub async fn failure_reasons(app: &TestApp) -> Vec<String> {
    audit(app, AuditAction::UpstreamLoginFailed)
        .await
        .iter()
        .filter_map(|e| {
            e.details
                .as_map()
                .get("reason")?
                .as_str()
                .map(str::to_owned)
        })
        .collect()
}

/// The form id of the first form in a page.
pub fn form_id(html: &str) -> String {
    let marker = "<form id=\"";
    let start = html.find(marker).expect("page has a form") + marker.len();
    let end = html[start..].find('"').expect("quoted") + start;
    html[start..end].to_owned()
}

pub fn tenant(app: &TestApp) -> Tenant {
    default_tenant(app)
}
