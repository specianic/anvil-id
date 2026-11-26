//! Helpers for driving upstream sign-in through the built-in pages against a [`MockProvider`]
//! (test code only). Used by `upstream_login.rs`, `security_linking.rs` and `enterprise_oidc.rs`
//! next to `mod support; mod ui_helpers; mod upstream_support;`.
//!
//! Enterprise (org) connections: [`create_org`], [`verify_domain`] and [`add_org_connection`]
//! seed them through the storage traits (the org connection admin API is 06-17). Org connections
//! have no sign-in button, so [`start_at`] posts the start route of any slug directly.
//!
//! The app runs with the production public URL (`https://op.test`, `__Host-` cookies) and the
//! development outbound policy so it can reach the mock on loopback; the route-class limit for
//! auth POSTs is raised so many sign-ins from the one test peer are not cut off by it.

#![allow(dead_code)]

use anvil_cache::limiter::RateQuota;
use anvil_core::model::{
    AuditAction, AuditEvent, AuditQuery, BrowserSession, Connection, ConnectionConfig,
    ConnectionId, IdentityLink, IdentityLinkId, NewConnection, NewIdentityLink, NewOrgDomain,
    NewOrganization, NewRole, OidcConfig, OrgDomain, OrgDomainId, OrgId, OrgSettings, Organization,
    OrganizationUpdate, Role, RoleId, SecretHash, Tenant, TenantSettings, User, UserUpdate,
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
    create_connection(app, slug, name, config, trust, None).await
}

/// A generic OIDC configuration pointing at `mock`.
pub fn mock_oidc_config(mock: &MockProvider) -> ConnectionConfig {
    ConnectionConfig::Oidc(OidcConfig {
        issuer: mock.issuer(),
        client_id: MOCK_CLIENT_ID.into(),
        scopes: vec![],
        use_pkce: true,
        fetch_userinfo: false,
    })
}

/// Creates an organization on the default tenant (no MFA requirement) whose just-in-time
/// members get `default_roles`.
pub async fn create_org(app: &TestApp, slug: &str, default_roles: &[RoleId]) -> Organization {
    app.storage()
        .organizations()
        .create(
            default_tenant(app).id,
            &NewOrganization {
                id: OrgId::new_v7(),
                slug: slug.into(),
                display_name: format!("Org {slug}"),
                mfa_policy: None,
                settings: OrgSettings {
                    default_role_ids: default_roles.to_vec(),
                },
                metadata: json!({}),
                created_at: app.clock().now(),
            },
        )
        .await
        .expect("create org")
}

/// Sets the roles just-in-time members of `org` get.
pub async fn set_default_roles(app: &TestApp, org: &Organization, roles: &[RoleId]) {
    app.storage()
        .organizations()
        .update(
            default_tenant(app).id,
            org.id,
            &OrganizationUpdate {
                settings: Some(OrgSettings {
                    default_role_ids: roles.to_vec(),
                }),
                ..OrganizationUpdate::default()
            },
            app.clock().now(),
        )
        .await
        .expect("update org")
        .expect("org exists");
}

/// Links `user` to `subject` at `conn` directly in storage.
pub async fn link_identity(app: &TestApp, user: &User, conn: &Connection, subject: &str) {
    app.storage()
        .connections()
        .create_link(
            default_tenant(app).id,
            &NewIdentityLink {
                id: IdentityLinkId::new_v7(),
                user_id: user.id,
                connection_id: conn.id,
                subject: subject.into(),
                email_at_link: None,
                metadata: serde_json::Map::new(),
                created_at: app.clock().now(),
            },
        )
        .await
        .expect("create link");
}

/// Creates a role owned by `org` (`org = None`: a tenant role).
pub async fn create_role(app: &TestApp, org: Option<OrgId>, name: &str) -> Role {
    app.storage()
        .roles()
        .create(
            default_tenant(app).id,
            &NewRole {
                id: RoleId::new_v7(),
                org_id: org,
                name: name.into(),
                description: String::new(),
                permissions: vec![format!("{name}:read")],
                created_at: app.clock().now(),
            },
        )
        .await
        .expect("create role")
}

/// Claims `domain` for `org`; `verified` also marks the claim verified (storage intent, as the
/// DNS check would).
pub async fn claim_domain(
    app: &TestApp,
    org: &Organization,
    domain: &str,
    verified: bool,
) -> OrgDomain {
    let tenant = default_tenant(app).id;
    let orgs = app.storage().organizations();
    let claim = orgs
        .create_domain(
            tenant,
            &NewOrgDomain {
                id: OrgDomainId::new_v7(),
                org_id: org.id,
                domain: domain.into(),
                token: "test-challenge-token".into(),
                connection_id: None,
                routing: false,
                allow_local_password: true,
                created_at: app.clock().now(),
            },
        )
        .await
        .expect("create domain");
    if !verified {
        return claim;
    }
    orgs.mark_verified(tenant, claim.id, app.clock().now())
        .await
        .expect("mark verified")
        .expect("domain exists")
}

/// Claims and verifies `domain` for `org`.
pub async fn verify_domain(app: &TestApp, org: &Organization, domain: &str) -> OrgDomain {
    claim_domain(app, org, domain, true).await
}

/// Creates an enabled OIDC connection owned by `org`, pointing at `mock`.
pub async fn add_org_connection(
    app: &TestApp,
    mock: &MockProvider,
    org: &Organization,
    slug: &str,
    trust: bool,
) -> Connection {
    create_connection(
        app,
        slug,
        &format!("{} SSO", org.display_name),
        mock_oidc_config(mock),
        trust,
        Some(org.id),
    )
    .await
}

/// Whether `user` is a member of `org`.
pub async fn is_member(app: &TestApp, org: &Organization, user: &User) -> bool {
    app.storage()
        .organizations()
        .is_member(default_tenant(app).id, org.id, user.id)
        .await
        .expect("is_member")
}

/// The role names `user` holds in `org`.
pub async fn org_role_names(app: &TestApp, org: &Organization, user: &User) -> Vec<String> {
    app.storage()
        .roles()
        .roles_for_user_in_org(default_tenant(app).id, user.id, org.id)
        .await
        .expect("roles in org")
        .into_iter()
        .map(|r| r.name)
        .collect()
}

/// Creates an enabled connection (tenant or org) with [`SECRET`] sealed like production.
async fn create_connection(
    app: &TestApp,
    slug: &str,
    name: &str,
    config: ConnectionConfig,
    trust: bool,
    org_id: Option<OrgId>,
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
                org_id,
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

/// Opens the sign-in page and posts the start route of `slug` directly (with the page's flow and
/// CSRF token), as home-realm discovery will for org connections, which have no button.
pub async fn start_at(app: &TestApp, slug: &str) -> Started {
    let page = app.get("/ui/login").await;
    assert_eq!(page.status, 200, "{}", page.text());
    let html = page.html();
    let action = url::Url::parse(&format!("https://op.test{}", form_action(app, &html)))
        .expect("login form action");
    let flow = action
        .query_pairs()
        .find(|(k, _)| k == "flow")
        .map(|(_, v)| v.into_owned())
        .expect("login form carries the flow");
    post_start(
        app,
        &format!("/ui/login/upstream/{slug}?flow={flow}"),
        &csrf_from(&html),
    )
    .await
}

/// The provider returns to the callback of `slug` (`GET`, with the jar's cookies).
pub async fn callback_at(u: &Upstream, slug: &str, started: &Started) -> TestResponse {
    let iss = u.mock.issuer();
    u.app
        .get(&callback_path(
            slug,
            &[("code", "code-1"), ("state", &started.state), ("iss", &iss)],
        ))
        .await
}

/// A full upstream sign-in through connection `slug` started with [`start_at`].
pub async fn sign_in_at(u: &Upstream, slug: &str, overrides: Value) -> TestResponse {
    let started = start_at(&u.app, slug).await;
    reply_for(u, &started, overrides);
    callback_at(u, slug, &started).await
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
    callback_at(u, SLUG, started).await
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
