//! Dynamic client registration test helpers (test code only): tenant DCR policy switches,
//! initial access tokens issued through `RegistrationService`, and JSON requests to the RFC 7591
//! and RFC 7592 endpoints.

#![allow(dead_code)]

use std::sync::Arc;

use anvil_core::model::{
    AuditAction, AuditQuery, DcrPolicy, DcrSettings, RequestContext, Tenant, TenantUpdate,
};
use anvil_core::oauth::redirect::validate_redirect_uri;
use anvil_core::ports::Clock;
use anvil_core::service::registration::{IatRequest, RegistrationService};
use anvil_web::AppConfig;
use axum::body::Body;
use axum::http::{Method, Request, header};
use secrecy::ExposeSecret as _;
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};

use crate::authz::RP;
use crate::support::{TestApp, TestResponse};

/// A clock frozen at one instant (the test app's clock when the token is issued).
struct At(OffsetDateTime);

impl Clock for At {
    fn now(&self) -> OffsetDateTime {
        self.0
    }
}

/// An app with rate limiting off, so a functional test can send more than the `Auth` burst.
pub async fn app() -> TestApp {
    TestApp::with(|c: &mut AppConfig| c.rate_limits.enabled = false).await
}

/// The tenant `slug` (`None` = the default tenant) as currently stored.
pub async fn tenant(app: &TestApp, slug: Option<&str>) -> Tenant {
    let slug = slug.map_or_else(
        || {
            app.default
                .as_ref()
                .expect("default tenant")
                .tenant
                .slug
                .clone()
        },
        str::to_owned,
    );
    app.storage()
        .tenants()
        .get_by_slug(&slug)
        .await
        .expect("tenant lookup")
        .expect("tenant exists")
}

/// Applies `f` to the DCR settings of the tenant `slug` (`None` = default); returns the tenant.
pub async fn set_dcr_of(
    app: &TestApp,
    slug: Option<&str>,
    f: impl FnOnce(&mut DcrSettings),
) -> Tenant {
    let tenant = tenant(app, slug).await;
    let mut settings = tenant.settings.clone();
    f(&mut settings.dcr);
    app.storage()
        .tenants()
        .update(
            tenant.id,
            &TenantUpdate {
                settings: Some(settings),
                ..TenantUpdate::default()
            },
        )
        .await
        .expect("tenant update")
        .expect("tenant exists")
}

/// Sets the default tenant's DCR policy.
pub async fn set_policy(app: &TestApp, policy: DcrPolicy) -> Tenant {
    set_dcr_of(app, None, |d| d.policy = policy).await
}

/// Issues an initial access token for the default tenant at the app's current time; returns
/// the plaintext value.
pub async fn issue_iat(app: &TestApp, uses: Option<u32>, expires_in: Option<Duration>) -> String {
    let tenant = tenant(app, None).await;
    let service = RegistrationService {
        storage: app.storage_arc(),
        clock: Arc::new(At(app.clock().now())),
        redirect_validator: validate_redirect_uri,
    };
    service
        .issue_iat(
            &tenant,
            IatRequest {
                description: "test".into(),
                expires_in,
                uses,
            },
            anvil_core::model::AuditActor::admin("test-admin"),
            &RequestContext::system(),
        )
        .await
        .expect("issue initial access token")
        .value
        .expose_secret()
        .to_owned()
}

/// A minimal valid web-client registration request.
pub fn web_request() -> Value {
    json!({"redirect_uris": [RP], "client_name": "Partner app"})
}

/// A JSON request to `path` with an optional bearer token.
pub async fn send_json(
    app: &TestApp,
    method: Method,
    path: &str,
    bearer: Option<&str>,
    body: Option<&Value>,
) -> TestResponse {
    let mut req = Request::builder().method(method).uri(path);
    if let Some(token) = bearer {
        req = req.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let body = match body {
        Some(b) => {
            req = req.header(header::CONTENT_TYPE, "application/json");
            Body::from(b.to_string())
        }
        None => Body::empty(),
    };
    app.send(req.body(body).expect("request")).await
}

/// `POST {base}/register` (`base` is `""` or `/t/{slug}`).
pub async fn register_at(
    app: &TestApp,
    base: &str,
    body: &Value,
    bearer: Option<&str>,
) -> TestResponse {
    send_json(
        app,
        Method::POST,
        &format!("{base}/register"),
        bearer,
        Some(body),
    )
    .await
}

/// `POST /register` on the default tenant.
pub async fn register(app: &TestApp, body: &Value, bearer: Option<&str>) -> TestResponse {
    register_at(app, "", body, bearer).await
}

/// The path of an absolute `registration_client_uri` on the app's public origin.
pub fn client_path(app: &TestApp, registration_client_uri: &str) -> String {
    let origin = format!(
        "{}://{}",
        app.config.public_url.scheme(),
        app.config.public_url.host_port()
    );
    registration_client_uri
        .strip_prefix(&origin)
        .unwrap_or_else(|| panic!("{registration_client_uri} is not on {origin}"))
        .to_owned()
}

/// The actions of the default tenant's audit events, oldest first.
pub async fn audit_actions(app: &TestApp) -> Vec<AuditAction> {
    let tenant = tenant(app, None).await;
    let mut actions: Vec<AuditAction> = app
        .storage()
        .audit()
        .query(
            tenant.id,
            &AuditQuery {
                limit: 200,
                ..AuditQuery::default()
            },
        )
        .await
        .expect("audit query")
        .items
        .into_iter()
        .map(|e| e.action)
        .collect();
    actions.reverse();
    actions
}
