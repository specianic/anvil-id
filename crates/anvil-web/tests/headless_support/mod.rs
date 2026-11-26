//! Helpers for the headless flow API tests (test code only): JSON requests with an `Origin` and
//! the `X-CSRF-Token` header over the harness cookie jar, and the per-tenant origin allow-list
//! set through the storage port. Used next to `mod support;` and `mod ui_helpers;`.

#![allow(dead_code)]

use std::net::SocketAddr;

use anvil_cache::limiter::RateQuota;
use anvil_core::model::{HeadlessSettings, TenantSettings};
use anvil_web::AppConfig;
use axum::body::Body;
use axum::http::{Method, Request, header};
use serde_json::{Value, json};

use crate::support::{TestApp, TestResponse};
use crate::ui_helpers::{default_tenant, set_settings};

/// The single-page app's origin in the tests: same-site with the issuer `https://op.test`.
pub const SPA: &str = "https://app.op.test";
/// An origin that is never allow-listed.
pub const EVIL: &str = "https://evil.test";
/// The API prefix of the default tenant (root).
pub const API: &str = "/api/flows/v1";

/// Raises the route-class limit of auth POSTs so it does not mask what a test checks (the
/// brute-force limits keep their defaults).
pub fn roomy(c: &mut AppConfig) {
    c.rate_limits.auth = RateQuota::per_minute(6000, 1000);
}

/// An installed app (`https://op.test`) whose default tenant allow-lists [`SPA`].
pub async fn app() -> TestApp {
    app_with(|_| {}).await
}

/// [`app`] with a customised configuration.
pub async fn app_with(f: impl FnOnce(&mut AppConfig)) -> TestApp {
    let app = TestApp::with(|c| {
        roomy(c);
        f(c);
    })
    .await;
    allow_origins(&app, &[SPA], TenantSettings::default()).await;
    app
}

/// Replaces the default tenant's settings with `settings` plus the given allow-list.
pub async fn allow_origins(app: &TestApp, origins: &[&str], settings: TenantSettings) {
    let tenant = default_tenant(app);
    set_settings(
        app,
        tenant.id,
        TenantSettings {
            headless: HeadlessSettings {
                allowed_origins: origins.iter().map(|o| (*o).to_owned()).collect(),
            },
            ..settings
        },
    )
    .await;
}

/// One API request.
#[derive(Debug, Clone)]
pub struct Call {
    pub method: Method,
    pub path: String,
    pub origin: Option<String>,
    pub sec_fetch_site: Option<&'static str>,
    pub csrf: Option<String>,
    pub content_type: Option<&'static str>,
    pub body: String,
    pub peer: Option<SocketAddr>,
    /// Further request headers.
    pub headers: Vec<(&'static str, String)>,
}

impl Call {
    /// A JSON `POST` from [`SPA`] (`Sec-Fetch-Site: same-site`, as a browser sends it).
    pub fn post(path: &str, body: &Value) -> Self {
        Self {
            method: Method::POST,
            path: path.to_owned(),
            origin: Some(SPA.into()),
            sec_fetch_site: Some("same-site"),
            csrf: None,
            content_type: Some("application/json"),
            body: body.to_string(),
            peer: None,
            headers: Vec::new(),
        }
    }

    /// A CORS preflight from `origin` for a JSON `POST` with the CSRF header.
    pub fn preflight(path: &str, origin: &str) -> Self {
        Self {
            method: Method::OPTIONS,
            origin: Some(origin.to_owned()),
            content_type: None,
            body: String::new(),
            ..Self::post(path, &Value::Null)
        }
        .header("access-control-request-method", "POST")
        .header(
            "access-control-request-headers",
            "content-type,x-csrf-token",
        )
    }

    /// A `GET` from [`SPA`].
    pub fn get(path: &str) -> Self {
        Self {
            method: Method::GET,
            content_type: None,
            body: String::new(),
            ..Self::post(path, &Value::Null)
        }
    }

    pub fn origin(mut self, origin: Option<&str>) -> Self {
        self.origin = origin.map(str::to_owned);
        self
    }

    pub fn site(mut self, site: Option<&'static str>) -> Self {
        self.sec_fetch_site = site;
        self
    }

    pub fn csrf(mut self, csrf: &str) -> Self {
        self.csrf = Some(csrf.to_owned());
        self
    }

    pub fn content_type(mut self, ct: Option<&'static str>, body: &str) -> Self {
        self.content_type = ct;
        self.body = body.to_owned();
        self
    }

    pub fn header(mut self, name: &'static str, value: &str) -> Self {
        self.headers.push((name, value.to_owned()));
        self
    }

    pub fn peer(mut self, peer: SocketAddr) -> Self {
        self.peer = Some(peer);
        self
    }

    pub async fn send(self, app: &TestApp) -> TestResponse {
        let mut b = Request::builder().method(self.method).uri(&self.path);
        if let Some(o) = &self.origin {
            b = b.header(header::ORIGIN, o);
        }
        if let Some(s) = self.sec_fetch_site {
            b = b.header("sec-fetch-site", s);
        }
        if let Some(c) = &self.csrf {
            b = b.header("x-csrf-token", c);
        }
        if let Some(ct) = self.content_type {
            b = b.header(header::CONTENT_TYPE, ct);
        }
        for (k, v) in &self.headers {
            b = b.header(*k, v);
        }
        let req = b.body(Body::from(self.body)).expect("request");
        match self.peer {
            Some(peer) => app.send_from(peer, req).await,
            None => app.send(req).await,
        }
    }
}

/// The body as JSON.
pub fn body(resp: &TestResponse) -> Value {
    serde_json::from_slice(&resp.body)
        .unwrap_or_else(|e| panic!("JSON body ({e}): {} {}", resp.status, resp.text()))
}

/// A started (or continued) flow: id and CSRF token from an answer.
#[derive(Debug, Clone)]
pub struct Flow {
    pub kind: String,
    pub id: String,
    pub csrf: String,
}

impl Flow {
    pub fn of(kind: &str, v: &Value) -> Self {
        Self {
            kind: kind.to_owned(),
            id: v["flow"]["id"].as_str().expect("flow id").to_owned(),
            csrf: v["csrf_token"].as_str().expect("csrf_token").to_owned(),
        }
    }

    pub fn path(&self) -> String {
        format!("{API}/{}/{}", self.kind, self.id)
    }

    /// Submits `body` with the flow's CSRF header from [`SPA`].
    pub async fn submit(&self, app: &TestApp, body: &Value) -> TestResponse {
        Call::post(&self.path(), body)
            .csrf(&self.csrf)
            .send(app)
            .await
    }

    /// The current step (`GET`).
    pub async fn get(&self, app: &TestApp) -> TestResponse {
        Call::get(&self.path()).csrf(&self.csrf).send(app).await
    }
}

/// Starts a flow of `kind` from [`SPA`] (`body` may be `{}`); asserts 200.
pub async fn start(app: &TestApp, kind: &str, body: &Value) -> (Flow, Value) {
    let resp = Call::post(&format!("{API}/{kind}"), body).send(app).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let v = self::body(&resp);
    (Flow::of(kind, &v), v)
}

/// A password submission.
pub fn password(identifier: &str, password: &str) -> Value {
    json!({"method": "password", "values": {"identifier": identifier, "password": password}})
}

/// The form-level message keys of an answer.
pub fn message_keys(v: &Value) -> Vec<String> {
    v["form"]["messages"]
        .as_array()
        .map(|m| {
            m.iter()
                .filter_map(|m| m["key"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// The method kinds a form offers.
pub fn method_kinds(v: &Value) -> Vec<String> {
    v["form"]["methods"]
        .as_array()
        .map(|m| {
            m.iter()
                .filter_map(|m| m["kind"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}
