//! Helpers for the native-app mode of the headless flow API (test code only), shared by
//! `headless_native.rs` and `security_headless.rs`: a `headless_native` first-party public client,
//! its pushed request (with the PKCE challenge of `token_support`), native requests without any
//! browser header, and the flow token. Used next to `mod authz; mod headless_support;
//! mod par_support; mod support; mod token_support; mod ui_helpers;`.

#![allow(dead_code)]

use anvil_core::model::{ClientAuthMethod, NewClient};
use axum::body::Body;
use axum::http::{Method, Request, header};
use serde_json::{Value, json};

use crate::headless_support::{API, body};
use crate::par_support::{ParClient, par_client_with, push_default};
use crate::support::{TestApp, TestResponse};

/// The native start path of the default tenant.
pub const START: &str = "/api/flows/v1/login";

/// A public PKCE client flagged `headless_native` (first-party: consent skipped), registered
/// through the storage port; `customise` changes the stored client (to build ineligible ones).
pub async fn native_client_with(
    app: &TestApp,
    customise: impl FnOnce(&mut NewClient),
) -> ParClient {
    par_client_with(app, ClientAuthMethod::None, |c| {
        c.headless_native = true;
        customise(c);
    })
    .await
}

/// [`native_client_with`] without changes.
pub async fn native_client(app: &TestApp) -> ParClient {
    native_client_with(app, |_| {}).await
}

/// One native request: JSON, no `Origin`, no `Sec-Fetch-*`, no cookies (the harness jar is not
/// sent: an explicit empty `Cookie` header stops it), optionally `Authorization: AnvilFlow`.
pub async fn native_call(
    app: &TestApp,
    method: Method,
    path: &str,
    token: Option<&str>,
    body: Option<&Value>,
    extra: &[(&'static str, &str)],
) -> TestResponse {
    let mut b = Request::builder()
        .method(method)
        .uri(path)
        .header(header::COOKIE, "")
        .header(header::USER_AGENT, "NativeApp/1.0");
    if let Some(t) = token {
        b = b.header(header::AUTHORIZATION, format!("AnvilFlow {t}"));
    }
    if body.is_some() {
        b = b.header(header::CONTENT_TYPE, "application/json");
    }
    for (k, v) in extra {
        b = b.header(*k, *v);
    }
    let body = body.map(Value::to_string).unwrap_or_default();
    app.send(b.body(Body::from(body)).expect("request")).await
}

/// `POST /api/flows/v1/login` with `{client_id, request_uri}`.
pub async fn native_start(app: &TestApp, client_id: &str, request_uri: &str) -> TestResponse {
    native_start_with(app, client_id, request_uri, &[]).await
}

/// [`native_start`] with extra headers.
pub async fn native_start_with(
    app: &TestApp,
    client_id: &str,
    request_uri: &str,
    extra: &[(&'static str, &str)],
) -> TestResponse {
    let body = json!({"client_id": client_id, "request_uri": request_uri});
    native_call(app, Method::POST, START, None, Some(&body), extra).await
}

/// A started native flow: its id and flow token.
#[derive(Debug, Clone)]
pub struct NativeFlow {
    pub id: String,
    pub token: String,
}

impl NativeFlow {
    /// The flow of a native start answer (asserts 200 and the token).
    pub fn of(resp: &TestResponse) -> (Self, Value) {
        assert_eq!(resp.status, 200, "{}", resp.text());
        let v = body(resp);
        let token = v["flow_token"].as_str().expect("flow_token").to_owned();
        assert!(v.get("csrf_token").is_none(), "{v}");
        let id = v["flow"]["id"].as_str().expect("flow id").to_owned();
        (Self { id, token }, v)
    }

    pub fn path(&self) -> String {
        format!("{API}/login/{}", self.id)
    }

    /// Submits `body` with the flow token.
    pub async fn submit(&self, app: &TestApp, body: &Value) -> TestResponse {
        native_call(
            app,
            Method::POST,
            &self.path(),
            Some(&self.token),
            Some(body),
            &[],
        )
        .await
    }

    /// Submits `body` with another token.
    pub async fn submit_with(
        &self,
        app: &TestApp,
        token: Option<&str>,
        body: &Value,
    ) -> TestResponse {
        native_call(app, Method::POST, &self.path(), token, Some(body), &[]).await
    }

    /// The current step.
    pub async fn get(&self, app: &TestApp) -> TestResponse {
        native_call(app, Method::GET, &self.path(), Some(&self.token), None, &[]).await
    }
}

/// Pushes the standard request for `client` and starts a native flow with it.
pub async fn started(app: &TestApp, client: &ParClient) -> (NativeFlow, Value) {
    let request_uri = push_default(app, client).await;
    let resp = native_start(app, client.id(), &request_uri).await;
    NativeFlow::of(&resp)
}

/// The code of a completed native answer (asserts the pushed state and the issuer).
pub fn code_of(resp: &TestResponse, issuer: &str) -> String {
    assert_eq!(resp.status, 200, "{}", resp.text());
    let v = body(resp);
    assert_eq!(v["step"], "completed", "{v}");
    assert!(v["result"].get("continue_to").is_none(), "{v}");
    assert_eq!(v["result"]["state"], "pushed-state", "{v}");
    assert_eq!(v["result"]["iss"], issuer, "{v}");
    v["result"]["code"].as_str().expect("code").to_owned()
}

/// Whether a response sets any cookie.
pub fn sets_cookie(resp: &TestResponse) -> bool {
    resp.headers.contains_key(header::SET_COOKIE)
}
