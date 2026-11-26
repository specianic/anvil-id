//! Client ID Metadata Document test helpers (test code only): a wiremock document server on
//! loopback, tenant CIMD policy switches, document templates and a scripted fetcher double for
//! resolver tests.

#![allow(dead_code)]

use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use anvil_core::model::{CimdPolicy, Client, FetchedMetadata, Tenant, TenantUpdate};
use anvil_core::ports::{ClientMetadataFetcher, Clock, MetadataFetchError};
use serde_json::{Value, json};
use time::OffsetDateTime;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::authz::RP;
use crate::support::TestApp;

/// The path documents are served at by default.
pub const DOC_PATH: &str = "/client.json";

/// A metadata document server on `127.0.0.1` (plain http: only reachable in development mode,
/// where the outbound policy allow-lists loopback).
pub struct DocServer {
    pub server: MockServer,
}

impl DocServer {
    pub async fn start() -> Self {
        Self {
            server: MockServer::start().await,
        }
    }

    /// `http://127.0.0.1:{port}{path}`: a client id.
    pub fn url(&self, path: &str) -> String {
        format!("{}{path}", self.server.uri())
    }

    /// Serves `body` at `path` with status 200 and an optional `Cache-Control`.
    pub async fn serve(&self, path_: &str, body: &Value, cache_control: Option<&str>) {
        let mut resp = ResponseTemplate::new(200)
            .insert_header("content-type", "application/json")
            .set_body_string(body.to_string());
        if let Some(cc) = cache_control {
            resp = resp.insert_header("cache-control", cc);
        }
        Mock::given(method("GET"))
            .and(path(path_))
            .respond_with(resp)
            .mount(&self.server)
            .await;
    }

    /// Serves raw bytes at `path` with status 200.
    pub async fn serve_raw(&self, path_: &str, body: Vec<u8>) {
        Mock::given(method("GET"))
            .and(path(path_))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_bytes(body),
            )
            .mount(&self.server)
            .await;
    }

    /// Answers `status` at `path` for the next `times` requests (higher priority than
    /// [`Self::serve`] mounts).
    pub async fn fail(&self, path_: &str, status: u16, times: u64) {
        Mock::given(method("GET"))
            .and(path(path_))
            .respond_with(ResponseTemplate::new(status))
            .up_to_n_times(times)
            .with_priority(1)
            .mount(&self.server)
            .await;
    }

    /// Answers a `302` redirect from `from` to `to` (same server).
    pub async fn redirect(&self, from: &str, to: &str) {
        Mock::given(method("GET"))
            .and(path(from))
            .respond_with(ResponseTemplate::new(302).insert_header("location", self.url(to)))
            .mount(&self.server)
            .await;
    }

    /// Requests received at `path`.
    pub async fn hits(&self, path_: &str) -> usize {
        self.server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .filter(|r| r.url.path() == path_)
            .count()
    }

    /// Every request received.
    pub async fn total_hits(&self) -> usize {
        self.server
            .received_requests()
            .await
            .unwrap_or_default()
            .len()
    }
}

/// A valid public-client document for `client_id` redirecting to [`RP`].
pub fn doc(client_id: &str) -> Value {
    json!({
        "client_id": client_id,
        "client_name": "Desk Agent",
        "redirect_uris": [RP],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        "scope": "openid profile",
    })
}

/// Sets the default tenant's CIMD policy (and allow-list) and self-service resources; returns
/// the updated tenant.
pub async fn set_policy(
    app: &TestApp,
    policy: CimdPolicy,
    allowed_hosts: &[&str],
    resources: &[&str],
) -> Tenant {
    let tenant = crate::authz::default_tenant(app);
    let mut settings = tenant.settings.clone();
    settings.cimd.policy = policy;
    settings.cimd.allowed_hosts = allowed_hosts.iter().map(|h| (*h).to_owned()).collect();
    settings.dcr.allowed_resources = resources.iter().map(|r| (*r).to_owned()).collect();
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

/// The stored client `client_id` of the default tenant.
pub async fn stored(app: &TestApp, client_id: &str) -> Option<Client> {
    let tenant = crate::authz::default_tenant(app);
    app.storage()
        .clients()
        .get(tenant.id, client_id)
        .await
        .expect("client lookup")
}

/// GET /authorize for `client_id` with the standard PKCE parameters plus `extra`.
pub fn authorize_path(client_id: &str, extra: &[(&str, &str)]) -> String {
    let mut pairs = crate::authz::pkce_params(client_id);
    pairs.extend_from_slice(extra);
    crate::authz::authorize_path("", &pairs)
}

/// A fixed clock for services built directly in tests.
pub struct FixedClock(pub OffsetDateTime);

impl Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        self.0
    }
}

/// A scripted fetcher double: answers the queued results in order and counts calls.
pub struct ScriptedFetcher {
    pub allow_http: bool,
    pub calls: AtomicUsize,
    script: Mutex<VecDeque<Result<FetchedMetadata, MetadataFetchError>>>,
}

impl ScriptedFetcher {
    pub fn new(allow_http: bool) -> Self {
        Self {
            allow_http,
            calls: AtomicUsize::new(0),
            script: Mutex::new(VecDeque::new()),
        }
    }

    pub fn push_doc(&self, body: &Value, max_age_secs: Option<u32>) {
        self.push(Ok(FetchedMetadata {
            body: body.to_string().into_bytes(),
            max_age_secs,
        }));
    }

    pub fn push(&self, result: Result<FetchedMetadata, MetadataFetchError>) {
        self.script.lock().expect("script lock").push_back(result);
    }

    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl ClientMetadataFetcher for ScriptedFetcher {
    async fn fetch(&self, _url: &str) -> Result<FetchedMetadata, MetadataFetchError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.script
            .lock()
            .expect("script lock")
            .pop_front()
            .unwrap_or(Err(MetadataFetchError::InvalidResponse("script exhausted")))
    }

    fn allow_http_loopback(&self) -> bool {
        self.allow_http
    }
}
