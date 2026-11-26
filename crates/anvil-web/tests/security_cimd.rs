//! Client ID Metadata Document abuse controls (AGT-02) over HTTP on the selected backend
//! (`ANVILID_TEST_DB`). Each test proves a refusal: policy and allow-list are checked before any
//! fetch, private destinations are blocked in production, redirects are not followed, oversized
//! and invalid documents are refused and never stored, fetch errors are not cached, a failure at
//! /authorize renders the error page and never redirects, per-host fetches are rate-limited, and
//! production refuses http client ids before fetching.
//!
//! Development-mode tests (`TestApp::dev()`) use a wiremock document server on loopback (the
//! development outbound policy allow-lists loopback and plain http to it); production-mode tests
//! (`TestApp::new()`) prove that loopback is unreachable.

mod authz;
mod cimd_support;
mod support;

use anvil_core::model::CimdPolicy;
use axum::http::header;
use cimd_support::{DOC_PATH, DocServer, authorize_path, doc, set_policy, stored};
use serde_json::json;
use support::{TestApp, TestResponse};

/// Asserts a themed error page (any 4xx/5xx) that does not redirect anywhere.
fn assert_error_page_no_redirect(resp: &TestResponse) {
    assert!(
        resp.status.as_u16() >= 400,
        "expected an error page, got {}: {}",
        resp.status,
        resp.text()
    );
    assert!(
        resp.headers.get(header::LOCATION).is_none(),
        "a CIMD failure must never redirect"
    );
    assert!(resp.html().contains("data-error-key="), "{}", resp.html());
}

async fn dev_open() -> (TestApp, DocServer) {
    let app = TestApp::dev().await;
    set_policy(&app, CimdPolicy::Open, &[], &[]).await;
    (app, DocServer::start().await)
}

#[tokio::test]
async fn cimd_policy_checked_before_fetch() {
    let app = TestApp::dev().await; // default policy: disabled
    let docs = DocServer::start().await;
    let client_id = docs.url(DOC_PATH);
    docs.serve(DOC_PATH, &doc(&client_id), None).await;

    let resp = app.get(&authorize_path(&client_id, &[])).await;
    authz::assert_error_page(&resp, "unknown_client");
    assert_eq!(docs.total_hits().await, 0);
    assert!(stored(&app, &client_id).await.is_none());
}

#[tokio::test]
async fn cimd_allow_list_checked_before_fetch() {
    let app = TestApp::dev().await;
    set_policy(&app, CimdPolicy::AllowListed, &["mcp-clients.example"], &[]).await;
    let docs = DocServer::start().await;
    let client_id = docs.url(DOC_PATH);
    docs.serve(DOC_PATH, &doc(&client_id), None).await;

    let resp = app.get(&authorize_path(&client_id, &[])).await;
    authz::assert_error_page(&resp, "unknown_client");
    assert_eq!(docs.total_hits().await, 0);

    // Listing the host lets the same request through.
    set_policy(&app, CimdPolicy::AllowListed, &["127.0.0.1"], &[]).await;
    let resp = app.get(&authorize_path(&client_id, &[])).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert_eq!(docs.total_hits().await, 1);
}

#[tokio::test]
async fn cimd_private_destination_blocked() {
    // Production mode: loopback and private ranges are not allow-listed.
    let app = TestApp::new().await;
    set_policy(&app, CimdPolicy::Open, &[], &[]).await;
    let docs = DocServer::start().await;
    let port = docs.server.address().port();
    for client_id in [
        format!("https://127.0.0.1:{port}/client.json"),
        "https://10.0.0.7/client.json".to_owned(),
        "https://169.254.169.254/latest/meta-data/client.json".to_owned(),
        "https://[::1]/client.json".to_owned(),
    ] {
        let resp = app.get(&authorize_path(&client_id, &[])).await;
        assert_error_page_no_redirect(&resp);
        assert!(stored(&app, &client_id).await.is_none(), "{client_id}");
    }
    assert_eq!(docs.total_hits().await, 0);
}

#[tokio::test]
async fn cimd_redirect_not_followed() {
    let (app, docs) = dev_open().await;
    let client_id = docs.url("/moved.json");
    docs.redirect("/moved.json", DOC_PATH).await;
    docs.serve(DOC_PATH, &doc(&client_id), None).await;

    let resp = app.get(&authorize_path(&client_id, &[])).await;
    authz::assert_error_page(&resp, "unknown_client");
    assert_eq!(docs.hits("/moved.json").await, 1);
    assert_eq!(docs.hits(DOC_PATH).await, 0, "the redirect was followed");
    assert!(stored(&app, &client_id).await.is_none());
}

#[tokio::test]
async fn cimd_document_over_5k_rejected() {
    let (app, docs) = dev_open().await;
    let client_id = docs.url(DOC_PATH);
    let mut body = doc(&client_id);
    body["client_name"] = json!("x".repeat(6 * 1024));
    docs.serve(DOC_PATH, &body, None).await;

    let resp = app.get(&authorize_path(&client_id, &[])).await;
    authz::assert_error_page(&resp, "unknown_client");
    assert!(stored(&app, &client_id).await.is_none());
}

#[tokio::test]
async fn cimd_client_id_mismatch_rejected() {
    let (app, docs) = dev_open().await;
    let client_id = docs.url(DOC_PATH);
    docs.serve(DOC_PATH, &doc(&format!("{client_id}/")), None)
        .await;

    let resp = app.get(&authorize_path(&client_id, &[])).await;
    authz::assert_error_page(&resp, "unknown_client");
    assert!(stored(&app, &client_id).await.is_none());
}

#[tokio::test]
async fn cimd_shared_secret_method_rejected() {
    let (app, docs) = dev_open().await;
    for (path, method) in [
        ("/basic.json", "client_secret_basic"),
        ("/post.json", "client_secret_post"),
        ("/jwt.json", "client_secret_jwt"),
    ] {
        let client_id = docs.url(path);
        let mut body = doc(&client_id);
        body["token_endpoint_auth_method"] = json!(method);
        docs.serve(path, &body, None).await;
        let resp = app.get(&authorize_path(&client_id, &[])).await;
        authz::assert_error_page(&resp, "unknown_client");
        assert!(stored(&app, &client_id).await.is_none(), "{method}");
    }
}

#[tokio::test]
async fn cimd_jwks_uri_document_rejected() {
    let (app, docs) = dev_open().await;
    let client_id = docs.url(DOC_PATH);
    let mut body = doc(&client_id);
    body["token_endpoint_auth_method"] = json!("private_key_jwt");
    body["jwks_uri"] = json!(docs.url("/jwks.json"));
    docs.serve(DOC_PATH, &body, None).await;

    let resp = app.get(&authorize_path(&client_id, &[])).await;
    authz::assert_error_page(&resp, "unknown_client");
    assert!(stored(&app, &client_id).await.is_none());
    assert_eq!(docs.hits("/jwks.json").await, 0);
}

#[tokio::test]
async fn cimd_fetch_error_not_cached() {
    let (app, docs) = dev_open().await;
    let client_id = docs.url(DOC_PATH);
    docs.fail(DOC_PATH, 500, 1).await;
    docs.serve(DOC_PATH, &doc(&client_id), Some("max-age=600"))
        .await;

    // The host fails: 503 error page, nothing stored.
    let resp = app.get(&authorize_path(&client_id, &[])).await;
    assert_error_page_no_redirect(&resp);
    assert_eq!(resp.status, 503);
    assert!(stored(&app, &client_id).await.is_none());

    // The next request fetches again and succeeds (login redirect).
    let resp = app.get(&authorize_path(&client_id, &[])).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert_eq!(docs.hits(DOC_PATH).await, 2);
    assert!(stored(&app, &client_id).await.is_some());
}

#[tokio::test]
async fn cimd_failure_never_redirects() {
    let (app, docs) = dev_open().await;
    // Invalid document, unreachable host, oversized: every failure is the error page, even
    // though the request carries a redirect_uri the document would have listed.
    let invalid = docs.url("/invalid.json");
    docs.serve("/invalid.json", &json!({"client_id": invalid}), None)
        .await;
    let gone = docs.url("/gone.json");
    docs.fail("/gone.json", 404, 10).await;
    let down = docs.url("/down.json");
    docs.fail("/down.json", 502, 10).await;
    for client_id in [invalid, gone, down] {
        let resp = app
            .get(&authorize_path(
                &client_id,
                &[("response_mode", "form_post")],
            ))
            .await;
        assert_error_page_no_redirect(&resp);
        assert!(!resp.text().contains(authz::RP), "{client_id}");
    }
}

#[tokio::test]
async fn cimd_fetch_rate_limited() {
    let (app, docs) = dev_open().await;
    // Every document is refused, so nothing is cached and each request wants a fetch; all of
    // them go to the same host.
    let mut statuses = Vec::new();
    for i in 0..12 {
        let path = format!("/c{i}.json");
        let client_id = docs.url(&path);
        docs.serve(&path, &doc("https://elsewhere.example/c.json"), None)
            .await;
        let resp = app.get(&authorize_path(&client_id, &[])).await;
        assert!(resp.headers.get(header::LOCATION).is_none());
        statuses.push(resp.status.as_u16());
    }
    let fetched = docs.total_hits().await;
    assert!(
        fetched < 12,
        "per-host budget not applied: {fetched} fetches"
    );
    assert!(fetched >= 1);
    // Denied fetches are transient: the 503 error page.
    assert_eq!(statuses.last(), Some(&503), "{statuses:?}");
}

#[tokio::test]
async fn cimd_http_client_id_rejected_in_production() {
    // Production mode, even with loopback reachable over https: http client ids are refused
    // before any fetch.
    let app = TestApp::with(|c| {
        c.outbound.allow_cidrs =
            anvil_web::adapters::outbound::OutboundPolicy::loopback_dev().allow_cidrs;
        c.outbound.allow_http = false;
    })
    .await;
    set_policy(&app, CimdPolicy::Open, &[], &[]).await;
    let docs = DocServer::start().await;
    let client_id = docs.url(DOC_PATH); // http://127.0.0.1:{port}/client.json
    assert!(client_id.starts_with("http://127.0.0.1:"));
    docs.serve(DOC_PATH, &doc(&client_id), None).await;

    let resp = app.get(&authorize_path(&client_id, &[])).await;
    authz::assert_error_page(&resp, "unknown_client");
    assert_eq!(docs.total_hits().await, 0);
    assert!(stored(&app, &client_id).await.is_none());
}

#[tokio::test]
async fn headless_native_refused_via_cimd() {
    let (app, docs) = dev_open().await;
    let tenant = authz::default_tenant(&app);
    let client_id = docs.url(DOC_PATH);
    let mut document = doc(&client_id);
    // Administrator-only fields in a self-published document are never mapped.
    document["headless_native"] = json!(true);
    document["client_kind"] = json!("agent");
    document["consent_mode"] = json!("skip_first_party");
    docs.serve(DOC_PATH, &document, None).await;
    let user = authz::user(&app, &tenant, "ada@example.com").await;
    let session = authz::session(&app, &tenant, user).await;
    let resp = authz::get(&app, &authorize_path(&client_id, &[]), Some(&session)).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    let row = stored(&app, &client_id).await.expect("materialised");
    assert!(!row.headless_native);
    assert_eq!(row.client_kind, anvil_core::model::ClientKind::Application);
    assert_eq!(row.consent_mode, anvil_core::model::ConsentMode::Required);

    // The shared client policy refuses the flag for a CIMD client whoever asks.
    let clients = anvil_core::service::client::ClientService {
        storage: app.storage_arc(),
        clock: std::sync::Arc::new(cimd_support::FixedClock(anvil_core::ports::Clock::now(
            app.clock(),
        ))),
        redirect_validator: anvil_core::oauth::redirect::validate_redirect_uri,
    };
    let err = clients
        .update(
            &tenant,
            &client_id,
            anvil_core::service::client::ClientPatch::default(),
            anvil_core::service::client::ClientOptionsPatch {
                consent_mode: Some(anvil_core::model::ConsentMode::SkipFirstParty),
                headless_native: Some(true),
                ..Default::default()
            },
            anvil_core::model::AuditActor::admin("test-admin"),
            &anvil_core::model::RequestContext::system(),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            anvil_core::error::CoreError::Validation {
                field: "headless_native",
                ..
            }
        ),
        "{err:?}"
    );
    assert!(!stored(&app, &client_id).await.unwrap().headless_native);
}
