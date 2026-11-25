//! In-process tests for the anvil-web router.

use anvil_web::{WebConfig, router};
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use http_body_util::BodyExt;
use tower::ServiceExt;

const CSS: &[u8] = include_bytes!("../../../themes/default/static/anvil.css");

fn app(issuer: &str) -> axum::Router {
    router(WebConfig {
        issuer: issuer.parse().expect("valid issuer url"),
    })
}

async fn send(app: axum::Router, req: Request<Body>) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let resp = app.oneshot(req).await.expect("infallible service");
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp.into_body().collect().await.expect("body").to_bytes().to_vec();
    (status, headers, body)
}

fn get(uri: &str) -> Request<Body> {
    Request::get(uri).body(Body::empty()).expect("request")
}

async fn discovery(issuer: &str) -> serde_json::Value {
    let (status, headers, body) = send(app(issuer), get("/.well-known/openid-configuration")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CONTENT_TYPE], "application/json");
    serde_json::from_slice(&body).expect("json body")
}

#[tokio::test]
async fn discovery_endpoints_derive_from_issuer() {
    let doc = discovery("http://example.test:9090").await;
    assert_eq!(doc["issuer"], "http://example.test:9090");
    assert_eq!(doc["authorization_endpoint"], "http://example.test:9090/authorize");
    assert_eq!(doc["token_endpoint"], "http://example.test:9090/token");
    assert_eq!(doc["jwks_uri"], "http://example.test:9090/jwks");
    assert_eq!(doc["response_types_supported"], serde_json::json!(["code"]));
    assert_eq!(doc["subject_types_supported"], serde_json::json!(["public"]));
    assert_eq!(doc["id_token_signing_alg_values_supported"], serde_json::json!(["ES256"]));
    assert_eq!(doc["code_challenge_methods_supported"], serde_json::json!(["S256"]));
    assert_eq!(doc["grant_types_supported"], serde_json::json!(["authorization_code"]));
    assert_eq!(
        doc["token_endpoint_auth_methods_supported"],
        serde_json::json!(["client_secret_basic"])
    );
    assert_eq!(doc["scopes_supported"], serde_json::json!(["openid"]));
}

#[tokio::test]
async fn discovery_trims_trailing_slash() {
    let doc = discovery("http://example.test:9090/").await;
    assert_eq!(doc["issuer"], "http://example.test:9090");
    assert_eq!(doc["token_endpoint"], "http://example.test:9090/token");
}

#[tokio::test]
async fn discovery_keeps_issuer_path() {
    let doc = discovery("https://example.test/t/acme").await;
    assert_eq!(doc["issuer"], "https://example.test/t/acme");
    assert_eq!(doc["authorization_endpoint"], "https://example.test/t/acme/authorize");
    assert_eq!(doc["token_endpoint"], "https://example.test/t/acme/token");
    assert_eq!(doc["jwks_uri"], "https://example.test/t/acme/jwks");

    let doc = discovery("https://example.test/t/acme/").await;
    assert_eq!(doc["issuer"], "https://example.test/t/acme");
    assert_eq!(doc["jwks_uri"], "https://example.test/t/acme/jwks");
}

#[tokio::test]
async fn healthz_ok() {
    let (status, _, body) = send(app("http://example.test"), get("/healthz")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"ok");
}

#[tokio::test]
async fn unimplemented_endpoints_return_501_never_success() {
    for (method, path) in [(Method::GET, "/authorize"), (Method::POST, "/token"), (Method::GET, "/jwks")] {
        let req = Request::builder()
            .method(method.clone())
            .uri(path)
            .body(Body::empty())
            .expect("request");
        let (status, headers, body) = send(app("http://example.test"), req).await;
        assert_eq!(status, StatusCode::NOT_IMPLEMENTED, "{method} {path}");
        assert!(!status.is_success());
        assert_eq!(headers[header::CONTENT_TYPE], "application/json");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["error"], "not_implemented");
        let desc = json["error_description"].as_str().expect("description");
        assert!(desc.contains(path), "{desc}");
    }
}

fn expected_etag() -> String {
    let d = aws_lc_rs_digest(CSS);
    format!("\"{d}\"")
}

// Independent SHA-256 reference: computed via the same primitive the plan mandates, but hex-encoded here
// separately so a broken hex function in the crate would be caught.
fn aws_lc_rs_digest(data: &[u8]) -> String {
    use std::fmt::Write;
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, data);
    digest.as_ref().iter().fold(String::new(), |mut s, b| {
        write!(s, "{b:02x}").expect("write to string");
        s
    })
}

#[tokio::test]
async fn asset_served_with_etag_and_content_type() {
    let (status, headers, body) = send(app("http://example.test"), get("/assets/anvil.css")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        headers[header::CONTENT_TYPE].to_str().expect("ascii").starts_with("text/css"),
        "{:?}",
        headers[header::CONTENT_TYPE]
    );
    let etag = headers[header::ETAG].to_str().expect("ascii").to_owned();
    assert_eq!(etag, expected_etag());
    assert_eq!(etag.len(), 66);
    assert_eq!(headers[header::CACHE_CONTROL], "public, max-age=3600");
    assert_eq!(body, CSS);
}

#[tokio::test]
async fn asset_if_none_match_returns_304() {
    let req = Request::get("/assets/anvil.css")
        .header(header::IF_NONE_MATCH, expected_etag())
        .body(Body::empty())
        .expect("request");
    let (status, headers, body) = send(app("http://example.test"), req).await;
    assert_eq!(status, StatusCode::NOT_MODIFIED);
    assert_eq!(headers[header::ETAG].to_str().expect("ascii"), expected_etag());
    assert!(body.is_empty());
}

#[tokio::test]
async fn asset_stale_if_none_match_returns_200() {
    let req = Request::get("/assets/anvil.css")
        .header(header::IF_NONE_MATCH, "\"deadbeef\"")
        .body(Body::empty())
        .expect("request");
    let (status, _, body) = send(app("http://example.test"), req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, CSS);
}

#[tokio::test]
async fn missing_asset_is_404() {
    let (status, _, _) = send(app("http://example.test"), get("/assets/does-not-exist.css")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn asset_path_traversal_is_404() {
    for uri in [
        "/assets/../Cargo.toml",
        "/assets/../../Cargo.toml",
        "/assets/../../../Cargo.toml",
        "/assets/%2e%2e/%2e%2e/%2e%2e/Cargo.toml",
        "/assets/..%2f..%2f..%2fCargo.toml",
    ] {
        let (status, _, _) = send(app("http://example.test"), get(uri)).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{uri}");
    }
}
