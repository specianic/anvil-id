//! Rate limiting on by default (SEC-05): route classes keyed by client IP, the per-surface 429
//! shapes with `Retry-After`, the per-client token limit, trusted-proxy keying, recovery once the
//! window passes, exempt paths, the operator switch and the brute-force helper API.

mod support;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anvil_cache::limiter::{Decision, RateQuota};
use anvil_core::model::{AuditAction, AuditQuery, RequestContext};
use anvil_core::ports::Clock;
use anvil_web::adapters::argon2::Argon2Pool;
use anvil_web::adapters::hibp::{BreachCheckMode, breach_checker};
use anvil_web::client_ip::{ForwardedHeader, TrustedProxies};
use anvil_web::layers::ratelimit::{attempt_keys, guard_attempt, record_attempt};
use anvil_web::{AppConfig, AppDeps, AppState};
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use support::{TestApp, TestClock, TestResponse, json, start_time};

fn peer(s: &str) -> SocketAddr {
    format!("{s}:40000").parse().expect("peer")
}

fn form_post(path: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("sec-fetch-site", "same-origin")
        .body(Body::from(body.to_owned()))
        .expect("request")
}

fn login_post() -> Request<Body> {
    form_post("/ui/login", "identifier=a%40b.test&password=x")
}

fn get(path: &str) -> Request<Body> {
    Request::get(path).body(Body::empty()).expect("request")
}

fn with_xff(mut req: Request<Body>, xff: &str) -> Request<Body> {
    req.headers_mut()
        .insert("x-forwarded-for", xff.parse().expect("xff"));
    req
}

fn retry_after(resp: &TestResponse) -> u64 {
    resp.header("retry-after")
        .expect("Retry-After on 429")
        .parse()
        .expect("Retry-After is whole seconds")
}

fn assert_themed_429(resp: &TestResponse) {
    assert_eq!(resp.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(retry_after(resp) >= 1);
    assert_eq!(resp.header("cache-control"), Some("no-store"));
    let html = resp.html();
    assert!(
        html.contains("data-error-key=\"too_many_requests\""),
        "{html}"
    );
    assert!(html.contains("Too many requests"), "{html}");
}

fn assert_oauth_429(resp: &TestResponse) {
    assert_eq!(resp.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(retry_after(resp) >= 1);
    assert_eq!(resp.header("cache-control"), Some("no-store"));
    assert_eq!(resp.header("pragma"), Some("no-cache"));
    let body = json(resp);
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], "too many requests");
}

#[tokio::test]
async fn auth_class_is_limited_per_ip_with_a_themed_429() {
    let app = TestApp::new().await;
    let a = peer("198.51.100.1");
    for i in 0..5 {
        let resp = app.send_from(a, login_post()).await;
        assert_ne!(resp.status, StatusCode::TOO_MANY_REQUESTS, "attempt {i}");
    }
    let resp = app.send_from(a, login_post()).await;
    assert_themed_429(&resp);
    // Another IP is not affected.
    let resp = app.send_from(peer("198.51.100.2"), login_post()).await;
    assert_ne!(resp.status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn rendering_the_login_page_is_default_class() {
    let app = TestApp::new().await;
    let a = peer("198.51.100.1");
    // Far beyond the auth burst of 5: GET is the default class (burst 50).
    for i in 0..20 {
        let resp = app.send_from(a, get("/ui/login")).await;
        assert_ne!(resp.status, StatusCode::TOO_MANY_REQUESTS, "render {i}");
    }
    // ... and does not consume the auth quota.
    let resp = app.send_from(a, login_post()).await;
    assert_ne!(resp.status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn path_tenant_auth_routes_are_classified_tenant_relative() {
    let app = TestApp::new().await;
    let a = peer("198.51.100.1");
    for _ in 0..5 {
        app.send_from(
            a,
            form_post("/t/default/ui/login", "identifier=x&password=y"),
        )
        .await;
    }
    let resp = app
        .send_from(
            a,
            form_post("/t/default/ui/login", "identifier=x&password=y"),
        )
        .await;
    assert_themed_429(&resp);
}

#[tokio::test]
async fn token_flood_from_one_ip_gets_oauth_json_429() {
    let app = TestApp::new().await;
    let a = peer("198.51.100.1");
    for i in 0..50 {
        let resp = app
            .send_from(a, form_post("/token", "grant_type=client_credentials"))
            .await;
        assert_ne!(resp.status, StatusCode::TOO_MANY_REQUESTS, "request {i}");
    }
    let resp = app
        .send_from(a, form_post("/token", "grant_type=client_credentials"))
        .await;
    assert_oauth_429(&resp);
    // introspect and revoke share the token class.
    let resp = app.send_from(a, form_post("/revoke", "token=x")).await;
    assert_oauth_429(&resp);
}

#[tokio::test]
async fn token_endpoint_limits_per_claimed_client_id() {
    let app = TestApp::with(|c| c.rate_limits.token_client = RateQuota::per_minute(3, 3)).await;
    let cc = |id: &str| {
        form_post(
            "/token",
            &format!("grant_type=client_credentials&client_id={id}"),
        )
    };
    for i in 1..=3 {
        let resp = app
            .send_from(peer(&format!("198.51.100.{i}")), cc("victim"))
            .await;
        assert_ne!(resp.status, StatusCode::TOO_MANY_REQUESTS, "request {i}");
    }
    // A fresh IP still trips the per-client limit for that client id ...
    let resp = app.send_from(peer("198.51.100.9"), cc("victim")).await;
    assert_oauth_429(&resp);
    // ... also when the client id comes from HTTP Basic.
    let mut basic = form_post("/token", "grant_type=client_credentials");
    basic.headers_mut().insert(
        header::AUTHORIZATION,
        // victim:secret
        "Basic dmljdGltOnNlY3JldA==".parse().expect("basic"),
    );
    let resp = app.send_from(peer("198.51.100.10"), basic).await;
    assert_oauth_429(&resp);
    // Another client from another IP is fine.
    let resp = app.send_from(peer("198.51.100.20"), cc("other")).await;
    assert_ne!(resp.status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn admin_api_flood_gets_problem_json_429() {
    let app = TestApp::new().await;
    let a = peer("198.51.100.1");
    for i in 0..20 {
        let resp = app.send_from(a, get("/api/admin/v1/tenants")).await;
        assert_ne!(resp.status, StatusCode::TOO_MANY_REQUESTS, "request {i}");
    }
    let resp = app.send_from(a, get("/api/admin/v1/tenants")).await;
    assert_eq!(resp.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(retry_after(&resp) >= 1);
    assert_eq!(
        resp.header("content-type"),
        Some("application/problem+json")
    );
    assert_eq!(resp.header("cache-control"), Some("no-store"));
    let body = json(&resp);
    assert_eq!(body["status"], 429);
    assert_eq!(body["type"], "urn:anvilid:problem:too_many_requests");
    assert_eq!(body["detail"], "too many requests");
}

#[tokio::test]
async fn trusted_proxy_clients_are_limited_independently() {
    let app = TestApp::with(|c| {
        c.trusted_proxies = TrustedProxies {
            cidrs: vec!["10.0.0.0/8".parse().expect("cidr")],
            header: ForwardedHeader::XForwardedFor,
        };
    })
    .await;
    let proxy = peer("10.1.2.3");
    for _ in 0..5 {
        app.send_from(proxy, with_xff(login_post(), "203.0.113.50"))
            .await;
    }
    let resp = app
        .send_from(proxy, with_xff(login_post(), "203.0.113.50"))
        .await;
    assert_themed_429(&resp);
    // A different client behind the same proxy has its own quota.
    let resp = app
        .send_from(proxy, with_xff(login_post(), "203.0.113.51"))
        .await;
    assert_ne!(resp.status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn varying_x_forwarded_for_from_an_untrusted_peer_does_not_bypass() {
    let app = TestApp::with(|c| {
        c.trusted_proxies = TrustedProxies {
            cidrs: vec!["10.0.0.0/8".parse().expect("cidr")],
            header: ForwardedHeader::XForwardedFor,
        };
    })
    .await;
    let attacker = peer("198.51.100.66");
    for i in 0..5 {
        let xff = format!("203.0.113.{i}");
        app.send_from(attacker, with_xff(login_post(), &xff)).await;
    }
    let resp = app
        .send_from(attacker, with_xff(login_post(), "203.0.113.200, 10.0.0.1"))
        .await;
    assert_themed_429(&resp);
}

#[tokio::test]
async fn advancing_past_retry_after_allows_again() {
    let app = TestApp::new().await;
    let a = peer("198.51.100.1");
    for _ in 0..5 {
        app.send_from(a, login_post()).await;
    }
    let resp = app.send_from(a, login_post()).await;
    assert_themed_429(&resp);
    let wait = retry_after(&resp);
    app.clock().advance(Duration::from_secs(wait));
    let resp = app.send_from(a, login_post()).await;
    assert_ne!(resp.status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn health_and_assets_are_never_limited() {
    let app = TestApp::with(|c| c.rate_limits.default = RateQuota::per_minute(1, 1)).await;
    let a = peer("198.51.100.1");
    for i in 0..30 {
        assert_eq!(
            app.send_from(a, get("/health/live")).await.status,
            StatusCode::OK,
            "{i}"
        );
        assert_eq!(
            app.send_from(a, get("/assets/anvil.css")).await.status,
            StatusCode::OK,
            "{i}"
        );
    }
    // The tiny default quota does apply to ordinary pages.
    app.send_from(a, get("/ui/login")).await;
    let resp = app.send_from(a, get("/ui/login")).await;
    assert_themed_429(&resp);
}

#[tokio::test]
async fn disabled_rate_limits_never_answer_429() {
    let app = TestApp::with(|c| c.rate_limits.enabled = false).await;
    let a = peer("198.51.100.1");
    for i in 0..30 {
        let resp = app.send_from(a, login_post()).await;
        assert_ne!(resp.status, StatusCode::TOO_MANY_REQUESTS, "login {i}");
        let resp = app
            .send_from(
                a,
                form_post("/token", "grant_type=client_credentials&client_id=c"),
            )
            .await;
        assert_ne!(resp.status, StatusCode::TOO_MANY_REQUESTS, "token {i}");
    }
}

#[tokio::test]
async fn request_without_peer_address_is_not_waved_through() {
    // Wiring error: no ConnectInfo. The layer never invents an address (generic 500).
    let app = TestApp::new().await;
    let router = anvil_web::app(
        app.config.clone(),
        deps_for(&app, Arc::new(TestClock::new(start_time()))),
    )
    .expect("app");
    let mut req = login_post();
    req.headers_mut()
        .insert(header::HOST, "op.test".parse().expect("host"));
    let resp = tower::ServiceExt::oneshot(router, req)
        .await
        .expect("infallible");
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

fn deps_for(app: &TestApp, clock: Arc<TestClock>) -> AppDeps {
    AppDeps {
        storage: app.storage_arc(),
        clock: clock as Arc<dyn Clock>,
        hasher: Arc::new(
            Argon2Pool::new(argon2::Params::new(256, 1, 1, None).expect("params"), 2)
                .expect("argon2 pool"),
        ),
        breach: breach_checker(BreachCheckMode::Off),
        kek: app.kek_arc(),
    }
}

#[tokio::test]
async fn brute_force_helpers_lock_audit_and_recover() {
    let app = TestApp::new().await;
    let tenant = app.default.as_ref().expect("default tenant").tenant.id;
    let clock = Arc::new(TestClock::new(start_time()));
    let state = AppState::new(
        AppConfig::new(app.config.public_url.clone()),
        deps_for(&app, Arc::clone(&clock)),
    )
    .expect("state");
    let ip = "198.51.100.7".parse().expect("ip");
    let ctx = RequestContext::new(Some(ip), Some("test"), None);
    let (strict, loose) = attempt_keys(tenant, "Alice@Example.test", ip);

    assert_eq!(
        guard_attempt(&state, &strict, &loose, false).await,
        Decision::Allow
    );
    // Five free failures, the sixth locks the strict key.
    for _ in 0..6 {
        record_attempt(
            &state,
            tenant,
            &ctx,
            &[strict.clone(), loose.clone()],
            false,
        )
        .await;
    }
    let Decision::Deny { retry_after } = guard_attempt(&state, &strict, &loose, false).await else {
        panic!("locked after six failures");
    };
    assert!(retry_after <= Duration::from_secs(1));

    // Exactly one lockout event (the unlocked -> locked transition), without the identifier.
    let events = app
        .storage()
        .audit()
        .query(
            tenant,
            &AuditQuery {
                action: Some(AuditAction::RateLimitLockout),
                limit: 50,
                ..AuditQuery::default()
            },
        )
        .await
        .expect("audit query");
    assert_eq!(events.items.len(), 1, "{:?}", events.items);
    let event = &events.items[0];
    assert_eq!(event.ctx.ip, Some(ip));
    assert_eq!(event.details.as_map()["reason"], "identifier_ip");
    assert!(event.target.is_none());
    assert!(!format!("{:?}", event.details).contains("alice"));

    // The lock expires on the clock; a success forgets the failures.
    clock.advance(Duration::from_secs(2));
    assert_eq!(
        guard_attempt(&state, &strict, &loose, false).await,
        Decision::Allow
    );
    record_attempt(&state, tenant, &ctx, std::slice::from_ref(&strict), true).await;
    record_attempt(&state, tenant, &ctx, std::slice::from_ref(&strict), false).await;
    assert_eq!(
        guard_attempt(&state, &strict, &loose, false).await,
        Decision::Allow
    );

    // Another IP for the same identifier is not locked by the first IP's failures.
    let (other_strict, _) = attempt_keys(
        tenant,
        "alice@example.test",
        "198.51.100.8".parse().expect("ip"),
    );
    assert_eq!(
        guard_attempt(&state, &other_strict, &loose, false).await,
        Decision::Allow
    );
}
