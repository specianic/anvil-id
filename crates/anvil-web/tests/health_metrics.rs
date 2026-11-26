//! Health endpoints (OPS-08): liveness and readiness aliases, readiness cleared for the
//! shutdown drain, probes outside tenant resolution and rate limiting.

mod support;

use std::net::SocketAddr;
use std::sync::Arc;

use anvil_cache::limiter::{LimiterConfig, RateQuota};
use anvil_core::clock::SystemClock;
use anvil_core::model::PublicUrl;
use anvil_core::ports::Clock;
use anvil_jose::kek::Kek;
use anvil_web::adapters::argon2::Argon2Pool;
use anvil_web::adapters::hibp::{BreachCheckMode, breach_checker};
use anvil_web::{AppConfig, AppDeps, AppState};
use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, header};
use http_body_util::BodyExt;
use support::TestApp;
use tower::ServiceExt;

/// An uninstalled app plus its state (the harness does not expose the state).
async fn app_with_state(f: impl FnOnce(&mut AppConfig)) -> (AppState, Router) {
    let storage = support::Backend::from_env().storage().await;
    let mut config = AppConfig::new(PublicUrl::parse("https://op.test").expect("url"));
    f(&mut config);
    let deps = AppDeps {
        storage,
        clock: Arc::new(SystemClock) as Arc<dyn Clock>,
        hasher: Arc::new(
            Argon2Pool::new(argon2::Params::new(256, 1, 1, None).expect("params"), 1)
                .expect("argon2 pool"),
        ),
        breach: breach_checker(BreachCheckMode::Off),
        kek: Arc::new(Kek::generate()),
    };
    let state = AppState::new(config, deps).expect("app builds");
    let router = anvil_web::router(state.clone());
    (state, router)
}

async fn get(router: &Router, path: &str, host: &str) -> (u16, String) {
    let mut req = Request::get(path)
        .header(header::HOST, host)
        .body(Body::empty())
        .expect("request");
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([203, 0, 113, 10], 40000))));
    let resp = router.clone().oneshot(req).await.expect("infallible");
    let status = resp.status().as_u16();
    let body = resp
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes()
        .to_vec();
    (status, String::from_utf8_lossy(&body).into_owned())
}

#[tokio::test]
async fn health_liveness_aliases_answer_ok() {
    let app = TestApp::uninstalled().await;
    for path in ["/health/live", "/healthz"] {
        let resp = app.get(path).await;
        assert_eq!(resp.status, 200, "{path}");
        assert_eq!(resp.text(), "ok", "{path}");
    }
}

#[tokio::test]
async fn health_readiness_aliases_share_one_handler() {
    let app = TestApp::new().await;
    let ready = app.get("/health/ready").await;
    let readyz = app.get("/readyz").await;
    assert_eq!(ready.status, 200);
    assert_eq!(readyz.status, 200);
    assert_eq!(ready.text(), readyz.text());
}

#[tokio::test]
async fn health_readiness_turns_503_while_draining() {
    let (state, router) = app_with_state(|_| {}).await;
    for path in ["/readyz", "/health/ready"] {
        assert_eq!(get(&router, path, "op.test").await, (200, "ok".into()));
    }
    state.set_ready(false);
    for path in ["/readyz", "/health/ready"] {
        assert_eq!(
            get(&router, path, "op.test").await,
            (503, "draining".into()),
            "{path}"
        );
    }
    // Liveness is unaffected: the node still serves while it drains.
    for path in ["/healthz", "/health/live"] {
        assert_eq!(get(&router, path, "op.test").await.0, 200, "{path}");
    }
    state.set_ready(true);
    assert_eq!(get(&router, "/readyz", "op.test").await.0, 200);
}

#[tokio::test]
async fn health_probes_skip_tenant_resolution_and_rate_limits() {
    let (_, router) = app_with_state(|c| {
        c.rate_limits = LimiterConfig {
            default: RateQuota::per_second(1, 1),
            ..LimiterConfig::default()
        };
    })
    .await;
    // An unknown Host header does not make probes depend on a tenant lookup.
    for path in ["/readyz", "/health/ready", "/healthz", "/health/live"] {
        assert_eq!(
            get(&router, path, "unknown.example.test").await.0,
            200,
            "{path}"
        );
    }
    // Far above the default quota of one request per second: never limited.
    for _ in 0..20 {
        assert_eq!(get(&router, "/readyz", "op.test").await.0, 200);
    }
    // The quota is real: an ordinary page from the same address is limited.
    let mut limited = false;
    for _ in 0..5 {
        limited |= get(&router, "/.well-known/openid-configuration", "op.test")
            .await
            .0
            == 429;
    }
    assert!(
        limited,
        "the default class quota applies to ordinary routes"
    );
}
