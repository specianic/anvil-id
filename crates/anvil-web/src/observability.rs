//! Request telemetry (OPS-08): the one request span/log/metrics layer, the metric names and
//! their descriptions, and the `/metrics` route.
//!
//! # Redaction by construction
//!
//! The layer never reads the URI into telemetry. Spans and the access log carry the **matched
//! route template** (`/authorize`, `/api/admin/v1/users/{id}`, or `unmatched`), the resolved
//! tenant slug, the status and the latency. Query strings (`login_hint`, `code`, `state`), raw
//! paths, client IPs, client ids and user identifiers never appear. Metrics are labelled only
//! with bounded classes: `route_class` (`auth`, `token`, `admin`, `default`, `health`,
//! `metrics`, `console`, `assets`) and `status_class` (`2xx` …); never a tenant or client.
//!
//! # How the pieces fit
//!
//! - [`observe`] wraps the whole router (outermost after the request id). It opens span
//!   `http.request`, runs the request inside it and, when the response is back, records the
//!   fields, writes the access log line and updates the HTTP metrics.
//! - [`record_route`] is a route layer on the inner (tenant-relative) and outer routers. Only
//!   there is axum's `MatchedPath` known; it hands the template back on the response.
//! - [`tenant_context`] runs right after tenant resolution: it records the tenant slug on the
//!   current span and hands the tenant-relative route class back on the response.
//! - Incoming trace context (`traceparent`) is continued only when the TCP peer is a trusted
//!   proxy ([`AppConfig::trusted_proxies`](crate::AppConfig)) and the binary installed a
//!   [`TraceContextHook`] (OTLP export configured). Anyone else cannot choose our trace ids.
//!
//! # Metric owners
//!
//! Each metric is incremented in exactly one place:
//!
//! | Metric | Labels | Owner |
//! | ------ | ------ | ----- |
//! | [`HTTP_REQUESTS_TOTAL`], [`HTTP_REQUEST_DURATION_SECONDS`] | `route_class`, `status_class` / `route_class` | [`observe`] |
//! | [`RATELIMIT_REJECTIONS_TOTAL`] | `route_class` | `layers::ratelimit` (layer and `guard_attempt`) |
//! | [`AUTH_ATTEMPTS_TOTAL`] | `outcome` | `layers::ratelimit::record_attempt` |
//! | [`JOBS_RUNS_TOTAL`] | `job`, `outcome` | the binary's lease runner (`anvilid` jobs) |
//! | [`TOKENS_ISSUED_TOTAL`], [`REFRESH_REUSE_TOTAL`] | `grant` / none | the token endpoint (05-12) |
//! | [`WEBHOOK_DELIVERIES_TOTAL`] | `outcome` | the webhook worker (05-14) |
//! | [`RATELIMIT_BACKEND_ERRORS_TOTAL`] | none | the shared limiter backend (05-08) |

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anvil_cache::limiter::RouteClass;
use axum::Router;
use axum::extract::{ConnectInfo, MatchedPath, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use tracing::Instrument as _;
use tracing::field::Empty;

use crate::layers::ratelimit::classify;
use crate::state::AppState;
use crate::tenant::ResolvedTenant;

/// Requests served, by `route_class` and `status_class`.
pub const HTTP_REQUESTS_TOTAL: &str = "anvil_http_requests_total";
/// Request latency in seconds (histogram), by `route_class`.
pub const HTTP_REQUEST_DURATION_SECONDS: &str = "anvil_http_request_duration_seconds";
/// Requests rejected by the rate limiter, by `route_class`.
pub const RATELIMIT_REJECTIONS_TOTAL: &str = "anvil_ratelimit_rejections_total";
/// Interactive authentication attempts, by `outcome` (`success`, `failure`).
pub const AUTH_ATTEMPTS_TOTAL: &str = "anvil_auth_attempts_total";
/// Leased periodic job runs, by `job` and `outcome` (`ran`, `lease_held`, `lease_error`).
pub const JOBS_RUNS_TOTAL: &str = "anvil_jobs_runs_total";
/// Access tokens issued, by `grant`.
pub const TOKENS_ISSUED_TOTAL: &str = "anvil_tokens_issued_total";
/// Refresh-token reuse detections (the token family is revoked).
pub const REFRESH_REUSE_TOTAL: &str = "anvil_refresh_reuse_total";
/// Webhook delivery attempts, by `outcome`.
pub const WEBHOOK_DELIVERIES_TOTAL: &str = "anvil_webhook_deliveries_total";
/// Errors talking to the shared rate-limit backend.
pub const RATELIMIT_BACKEND_ERRORS_TOTAL: &str = "anvil_ratelimit_backend_errors_total";

/// Every metric name, for tests and the exporter configuration.
pub const METRIC_NAMES: &[&str] = &[
    HTTP_REQUESTS_TOTAL,
    HTTP_REQUEST_DURATION_SECONDS,
    RATELIMIT_REJECTIONS_TOTAL,
    AUTH_ATTEMPTS_TOTAL,
    JOBS_RUNS_TOTAL,
    TOKENS_ISSUED_TOTAL,
    REFRESH_REUSE_TOTAL,
    WEBHOOK_DELIVERIES_TOTAL,
    RATELIMIT_BACKEND_ERRORS_TOTAL,
];

/// Histogram buckets of [`HTTP_REQUEST_DURATION_SECONDS`] (1 ms to 5 s). Set explicitly in the
/// exporter; without them it would render a summary.
pub const DURATION_BUCKETS: &[f64] = &[
    0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
];

/// Route template recorded for requests no route matched.
pub const UNMATCHED: &str = "unmatched";

/// Target of the access log line.
pub const ACCESS_LOG_TARGET: &str = "anvil_web::access";

/// Registers the description of every metric with the installed recorder.
pub fn describe_metrics() {
    metrics::describe_counter!(
        HTTP_REQUESTS_TOTAL,
        metrics::Unit::Count,
        "HTTP requests served, by route class and status class"
    );
    metrics::describe_histogram!(
        HTTP_REQUEST_DURATION_SECONDS,
        metrics::Unit::Seconds,
        "HTTP request latency, by route class"
    );
    metrics::describe_counter!(
        RATELIMIT_REJECTIONS_TOTAL,
        metrics::Unit::Count,
        "Requests rejected by the rate limiter, by route class"
    );
    metrics::describe_counter!(
        AUTH_ATTEMPTS_TOTAL,
        metrics::Unit::Count,
        "Interactive authentication attempts, by outcome"
    );
    metrics::describe_counter!(
        JOBS_RUNS_TOTAL,
        metrics::Unit::Count,
        "Leased background job runs, by job and outcome"
    );
    metrics::describe_counter!(
        TOKENS_ISSUED_TOTAL,
        metrics::Unit::Count,
        "Access tokens issued, by grant type"
    );
    metrics::describe_counter!(
        REFRESH_REUSE_TOTAL,
        metrics::Unit::Count,
        "Refresh token reuse detections"
    );
    metrics::describe_counter!(
        WEBHOOK_DELIVERIES_TOTAL,
        metrics::Unit::Count,
        "Webhook delivery attempts, by outcome"
    );
    metrics::describe_counter!(
        RATELIMIT_BACKEND_ERRORS_TOTAL,
        metrics::Unit::Count,
        "Errors reaching the shared rate-limit backend"
    );
}

/// The `route_class` label of a limiter class.
pub fn class_label(class: RouteClass) -> &'static str {
    match class {
        RouteClass::Auth => "auth",
        RouteClass::Token => "token",
        RouteClass::Admin => "admin",
        RouteClass::Default => "default",
    }
}

/// `2xx`, `4xx`, … (`other` outside 100..=599).
pub fn status_class(status: u16) -> &'static str {
    match status {
        100..=199 => "1xx",
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        500..=599 => "5xx",
        _ => "other",
    }
}

fn under(path: &str, prefix: &str) -> bool {
    path.strip_prefix(prefix)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

/// The route class of a tenant-relative request: the limiter class, or `health` / `metrics` /
/// `assets` for paths the limiter never sees.
pub fn route_class(method: &Method, path: &str) -> &'static str {
    match classify(method, path) {
        Some(class) => class_label(class),
        None if under(path, "/assets") => "assets",
        None if path == "/metrics" => "metrics",
        None => "health",
    }
}

/// The route class of a request answered outside tenant routing (console, probes, metrics) or
/// rejected before it (unknown tenant).
fn outer_route_class(path: &str) -> &'static str {
    if path == "/metrics" {
        "metrics"
    } else if under(path, "/health") || path == "/healthz" || path == "/readyz" {
        "health"
    } else if under(path, "/console") {
        "console"
    } else {
        "default"
    }
}

/// Records one served request in the HTTP metrics.
pub fn record_request(route_class: &'static str, status: u16, latency: Duration) {
    metrics::counter!(
        HTTP_REQUESTS_TOTAL,
        "route_class" => route_class,
        "status_class" => status_class(status),
    )
    .increment(1);
    metrics::histogram!(HTTP_REQUEST_DURATION_SECONDS, "route_class" => route_class)
        .record(latency.as_secs_f64());
}

/// The matched route template, handed from [`record_route`] to [`observe`] on the response.
#[derive(Clone)]
struct MatchedRoute(MatchedPath);

/// The resolved tenant and tenant-relative route class, handed from [`tenant_context`] to
/// [`observe`] on the response.
#[derive(Clone)]
struct TenantLabels {
    tenant: Option<String>,
    class: &'static str,
}

/// A request id worth recording: the generated UUID, or a client-sent id made only of id
/// characters (anything else is dropped rather than copied into telemetry).
fn request_id(req: &Request) -> Option<String> {
    let id = req.headers().get("x-request-id")?.to_str().ok()?;
    let ok = !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
    ok.then(|| id.to_owned())
}

/// Continues an incoming trace on the request span (the binary extracts W3C trace context from
/// the headers). Called only for requests from trusted proxies.
#[derive(Clone)]
pub struct TraceContextHook(Arc<TraceContextFn>);

/// The function behind a [`TraceContextHook`].
type TraceContextFn = dyn Fn(&HeaderMap, &tracing::Span) + Send + Sync;

impl TraceContextHook {
    pub fn new(hook: impl Fn(&HeaderMap, &tracing::Span) + Send + Sync + 'static) -> Self {
        Self(Arc::new(hook))
    }

    /// Applies the hook to `span`.
    pub fn call(&self, headers: &HeaderMap, span: &tracing::Span) {
        (self.0)(headers, span);
    }
}

impl std::fmt::Debug for TraceContextHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TraceContextHook")
    }
}

/// The request span/log/metrics layer (`axum::middleware::from_fn_with_state`, around the
/// whole router).
pub(crate) async fn observe(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let start = Instant::now();
    let fallback_class = outer_route_class(req.uri().path());
    let span = tracing::info_span!(
        "http.request",
        otel.kind = "server",
        method = %req.method(),
        route = Empty,
        tenant = Empty,
        status = Empty,
        latency_ms = Empty,
        request_id = Empty,
    );
    if let Some(id) = request_id(&req) {
        span.record("request_id", id.as_str());
    }
    if let Some(hook) = &state.config().trace_context {
        let trusted_peer = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .is_some_and(|ConnectInfo(peer)| state.config().trusted_proxies.is_trusted(peer.ip()));
        if trusted_peer {
            hook.call(req.headers(), &span);
        }
    }
    let resp = next.run(req).instrument(span.clone()).await;

    let status = resp.status().as_u16();
    let latency = start.elapsed();
    let latency_ms = u64::try_from(latency.as_millis()).unwrap_or(u64::MAX);
    let route = resp
        .extensions()
        .get::<MatchedRoute>()
        .map_or(UNMATCHED, |r| r.0.as_str());
    let labels = resp.extensions().get::<TenantLabels>();
    let tenant = labels.and_then(|l| l.tenant.as_deref());
    let class = labels.map_or(fallback_class, |l| l.class);
    span.record("route", route);
    if let Some(slug) = tenant {
        span.record("tenant", slug);
    }
    span.record("status", status);
    span.record("latency_ms", latency_ms);
    span.in_scope(|| {
        tracing::info!(
            target: ACCESS_LOG_TARGET,
            route,
            tenant,
            status,
            latency_ms,
            "request"
        );
    });
    record_request(class, status, latency);
    resp
}

/// Route layer: hands the matched route template back to [`observe`].
pub(crate) async fn record_route(req: Request, next: Next) -> Response {
    let matched = req.extensions().get::<MatchedPath>().cloned();
    let mut resp = next.run(req).await;
    if let Some(m) = matched {
        resp.extensions_mut().insert(MatchedRoute(m));
    }
    resp
}

/// Runs right after tenant resolution: records the tenant slug on the request span and hands
/// the tenant-relative route class back to [`observe`].
pub(crate) async fn tenant_context(req: Request, next: Next) -> Response {
    let class = route_class(req.method(), req.uri().path());
    let tenant = req
        .extensions()
        .get::<ResolvedTenant>()
        .map(|t| t.tenant.slug.clone());
    if let Some(slug) = &tenant {
        tracing::Span::current().record("tenant", slug.as_str());
    }
    let mut resp = next.run(req).await;
    resp.extensions_mut().insert(TenantLabels { tenant, class });
    resp
}

/// Renders the Prometheus exposition text (the binary wraps its exporter handle).
#[derive(Clone)]
pub struct MetricsEndpoint(Arc<dyn Fn() -> String + Send + Sync>);

impl MetricsEndpoint {
    pub fn new(render: impl Fn() -> String + Send + Sync + 'static) -> Self {
        Self(Arc::new(render))
    }

    pub fn render(&self) -> String {
        (self.0)()
    }
}

impl std::fmt::Debug for MetricsEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MetricsEndpoint")
    }
}

/// `GET /metrics` and nothing else: the separate metrics listener serves this router as is;
/// with `metrics_on_main_port` the main router merges it outside tenant resolution and rate
/// limiting.
pub fn metrics_router(endpoint: MetricsEndpoint) -> Router {
    Router::new().route(
        "/metrics",
        get(move || {
            let endpoint = endpoint.clone();
            async move {
                let mut resp = (StatusCode::OK, endpoint.render()).into_response();
                resp.headers_mut().insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
                );
                resp
            }
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observability_status_classes() {
        assert_eq!(status_class(101), "1xx");
        assert_eq!(status_class(200), "2xx");
        assert_eq!(status_class(303), "3xx");
        assert_eq!(status_class(429), "4xx");
        assert_eq!(status_class(503), "5xx");
        assert_eq!(status_class(42), "other");
    }

    #[test]
    fn observability_route_classes_are_bounded() {
        let get = Method::GET;
        let post = Method::POST;
        assert_eq!(route_class(&post, "/token"), "token");
        assert_eq!(route_class(&post, "/ui/login"), "auth");
        assert_eq!(route_class(&get, "/ui/login"), "default");
        assert_eq!(route_class(&get, "/api/admin/v1/users"), "admin");
        assert_eq!(route_class(&get, "/assets/anvil.css"), "assets");
        assert_eq!(route_class(&get, "/metrics"), "metrics");
        assert_eq!(route_class(&get, "/readyz"), "health");
        assert_eq!(outer_route_class("/console/tenants"), "console");
        assert_eq!(outer_route_class("/health/ready"), "health");
        assert_eq!(outer_route_class("/t/acme/authorize"), "default");
        let allowed = [
            "auth", "token", "admin", "default", "health", "metrics", "console", "assets",
        ];
        for path in ["/x", "/t/a/b", "/assets", "/console", "/metrics", "/readyz"] {
            assert!(allowed.contains(&route_class(&get, path)), "{path}");
            assert!(allowed.contains(&outer_route_class(path)), "{path}");
        }
    }

    #[test]
    fn observability_request_ids_are_filtered() {
        let req = |v: &str| {
            Request::get("/")
                .header("x-request-id", v)
                .body(axum::body::Body::empty())
                .expect("request")
        };
        assert_eq!(
            request_id(&req("0192f0c4-7a1b-7c3d-8e9f-0123456789ab")).as_deref(),
            Some("0192f0c4-7a1b-7c3d-8e9f-0123456789ab")
        );
        assert_eq!(request_id(&req("alice@example.com")), None);
        assert_eq!(request_id(&req(&"a".repeat(65))), None);
    }

    #[test]
    fn observability_metric_names_are_unique_and_prefixed() {
        let mut names = METRIC_NAMES.to_vec();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), METRIC_NAMES.len());
        assert!(names.iter().all(|n| n.starts_with("anvil_")));
        assert!(!names.contains(&"anvil_db_pool_connections"));
    }
}
