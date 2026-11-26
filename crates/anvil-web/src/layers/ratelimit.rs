//! Request rate limiting on top of the single limiter (SEC-05, ARCHITECTURE §11).
//!
//! - [`classify`] maps a request (method + tenant-relative path) to a [`RouteClass`], or to
//!   `None` for paths that are never limited (health probes, static assets).
//! - [`layer`] runs inside the tenant-routed service (after tenant resolution, so paths are
//!   tenant-relative). It keys every classified request by the client IP from the trusted-proxy
//!   extractor ([`crate::client_ip`]) and answers 429 with `Retry-After` when the class quota of
//!   that IP is exhausted. Handlers never sleep.
//! - [`guard_attempt`] and [`record_attempt`] are the brute-force helper API of UI handlers
//!   (login, second factor). They are the only place UI handlers touch the limiter.
//! - [`too_many_requests`] is the one place a 429 response is built, per surface:
//!   OAuth-style JSON for protocol endpoints (OAuth has no rate-limit error code, so the body is
//!   `{"error":"invalid_request","error_description":"too many requests"}`), RFC 9457 problem JSON
//!   for the admin API, and the themed error page for browser routes.
//!
//! # Route classes
//!
//! | Request | Class |
//! | ------- | ----- |
//! | `/health/*`, `/healthz`, `/readyz`, `/metrics`, `/assets/*` (any method) | never limited |
//! | `/token`, `/introspect`, `/revoke` (any method) | `Token` |
//! | `/api/admin` and below (any method) | `Admin` |
//! | `POST` to `/ui/login`, `/ui/registration`, `/ui/recovery`, `/setup` and below | `Auth` |
//! | everything else (including `GET` of the auth pages) | `Default` |

use std::time::Duration;

use anvil_cache::limiter::{Decision, LimitKey, RouteClass};
use anvil_core::model::{
    AuditAction, AuditActor, AuditDetails, AuditOutcome, RequestContext, TenantId,
};
use anvil_core::service::audit::AuditService;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use std::net::IpAddr;

use crate::client_ip::ClientIp;
use crate::errors::error_page;
use crate::observability::{AUTH_ATTEMPTS_TOTAL, RATELIMIT_REJECTIONS_TOTAL, class_label};
use crate::state::AppState;
use crate::tenant::ResolvedTenant;

/// Paths (and everything below them) that are never rate limited.
const EXEMPT: &[&str] = &["/health", "/healthz", "/readyz", "/metrics", "/assets"];
/// Token-class paths (any method).
const TOKEN: &[&str] = &["/token", "/introspect", "/revoke"];
/// Admin-class paths (any method).
const ADMIN: &[&str] = &["/api/admin"];
/// Auth-class paths (`POST` only; rendering the page is `Default`).
const AUTH_POST: &[&str] = &["/ui/login", "/ui/registration", "/ui/recovery", "/setup"];
/// Paths whose 429 is an OAuth-style JSON body (protocol endpoints, not browser pages).
const PROTOCOL: &[&str] = &[
    "/token",
    "/introspect",
    "/revoke",
    "/userinfo",
    "/jwks",
    "/.well-known",
];

/// The body description of every 429 (fixed, client-safe).
pub const TOO_MANY_REQUESTS: &str = "too many requests";

/// `path` is `prefix` or lies below it (`/ui/login/x`, never `/ui/loginx`).
fn under(path: &str, prefix: &str) -> bool {
    path.strip_prefix(prefix)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

fn under_any(path: &str, prefixes: &[&str]) -> bool {
    prefixes.iter().any(|p| under(path, p))
}

/// The route class of a request by method and tenant-relative path; `None` means the request is
/// never limited. See the module table.
pub fn classify(method: &Method, path: &str) -> Option<RouteClass> {
    if under_any(path, EXEMPT) {
        return None;
    }
    if under_any(path, TOKEN) {
        return Some(RouteClass::Token);
    }
    if under_any(path, ADMIN) {
        return Some(RouteClass::Admin);
    }
    if method == Method::POST && under_any(path, AUTH_POST) {
        return Some(RouteClass::Auth);
    }
    Some(RouteClass::Default)
}

/// Which response shape a 429 takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Surface {
    /// OAuth / OIDC protocol endpoints: OAuth-style JSON.
    Protocol,
    /// The management API: RFC 9457 problem JSON.
    Admin,
    /// Browser routes: the themed error page.
    Browser,
}

impl Surface {
    /// The surface of a tenant-relative path.
    pub fn of(path: &str) -> Self {
        if under(path, "/api") {
            Surface::Admin
        } else if under_any(path, PROTOCOL) {
            Surface::Protocol
        } else {
            Surface::Browser
        }
    }
}

/// `Retry-After` in whole seconds, rounded up, at least 1.
fn retry_after_secs(d: Duration) -> u64 {
    let secs = d.as_secs() + u64::from(d.subsec_nanos() > 0);
    secs.max(1)
}

/// The 429 response for `surface`, with `Retry-After` and `Cache-Control: no-store`.
pub fn too_many_requests(
    state: &AppState,
    tenant: Option<&ResolvedTenant>,
    surface: Surface,
    retry_after: Duration,
) -> Response {
    let status = StatusCode::TOO_MANY_REQUESTS;
    let mut resp = match surface {
        Surface::Protocol => {
            let body = json!({
                "error": "invalid_request",
                "error_description": TOO_MANY_REQUESTS,
            });
            let mut r = (status, axum::Json(body)).into_response();
            r.headers_mut()
                .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
            r
        }
        Surface::Admin => {
            let body = json!({
                "type": "urn:anvilid:problem:too_many_requests",
                "title": "Too Many Requests",
                "status": status.as_u16(),
                "detail": TOO_MANY_REQUESTS,
                "errors": [],
            });
            let mut r = (status, body.to_string()).into_response();
            r.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/problem+json"),
            );
            r
        }
        Surface::Browser => error_page(
            state,
            tenant,
            status,
            "too_many_requests",
            "Too many requests. Please wait a moment and try again.",
        ),
    };
    let headers = resp.headers_mut();
    headers.insert(
        header::RETRY_AFTER,
        HeaderValue::from(retry_after_secs(retry_after)),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

/// The route-class rate-limit layer (`axum::middleware::from_fn_with_state` inside the
/// tenant-routed service). A request without a peer address is a wiring error and gets the
/// generic 500 of [`crate::client_ip::MissingPeerAddress`]; no address is ever invented.
pub(crate) async fn layer(State(state): State<AppState>, req: Request, next: Next) -> Response {
    if !state.config().rate_limits.enabled {
        return next.run(req).await;
    }
    let Some(class) = classify(req.method(), req.uri().path()) else {
        return next.run(req).await;
    };
    let (parts, body) = req.into_parts();
    let ip = match ClientIp::from_parts(&parts, &state.config().trusted_proxies) {
        Ok(ip) => ip,
        Err(e) => return e.into_response(),
    };
    match state.limiter().check(class, &LimitKey::Ip(ip.0)).await {
        Decision::Deny { retry_after } => {
            // No client IP in operational logs (the audit log keeps it where it is recorded).
            tracing::info!(?class, "rate limited");
            metrics::counter!(RATELIMIT_REJECTIONS_TOTAL, "route_class" => class_label(class))
                .increment(1);
            too_many_requests(
                &state,
                parts.extensions.get::<ResolvedTenant>(),
                Surface::of(parts.uri.path()),
                retry_after,
            )
        }
        Decision::Allow | Decision::RequireCaptcha => {
            next.run(Request::from_parts(parts, body)).await
        }
    }
}

/// SHA-256 of the normalised identifier (trimmed, lowercased): the limiter never sees it in clear.
pub fn identifier_hash(identifier: &str) -> [u8; 32] {
    let normalised = identifier.trim().to_lowercase();
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, normalised.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

/// The strict (identifier + IP) and loose (identifier only) brute-force keys of an attempt.
pub fn attempt_keys(tenant: TenantId, identifier: &str, ip: IpAddr) -> (LimitKey, LimitKey) {
    let ident = identifier_hash(identifier);
    (
        LimitKey::IdentIp { tenant, ident, ip },
        LimitKey::Identifier { tenant, ident },
    )
}

/// The brute-force decision before an attempt (two-tier gate of the limiter): a locked strict key
/// denies with `retry_after`; a loose key over its hourly threshold requires a CAPTCHA when the
/// tenant has one (`captcha_available`), otherwise a short delay (`Deny`).
pub async fn guard_attempt(
    state: &AppState,
    strict: &LimitKey,
    loose: &LimitKey,
    captcha_available: bool,
) -> Decision {
    let decision = state
        .limiter()
        .brute_force_gate(strict, loose, captcha_available)
        .await;
    if matches!(decision, Decision::Deny { .. }) {
        metrics::counter!(
            RATELIMIT_REJECTIONS_TOTAL,
            "route_class" => class_label(RouteClass::Auth),
        )
        .increment(1);
    }
    decision
}

fn key_kind(key: &LimitKey) -> &'static str {
    match key {
        LimitKey::Ip(_) => "ip",
        LimitKey::Identifier { .. } => "identifier",
        LimitKey::IdentIp { .. } => "identifier_ip",
        LimitKey::Client { .. } => "client",
        LimitKey::User { .. } => "user",
    }
}

/// Records the outcome of an attempt for every key. Success forgets the keys' failures. A failure
/// counts against each key; when a key goes from unlocked to locked, a `rate_limit_lockout` audit
/// event (actor `system`, details: key kind and lock seconds, never the identifier) is recorded in
/// `tenant` with the request context. An audit append failure is logged and does not fail the
/// request.
pub async fn record_attempt(
    state: &AppState,
    tenant: TenantId,
    ctx: &RequestContext,
    keys: &[LimitKey],
    success: bool,
) {
    metrics::counter!(
        AUTH_ATTEMPTS_TOTAL,
        "outcome" => if success { "success" } else { "failure" },
    )
    .increment(1);
    let limiter = state.limiter();
    for key in keys {
        if success {
            limiter.record_success(key).await;
            continue;
        }
        let was_locked = limiter.backoff(key).await.is_some();
        let after = limiter.record_failure(key).await;
        let Some(locked_for) = after.locked_for else {
            continue;
        };
        if was_locked {
            continue;
        }
        let audit = AuditService {
            storage: state.storage_arc(),
            clock: state.clock_arc(),
        };
        let details = AuditDetails::reason(key_kind(key)).with(AuditDetails::count(
            "locked_seconds",
            retry_after_secs(locked_for),
        ));
        if let Err(e) = audit
            .record(
                tenant,
                AuditActor::system(),
                AuditAction::RateLimitLockout,
                None,
                AuditOutcome::Failure,
                ctx,
                details,
            )
            .await
        {
            tracing::error!(error = %e, "recording the rate_limit_lockout audit event failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_table() {
        let get = Method::GET;
        let post = Method::POST;
        let cases: &[(&Method, &str, Option<RouteClass>)] = &[
            (&get, "/health/live", None),
            (&get, "/health/ready", None),
            (&get, "/healthz", None),
            (&get, "/readyz", None),
            (&get, "/metrics", None),
            (&get, "/assets/anvil.css", None),
            (&post, "/token", Some(RouteClass::Token)),
            (&get, "/token", Some(RouteClass::Token)),
            (&post, "/introspect", Some(RouteClass::Token)),
            (&post, "/revoke", Some(RouteClass::Token)),
            (&get, "/api/admin", Some(RouteClass::Admin)),
            (&post, "/api/admin/users", Some(RouteClass::Admin)),
            (
                &Method::DELETE,
                "/api/admin/clients/x",
                Some(RouteClass::Admin),
            ),
            (&post, "/ui/login", Some(RouteClass::Auth)),
            (&post, "/ui/login/mfa", Some(RouteClass::Auth)),
            (&post, "/ui/registration", Some(RouteClass::Auth)),
            (&post, "/ui/recovery", Some(RouteClass::Auth)),
            (&post, "/ui/recovery/reset", Some(RouteClass::Auth)),
            (&post, "/setup", Some(RouteClass::Auth)),
            (&get, "/ui/login", Some(RouteClass::Default)),
            (&get, "/ui/registration", Some(RouteClass::Default)),
            (&get, "/setup", Some(RouteClass::Default)),
            (&post, "/ui/loginx", Some(RouteClass::Default)),
            (&post, "/tokens", Some(RouteClass::Default)),
            (&get, "/healthcheck", Some(RouteClass::Default)),
            (&get, "/authorize", Some(RouteClass::Default)),
            (
                &get,
                "/.well-known/openid-configuration",
                Some(RouteClass::Default),
            ),
            (&get, "/userinfo", Some(RouteClass::Default)),
            (&get, "/", Some(RouteClass::Default)),
        ];
        for (method, path, want) in cases {
            assert_eq!(classify(method, path), *want, "{method} {path}");
        }
    }

    #[test]
    fn surfaces() {
        assert_eq!(Surface::of("/token"), Surface::Protocol);
        assert_eq!(Surface::of("/userinfo"), Surface::Protocol);
        assert_eq!(Surface::of("/.well-known/jwks.json"), Surface::Protocol);
        assert_eq!(Surface::of("/api/admin/users"), Surface::Admin);
        assert_eq!(Surface::of("/ui/login"), Surface::Browser);
        assert_eq!(Surface::of("/setup"), Surface::Browser);
        assert_eq!(Surface::of("/authorize"), Surface::Browser);
    }

    #[test]
    fn retry_after_rounds_up_to_whole_seconds() {
        assert_eq!(retry_after_secs(Duration::ZERO), 1);
        assert_eq!(retry_after_secs(Duration::from_millis(1)), 1);
        assert_eq!(retry_after_secs(Duration::from_secs(12)), 12);
        assert_eq!(retry_after_secs(Duration::from_millis(12_001)), 13);
    }

    #[test]
    fn identifier_hash_normalises() {
        assert_eq!(
            identifier_hash(" Alice@Example.COM "),
            identifier_hash("alice@example.com")
        );
        assert_ne!(identifier_hash("alice"), identifier_hash("bob"));
    }
}
