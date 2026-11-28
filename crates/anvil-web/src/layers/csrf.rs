//! Fetch-Metadata CSRF protection (SEC-04), with Go `net/http.CrossOriginProtection` semantics.
//!
//! For unsafe methods (everything except GET, HEAD, OPTIONS):
//! 1. `Sec-Fetch-Site` present: only `same-origin` or `none` pass; anything else is 403.
//! 2. Else `Origin` present: it must equal an allowed origin (the public origin, or the tenant
//!    host's origin for host-based tenants); otherwise 403.
//! 3. Else (neither header, e.g. a non-browser client or HtmlUnit): pass. The per-flow synchronizer
//!    token is still checked by the handler.
//!
//! Applied in `ui::routes()` only. `/token`, `/api/admin/*` and `POST /authorize` are exempt
//! (client-authenticated or cross-site by design).
//!
//! The headless flow API (`/api/flows/v1`) has its own, separate layer
//! ([`headless_origin_layer`]): the tenant's own origin or an exact entry of its
//! `headless.allowed_origins`, and JSON bodies only. It never relaxes the UI layer.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use axum::response::{IntoResponse, Response};
use tower::{Layer, Service};

use crate::errors::error_page_in;
use crate::i18n::locale_of;
use crate::state::AppState;
use crate::tenant::{AllowedOrigins, ResolvedTenant};

const SEC_FETCH_SITE: &str = "sec-fetch-site";

/// The layer. Allowed origins come from the tenant layer's request extension; without it any
/// request carrying an `Origin` is rejected (fail closed).
pub fn fetch_metadata_layer() -> FetchMetadataLayer {
    FetchMetadataLayer
}

#[derive(Debug, Clone, Copy)]
pub struct FetchMetadataLayer;

impl<S> Layer<S> for FetchMetadataLayer {
    type Service = FetchMetadata<S>;

    fn layer(&self, inner: S) -> Self::Service {
        FetchMetadata { inner }
    }
}

#[derive(Debug, Clone)]
pub struct FetchMetadata<S> {
    inner: S,
}

/// The decision of the three rules above.
pub(crate) fn allowed(method: &Method, headers: &HeaderMap, origins: &[String]) -> bool {
    if matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) {
        return true;
    }
    if let Some(site) = headers.get(SEC_FETCH_SITE) {
        return matches!(site.to_str(), Ok("same-origin" | "none"));
    }
    if let Some(origin) = headers.get(header::ORIGIN) {
        return origin.to_str().is_ok_and(|o| {
            origins
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(o))
        });
    }
    true
}

fn reject(req: &Request<Body>) -> Response {
    tracing::info!(method = %req.method(), path = %req.uri().path(), "cross-origin form submission rejected");
    match req.extensions().get::<AppState>() {
        Some(state) => {
            let tenant = req.extensions().get::<ResolvedTenant>();
            let locale = locale_of(state, tenant, req.headers(), req.uri().query());
            error_page_in(state, tenant, &locale, StatusCode::FORBIDDEN, "csrf", "")
        }
        None => (StatusCode::FORBIDDEN, "forbidden").into_response(),
    }
}

impl<S> Service<Request<Body>> for FetchMetadata<S>
where
    S: Service<Request<Body>, Response = Response> + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Response, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let origins = req
            .extensions()
            .get::<AllowedOrigins>()
            .map(|o| o.0.as_slice())
            .unwrap_or(&[]);
        if allowed(req.method(), req.headers(), origins) {
            Box::pin(self.inner.call(req))
        } else {
            let resp = reject(&req);
            Box::pin(async move { Ok(resp) })
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Headless flow API (browser mode, UI-05)
// ---------------------------------------------------------------------------------------------

/// The origin and content-type check of the headless flow API (`/api/flows/v1`, browser mode).
///
/// A separate layer, applied only inside `api_flows::routes()`: the UI router keeps
/// [`fetch_metadata_layer`] unchanged. Rules, for every method except `OPTIONS` (the CORS layer
/// answers preflights before this layer runs):
///
/// 1. `Origin` present: it must equal the tenant's own origin (`AllowedOrigins`) or one entry of
///    the tenant's `headless.allowed_origins` (exact, byte-for-byte); otherwise 403.
/// 2. Else `Sec-Fetch-Site` present: only `same-origin` or `none` pass (a same-site or cross-site
///    browser request without `Origin` is never admitted); otherwise 403.
/// 3. Else (no browser signal): pass. The handler still requires the flow cookie plus the CSRF
///    token in `X-CSRF-Token`.
///
/// A `POST` that passes must carry `Content-Type: application/json` (parameters allowed), else
/// 415: a cross-site HTML form can only send form-encoded, multipart or text bodies. Refusals are
/// JSON problems (`application/problem+json`), never HTML pages.
pub fn headless_origin_layer() -> HeadlessOriginLayer {
    HeadlessOriginLayer
}

#[derive(Debug, Clone, Copy)]
pub struct HeadlessOriginLayer;

impl<S> Layer<S> for HeadlessOriginLayer {
    type Service = HeadlessOrigin<S>;

    fn layer(&self, inner: S) -> Self::Service {
        HeadlessOrigin { inner }
    }
}

#[derive(Debug, Clone)]
pub struct HeadlessOrigin<S> {
    inner: S,
}

/// The decision of [`headless_origin_layer`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HeadlessVerdict {
    Allow,
    /// 403 `forbidden_origin`.
    ForbiddenOrigin,
    /// 415 `unsupported_media_type`.
    UnsupportedMediaType,
}

/// The rules of [`headless_origin_layer`]: `own` are the tenant's own origins, `listed` its
/// `headless.allowed_origins`.
pub(crate) fn headless_verdict(
    method: &Method,
    headers: &HeaderMap,
    own: &[String],
    listed: &[String],
) -> HeadlessVerdict {
    if *method == Method::OPTIONS {
        return HeadlessVerdict::Allow;
    }
    let origin_ok = if let Some(origin) = headers.get(header::ORIGIN) {
        origin.to_str().is_ok_and(|o| {
            own.iter().any(|allowed| allowed.eq_ignore_ascii_case(o))
                || listed.iter().any(|allowed| allowed == o)
        })
    } else if let Some(site) = headers.get(SEC_FETCH_SITE) {
        matches!(site.to_str(), Ok("same-origin" | "none"))
    } else {
        true
    };
    if !origin_ok {
        return HeadlessVerdict::ForbiddenOrigin;
    }
    if *method == Method::POST && !is_json(headers) {
        return HeadlessVerdict::UnsupportedMediaType;
    }
    HeadlessVerdict::Allow
}

/// `Content-Type: application/json`, optionally with parameters (`; charset=utf-8`).
fn is_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|essence| essence.trim().eq_ignore_ascii_case("application/json"))
}

impl<S> Service<Request<Body>> for HeadlessOrigin<S>
where
    S: Service<Request<Body>, Response = Response> + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Response, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let own = req
            .extensions()
            .get::<AllowedOrigins>()
            .map(|o| o.0.as_slice())
            .unwrap_or(&[]);
        // Without a resolved tenant there is no allow-list (fail closed for foreign origins).
        let listed = req
            .extensions()
            .get::<ResolvedTenant>()
            .map(|t| t.tenant.settings.headless.allowed_origins.as_slice())
            .unwrap_or(&[]);
        let verdict = headless_verdict(req.method(), req.headers(), own, listed);
        let resp = match verdict {
            HeadlessVerdict::Allow => return Box::pin(self.inner.call(req)),
            HeadlessVerdict::ForbiddenOrigin => {
                tracing::info!(method = %req.method(), path = %req.uri().path(), "headless flow request from a foreign origin rejected");
                crate::api_flows::problem(StatusCode::FORBIDDEN, "forbidden_origin")
            }
            HeadlessVerdict::UnsupportedMediaType => crate::api_flows::problem(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "unsupported_media_type",
            ),
        };
        Box::pin(async move { Ok(resp) })
    }
}

#[cfg(test)]
mod headless_tests {
    use super::*;

    const OWN: &str = "https://op.test";
    const SPA: &str = "https://app.op.test";

    fn verdict(method: Method, headers: &[(&str, &str)]) -> HeadlessVerdict {
        let mut h = HeaderMap::new();
        for (k, v) in headers {
            h.insert(
                axum::http::HeaderName::from_bytes(k.as_bytes()).expect("name"),
                v.parse().expect("value"),
            );
        }
        headless_verdict(&method, &h, &[OWN.into()], &[SPA.into()])
    }

    const JSON: (&str, &str) = ("content-type", "application/json");

    #[test]
    fn same_origin_passes() {
        assert_eq!(
            verdict(Method::POST, &[("origin", OWN), JSON]),
            HeadlessVerdict::Allow
        );
        assert_eq!(
            verdict(Method::POST, &[("sec-fetch-site", "same-origin"), JSON]),
            HeadlessVerdict::Allow
        );
        assert_eq!(verdict(Method::GET, &[]), HeadlessVerdict::Allow);
    }

    #[test]
    fn allow_listed_cross_origin_passes() {
        assert_eq!(
            verdict(
                Method::POST,
                &[("origin", SPA), ("sec-fetch-site", "same-site"), JSON]
            ),
            HeadlessVerdict::Allow
        );
        assert_eq!(
            verdict(
                Method::GET,
                &[("origin", SPA), ("sec-fetch-site", "cross-site")]
            ),
            HeadlessVerdict::Allow
        );
    }

    #[test]
    fn unlisted_origin_is_forbidden() {
        for origin in [
            "https://evil.test",
            "null",
            "https://app.op.test:444",
            "https://APP.op.test",
            "http://app.op.test",
        ] {
            assert_eq!(
                verdict(Method::POST, &[("origin", origin), JSON]),
                HeadlessVerdict::ForbiddenOrigin,
                "{origin}"
            );
            assert_eq!(
                verdict(Method::GET, &[("origin", origin)]),
                HeadlessVerdict::ForbiddenOrigin,
                "GET {origin}"
            );
        }
    }

    #[test]
    fn cross_site_without_origin_is_forbidden() {
        for site in ["cross-site", "same-site"] {
            assert_eq!(
                verdict(Method::POST, &[("sec-fetch-site", site), JSON]),
                HeadlessVerdict::ForbiddenOrigin,
                "{site}"
            );
        }
    }

    #[test]
    fn post_without_json_is_unsupported_media_type() {
        for ct in [
            "application/x-www-form-urlencoded",
            "multipart/form-data; boundary=x",
            "text/plain",
            "application/jsonx",
        ] {
            assert_eq!(
                verdict(Method::POST, &[("origin", SPA), ("content-type", ct)]),
                HeadlessVerdict::UnsupportedMediaType,
                "{ct}"
            );
        }
        assert_eq!(
            verdict(Method::POST, &[("origin", SPA)]),
            HeadlessVerdict::UnsupportedMediaType
        );
        assert_eq!(
            verdict(
                Method::POST,
                &[
                    ("origin", SPA),
                    ("content-type", "application/json; charset=utf-8")
                ]
            ),
            HeadlessVerdict::Allow
        );
    }

    #[test]
    fn origin_wins_over_sec_fetch_site() {
        assert_eq!(
            verdict(
                Method::POST,
                &[
                    ("origin", "https://evil.test"),
                    ("sec-fetch-site", "same-origin"),
                    JSON
                ]
            ),
            HeadlessVerdict::ForbiddenOrigin
        );
    }

    #[test]
    fn without_a_tenant_list_only_own_origin_passes() {
        let mut h = HeaderMap::new();
        h.insert(header::ORIGIN, SPA.parse().expect("value"));
        assert_eq!(
            headless_verdict(&Method::GET, &h, &[OWN.into()], &[]),
            HeadlessVerdict::ForbiddenOrigin
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::routing::post;
    use tower::ServiceExt;

    fn app() -> Router {
        Router::new()
            .route("/ui/login", post(|| async { "ok" }).get(|| async { "ok" }))
            .layer(fetch_metadata_layer())
            .layer(axum::middleware::from_fn(
                |mut req: Request<Body>, next: axum::middleware::Next| async move {
                    req.extensions_mut()
                        .insert(AllowedOrigins(vec!["https://op.test".into()]));
                    next.run(req).await
                },
            ))
    }

    async fn status(method: Method, headers: &[(&str, &str)]) -> StatusCode {
        let mut b = Request::builder().method(method).uri("/ui/login");
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        app()
            .oneshot(b.body(Body::empty()).expect("request"))
            .await
            .expect("infallible")
            .status()
    }

    #[tokio::test]
    async fn sec_fetch_site_rules() {
        assert_eq!(
            status(Method::POST, &[("sec-fetch-site", "cross-site")]).await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            status(Method::POST, &[("sec-fetch-site", "same-site")]).await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            status(Method::POST, &[("sec-fetch-site", "same-origin")]).await,
            StatusCode::OK
        );
        assert_eq!(
            status(Method::POST, &[("sec-fetch-site", "none")]).await,
            StatusCode::OK
        );
        // Sec-Fetch-Site wins over a matching Origin.
        assert_eq!(
            status(
                Method::POST,
                &[
                    ("sec-fetch-site", "cross-site"),
                    ("origin", "https://op.test")
                ]
            )
            .await,
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn origin_rules() {
        assert_eq!(
            status(Method::POST, &[("origin", "https://evil.test")]).await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            status(Method::POST, &[("origin", "null")]).await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            status(Method::POST, &[("origin", "https://op.test")]).await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn no_headers_pass_and_safe_methods_pass() {
        assert_eq!(status(Method::POST, &[]).await, StatusCode::OK);
        assert_eq!(
            status(Method::GET, &[("sec-fetch-site", "cross-site")]).await,
            StatusCode::OK
        );
    }

    #[test]
    fn without_allowed_origins_any_origin_is_rejected() {
        let mut h = HeaderMap::new();
        h.insert(header::ORIGIN, "https://op.test".parse().expect("value"));
        assert!(!allowed(&Method::POST, &h, &[]));
        assert!(allowed(&Method::POST, &HeaderMap::new(), &[]));
    }
}
