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

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use axum::response::{IntoResponse, Response};
use tower::{Layer, Service};

use crate::errors::error_page;
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
        Some(state) => error_page(
            state,
            req.extensions().get::<ResolvedTenant>(),
            StatusCode::FORBIDDEN,
            "csrf",
            "",
        ),
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
