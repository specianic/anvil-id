//! CORS for the public, non-cookie protocol endpoints only: discovery, JWKS, token and userinfo.
//! Never applied to `/authorize` or `/ui/*` (those rely on cookies and must stay same-origin).
//!
//! The headless flow API (`/api/flows/v1`, browser mode) has its own credentialed policy,
//! [`headless_cors`]: only origins in the tenant's `headless.allowed_origins` (exact match) are
//! echoed, with `Access-Control-Allow-Credentials: true`; never `*`.

use std::time::Duration;

use axum::http::request::Parts;
use axum::http::{HeaderName, HeaderValue, Method, header};
use tower_http::cors::{AllowOrigin, Any, CorsLayer};

use crate::tenant::ResolvedTenant;

/// The CSRF header of the headless flow API (browser mode).
pub const CSRF_HEADER: &str = "x-csrf-token";

/// Any origin, GET/POST, no credentials.
pub fn public_cors() -> CorsLayer {
    CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
}

/// Credentialed CORS for the headless flow API: the request's `Origin` is echoed only when it
/// equals an entry of the resolved tenant's `headless.allowed_origins` (byte-for-byte). Methods
/// GET and POST, request headers `Content-Type` and `X-CSRF-Token`, `Retry-After` exposed,
/// `Vary: Origin` (and the preflight request headers) on every answer. An unlisted origin gets
/// no `Access-Control-Allow-*` headers, so the browser withholds the response.
pub fn headless_cors() -> CorsLayer {
    CorsLayer::new()
        .allow_origin(AllowOrigin::predicate(headless_origin_listed))
        .allow_credentials(true)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([header::CONTENT_TYPE, HeaderName::from_static(CSRF_HEADER)])
        .expose_headers([header::RETRY_AFTER])
        .max_age(Duration::from_secs(600))
}

/// Whether `origin` is in the allow-list of the tenant the request resolved to (none: no).
fn headless_origin_listed(origin: &HeaderValue, parts: &Parts) -> bool {
    let Ok(origin) = origin.to_str() else {
        return false;
    };
    parts.extensions.get::<ResolvedTenant>().is_some_and(|t| {
        t.tenant
            .settings
            .headless
            .allowed_origins
            .iter()
            .any(|o| o == origin)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::get;
    use tower::ServiceExt;

    #[tokio::test]
    async fn any_origin_without_credentials() {
        let app = Router::new()
            .route("/jwks", get(|| async { "{}" }))
            .layer(public_cors());
        let resp = app
            .oneshot(
                Request::get("/jwks")
                    .header(header::ORIGIN, "https://rp.example")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("infallible");
        assert_eq!(resp.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");
        assert!(
            resp.headers()
                .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
                .is_none()
        );
    }

    mod headless {
        use super::super::*;
        use anvil_core::model::{HeadlessSettings, Tenant, TenantBase, TenantId, TenantSettings};
        use axum::Router;
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use axum::routing::post;
        use time::OffsetDateTime;
        use tower::ServiceExt;

        const SPA: &str = "https://app.op.test";

        fn tenant() -> ResolvedTenant {
            ResolvedTenant {
                tenant: Tenant {
                    id: TenantId::new_v7(),
                    slug: "acme".into(),
                    display_name: "Acme".into(),
                    host: None,
                    settings: TenantSettings {
                        headless: HeadlessSettings {
                            allowed_origins: vec![SPA.into()],
                        },
                        ..TenantSettings::default()
                    },
                    created_at: OffsetDateTime::UNIX_EPOCH,
                },
                base: TenantBase::Path("acme".into()),
                issuer: "https://op.test/t/acme".into(),
            }
        }

        fn app(with_tenant: bool) -> Router {
            Router::new()
                .route("/api/flows/v1/login", post(|| async { "{}" }))
                .layer(headless_cors())
                .layer(axum::middleware::from_fn(
                    move |mut req: Request<Body>, next: axum::middleware::Next| async move {
                        if with_tenant {
                            req.extensions_mut().insert(tenant());
                        }
                        next.run(req).await
                    },
                ))
        }

        async fn send(app: Router, req: Request<Body>) -> axum::response::Response {
            app.oneshot(req).await.expect("infallible")
        }

        fn post_from(origin: &str) -> Request<Body> {
            Request::post("/api/flows/v1/login")
                .header(header::ORIGIN, origin)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .expect("request")
        }

        fn preflight(origin: &str) -> Request<Body> {
            Request::builder()
                .method(Method::OPTIONS)
                .uri("/api/flows/v1/login")
                .header(header::ORIGIN, origin)
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
                .header(
                    header::ACCESS_CONTROL_REQUEST_HEADERS,
                    "content-type,x-csrf-token",
                )
                .body(Body::empty())
                .expect("request")
        }

        #[tokio::test]
        async fn allow_listed_origin_is_echoed_with_credentials_and_vary() {
            let resp = send(app(true), post_from(SPA)).await;
            assert_eq!(resp.status(), StatusCode::OK);
            let h = resp.headers();
            assert_eq!(h[header::ACCESS_CONTROL_ALLOW_ORIGIN], SPA);
            assert_eq!(h[header::ACCESS_CONTROL_ALLOW_CREDENTIALS], "true");
            let vary: Vec<_> = h
                .get_all(header::VARY)
                .iter()
                .map(|v| v.to_str().expect("ascii").to_ascii_lowercase())
                .collect();
            assert!(vary.iter().any(|v| v.contains("origin")), "{vary:?}");
        }

        #[tokio::test]
        async fn unlisted_origin_gets_no_cors_headers_and_never_a_wildcard() {
            for origin in ["https://evil.test", "null", "https://app.op.test.evil.test"] {
                let resp = send(app(true), post_from(origin)).await;
                let h = resp.headers();
                // Without `Access-Control-Allow-Origin` the browser withholds the response
                // (tower-http may still send `Allow-Credentials`, which grants nothing alone).
                assert!(
                    h.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none(),
                    "{origin}"
                );
            }
            // Without a resolved tenant nothing is listed.
            let resp = send(app(false), post_from(SPA)).await;
            assert!(
                resp.headers()
                    .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                    .is_none()
            );
        }

        #[tokio::test]
        async fn preflight_allows_the_csrf_header_for_listed_origins_only() {
            let resp = send(app(true), preflight(SPA)).await;
            let h = resp.headers();
            assert_eq!(h[header::ACCESS_CONTROL_ALLOW_ORIGIN], SPA);
            assert_eq!(h[header::ACCESS_CONTROL_ALLOW_CREDENTIALS], "true");
            let allowed = h[header::ACCESS_CONTROL_ALLOW_HEADERS]
                .to_str()
                .expect("ascii")
                .to_ascii_lowercase();
            assert!(allowed.contains("x-csrf-token"), "{allowed}");
            assert!(allowed.contains("content-type"), "{allowed}");
            let resp = send(app(true), preflight("https://evil.test")).await;
            assert!(
                resp.headers()
                    .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                    .is_none()
            );
        }
    }
}
