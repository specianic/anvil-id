//! CORS for the public, non-cookie protocol endpoints only: discovery, JWKS, token and userinfo.
//! Never applied to `/authorize` or `/ui/*` (those rely on cookies and must stay same-origin).

use axum::http::{Method, header};
use tower_http::cors::{Any, CorsLayer};

/// Any origin, GET/POST, no credentials.
pub fn public_cors() -> CorsLayer {
    CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
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
}
