//! Headless flow API (`/api/flows/v1`, UI-05): JSON login, registration, recovery and
//! verification flows for native and single-page clients. Owned by plans 07-10 and 07-18;
//! pre-declared by 07-04 so no later plan edits `lib.rs`.
//!
//! [`routes`] is merged into the tenant router next to `ui::routes()`, outside the UI
//! Fetch-Metadata layer and outside `public_cors()`: 07-10 adds its own allow-listed origin and
//! CORS layers here. The rate-limit class of `POST` below `/api/flows` is `Auth`
//! ([`crate::layers::ratelimit`]); its 429 is JSON.
//!
//! Until the flows exist, every path below `/api/flows/v1` answers a JSON 404 (RFC 9457
//! problem), never a success.

use axum::Router;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use serde_json::json;

use crate::state::AppState;

/// Path prefix of the headless flow API.
pub const BASE_PATH: &str = "/api/flows/v1";

/// The headless flow routes. No flow is implemented yet: unknown paths below [`BASE_PATH`]
/// answer a JSON 404.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route(BASE_PATH, any(unknown_route))
        .route(&format!("{BASE_PATH}/{{*rest}}"), any(unknown_route))
}

/// Unknown paths below the API prefix answer with a problem, not the HTML 404 page.
async fn unknown_route() -> Response {
    let status = StatusCode::NOT_FOUND;
    let body = json!({
        "type": "about:blank",
        "title": "Not Found",
        "status": status.as_u16(),
    });
    let mut resp = (status, body.to_string()).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    resp
}
