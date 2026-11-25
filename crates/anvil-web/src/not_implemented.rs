//! Explicit `501 Not Implemented` responses for endpoints advertised in discovery but not built yet (M0).

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

fn not_implemented(endpoint: &str) -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({
            "error": "not_implemented",
            "error_description": format!("{endpoint} is not implemented in this build (M0)"),
        })),
    )
        .into_response()
}

pub(crate) async fn authorize() -> Response {
    not_implemented("/authorize")
}

pub(crate) async fn token() -> Response {
    not_implemented("/token")
}

pub(crate) async fn jwks() -> Response {
    not_implemented("/jwks")
}
