//! Headless flow API (`/api/flows/v1`, UI-05): JSON login, registration, recovery and
//! verification flows for single-page apps (browser mode, plan 07-10; native apps follow in
//! 07-18). See docs/HEADLESS.md.
//!
//! A second renderer over the shared [`crate::ui::flow_driver`]: every handler in [`browser`]
//! calls the driver, so throttling, CAPTCHA, the flow binding and session handling exist once.
//! The handlers only map the driver's typed outcomes to the versioned DTO ([`dto`]).
//!
//! | Route (tenant-relative) | |
//! |---|---|
//! | `POST /api/flows/v1/{kind}` | start (`kind` = `login`, `registration`, `recovery`, `verification`) |
//! | `GET  /api/flows/v1/{kind}/{flow_id}` | the current step |
//! | `POST /api/flows/v1/{kind}/{flow_id}` | submit the current step |
//! | `POST /api/flows/v1/login/{flow_id}/passkey/options` | discoverable passkey sign-in options |
//! | `POST /api/flows/v1/login/{flow_id}/passkey` | the passkey assertion |
//! | `POST /api/flows/v1/login/{flow_id}/enroll/passkey/{start,finish}` | passkey enrolment step |
//! | `POST /api/flows/v1/login/{flow_id}/second-factor/passkey/{start,finish}` | passkey second factor |
//!
//! [`routes`] is merged into the tenant router next to `ui::routes()`, outside the UI
//! Fetch-Metadata layer and outside `public_cors()`. It brings its own router-local layers:
//! [`headless_origin_layer`] (the tenant's own origin or an exact entry of
//! `headless.allowed_origins`; JSON bodies only) inside [`headless_cors`] (credentialed CORS for
//! allow-listed origins only). The rate-limit class of `POST` below `/api/flows` is `Auth`
//! ([`crate::layers::ratelimit`]); its 429 is JSON. Unknown paths below [`BASE_PATH`] answer a
//! JSON 404 problem.

pub mod browser;
pub mod dto;
pub mod openapi;

use axum::Router;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::layers::cors::headless_cors;
use crate::layers::csrf::headless_origin_layer;
use crate::state::AppState;
use dto::{CaptchaDto, FlowProblem};

pub use openapi::openapi;

/// Path prefix of the headless flow API.
pub const BASE_PATH: &str = "/api/flows/v1";

/// The documented routes, shared by [`routes`] and [`openapi`].
fn api_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::with_openapi(openapi::base_document())
        .routes(routes!(browser::start_flow))
        .routes(routes!(browser::get_flow, browser::submit_flow))
        .routes(routes!(browser::passkey_options))
        .routes(routes!(browser::passkey_assertion))
        .routes(routes!(browser::enrolment_passkey_start))
        .routes(routes!(browser::enrolment_passkey_finish))
        .routes(routes!(browser::second_factor_passkey_start))
        .routes(routes!(browser::second_factor_passkey_finish))
}

/// The headless flow routes with their router-local origin, content-type and CORS layers.
pub fn routes() -> Router<AppState> {
    let (router, _) = api_router().split_for_parts();
    router
        // Unknown paths answer a JSON 404. A catch-all cannot sit beside `{kind}` (matchit), so
        // it covers everything deeper than a flow; an unknown `{kind}` is refused by the handlers.
        .route(BASE_PATH, any(unknown_route))
        .route(
            &format!("{BASE_PATH}/{{kind}}/{{flow_id}}/{{*rest}}"),
            any(unknown_route),
        )
        // Inner: origin allow-list and JSON-only bodies.
        .layer(headless_origin_layer())
        // Outer: answers preflights and adds credentialed CORS headers for listed origins only.
        .layer(headless_cors())
}

/// Unknown paths below the API prefix answer with a problem, not the HTML 404 page.
async fn unknown_route() -> Response {
    problem(StatusCode::NOT_FOUND, "not_found")
}

/// An RFC 9457 problem (`application/problem+json`, `no-store`) with the stable `code`.
pub(crate) fn problem(status: StatusCode, code: &str) -> Response {
    problem_with(status, code, None, None)
}

/// [`problem`] with the optional `retry_after` (also `Retry-After`) and CAPTCHA members.
pub(crate) fn problem_with(
    status: StatusCode,
    code: &str,
    retry_after: Option<u64>,
    captcha: Option<CaptchaDto>,
) -> Response {
    let body = FlowProblem {
        kind: format!("urn:anvilid:problem:flows:{code}"),
        title: status.canonical_reason().unwrap_or("Error").to_owned(),
        status: status.as_u16(),
        code: code.to_owned(),
        retry_after,
        captcha,
    };
    let json = serde_json::to_string(&body).unwrap_or_default();
    let mut resp = (status, json).into_response();
    let headers = resp.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Some(secs) = retry_after {
        headers.insert(header::RETRY_AFTER, HeaderValue::from(secs));
    }
    resp
}
