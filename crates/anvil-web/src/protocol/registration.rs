//! RFC 7591 dynamic client registration and RFC 7592 client configuration endpoints (OIDC-17).
//!
//! - `POST /register`: registration. Under `allow_listed` it needs `Authorization: Bearer
//!   <initial access token>`; under `open` no token. `201` with the client information response.
//! - `GET`, `PUT`, `DELETE /register/{client_id}` (the `registration_client_uri`): read, replace
//!   and delete with `Authorization: Bearer <registration access token>`. `DELETE` answers `204`.
//!
//! The tenant's settings are read per request: while the effective policy is `disabled` (always
//! for the system tenant) every one of these paths answers the 404 page of a route that does not
//! exist, before the body or any token is looked at. Request bodies must be
//! `Content-Type: application/json` (a cross-site HTML form cannot send it without a CORS
//! preflight) and are bounded by the global body limit (413). Metadata errors are RFC 7591 JSON
//! (`400 {error, error_description}`); token errors are RFC 6750 `401` with
//! `WWW-Authenticate: Bearer error="invalid_token"` (a wrong token and an unknown client look the
//! same). Every rule lives in [`RegistrationService`]; the rate-limit class is `Auth`
//! ([`crate::layers::ratelimit`]).

use anvil_core::error::CoreError;
use anvil_core::model::DcrPolicy;
use anvil_core::oauth::redirect::validate_redirect_uri;
use anvil_core::service::registration::{
    RegistrationService, client_information, effective_settings,
};
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde_json::Value;

use crate::errors::{error_page_in, oauth_json};
use crate::i18n::locale_of;
use crate::protocol::token::no_store;
use crate::protocol::userinfo::bearer_from_header;
use crate::request_context::AuditContext;
use crate::state::AppState;
use crate::tenant::ResolvedTenant;

impl AppState {
    /// The dynamic client registration service on this state's ports.
    pub(crate) fn registration_service(&self) -> RegistrationService {
        RegistrationService {
            storage: self.storage_arc(),
            clock: self.clock_arc(),
            redirect_validator: validate_redirect_uri,
        }
    }
}

/// The routes of this module (tenant-relative paths), merged by the parent module.
pub(super) fn routes() -> Router<AppState> {
    Router::new().route("/register", post(register)).route(
        "/register/{client_id}",
        get(read).put(update).delete(delete),
    )
}

/// The 404 of a route that does not exist (the fallback's page), for a disabled policy.
fn not_found(state: &AppState, tenant: &ResolvedTenant, headers: &HeaderMap) -> Response {
    let locale = locale_of(state, Some(tenant), headers, None);
    error_page_in(
        state,
        Some(tenant),
        &locale,
        StatusCode::NOT_FOUND,
        "not_found",
        "",
    )
}

fn disabled(tenant: &ResolvedTenant) -> bool {
    effective_settings(&tenant.tenant).policy == DcrPolicy::Disabled
}

/// The bearer token of the request, if an `Authorization` header is present. A malformed header
/// yields an empty token, which the service refuses wherever a token is required.
fn bearer(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?;
    Some(
        value
            .to_str()
            .ok()
            .and_then(|v| bearer_from_header(v).ok())
            .unwrap_or_default(),
    )
}

/// The JSON request body: `Content-Type: application/json` and a JSON value.
fn json_body(headers: &HeaderMap, body: &[u8]) -> Result<Value, CoreError> {
    let is_json = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|m| m.trim().eq_ignore_ascii_case("application/json"));
    if !is_json {
        return Err(CoreError::InvalidClientMetadata(
            "the request must be sent as application/json".to_owned(),
        ));
    }
    serde_json::from_slice(body).map_err(|_| {
        CoreError::InvalidClientMetadata("the request body is not valid JSON".to_owned())
    })
}

/// Maps a service result to the response; `NotFound` (the policy was switched off) is the
/// route-level 404.
fn respond(
    state: &AppState,
    tenant: &ResolvedTenant,
    headers: &HeaderMap,
    result: Result<Response, CoreError>,
) -> Response {
    match result {
        Ok(resp) => no_store(resp),
        Err(CoreError::NotFound) => not_found(state, tenant, headers),
        Err(e) => oauth_json(&e),
    }
}

async fn register(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    AuditContext(ctx): AuditContext,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if disabled(&tenant) {
        return not_found(&state, &tenant, &headers);
    }
    let result = async {
        let iat = bearer(&headers);
        let request = json_body(&headers, &body)?;
        let registration = state
            .registration_service()
            .register(&tenant.tenant, &request, iat.as_deref(), &ctx)
            .await?;
        Ok((
            StatusCode::CREATED,
            axum::Json(Value::Object(registration.response(&tenant.issuer))),
        )
            .into_response())
    }
    .await;
    respond(&state, &tenant, &headers, result)
}

async fn read(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    Path(client_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if disabled(&tenant) {
        return not_found(&state, &tenant, &headers);
    }
    let result = async {
        let rat = bearer(&headers);
        let client = state
            .registration_service()
            .read(&tenant.tenant, &client_id, rat.as_deref())
            .await?;
        let info = client_information(&client, &tenant.issuer, None, None);
        Ok(axum::Json(Value::Object(info)).into_response())
    }
    .await;
    respond(&state, &tenant, &headers, result)
}

async fn update(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    AuditContext(ctx): AuditContext,
    Path(client_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if disabled(&tenant) {
        return not_found(&state, &tenant, &headers);
    }
    let result = async {
        let rat = bearer(&headers);
        let service = state.registration_service();
        // Authenticate before looking at the body: a caller without the token learns only 401.
        service
            .read(&tenant.tenant, &client_id, rat.as_deref())
            .await?;
        let request = json_body(&headers, &body)?;
        let client = service
            .update(&tenant.tenant, &client_id, rat.as_deref(), &request, &ctx)
            .await?;
        let info = client_information(&client, &tenant.issuer, None, None);
        Ok(axum::Json(Value::Object(info)).into_response())
    }
    .await;
    respond(&state, &tenant, &headers, result)
}

async fn delete(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    AuditContext(ctx): AuditContext,
    Path(client_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if disabled(&tenant) {
        return not_found(&state, &tenant, &headers);
    }
    let result = async {
        let rat = bearer(&headers);
        state
            .registration_service()
            .delete(&tenant.tenant, &client_id, rat.as_deref(), &ctx)
            .await?;
        Ok(StatusCode::NO_CONTENT.into_response())
    }
    .await;
    respond(&state, &tenant, &headers, result)
}
