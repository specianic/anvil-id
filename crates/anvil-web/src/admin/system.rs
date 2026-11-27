//! Installation facts for console administrators.
//!
//! - `GET …/system/info` (any admin scope): the version of the running server binary, shown in
//!   the console footer. This is the only place the version is disclosed over HTTP: discovery,
//!   JWKS, health, metrics, pages, headers and error bodies never carry it.
//!
//! Any admin scope suffices (see [`AdminAuth::require_any_admin_scope`]): every console
//! administrator holds at least one, whatever their role, while application-tenant tokens (401,
//! wrong issuer), org admins and system-tenant tokens without admin scopes (403) are refused.

use anvil_core::error::CoreError;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use serde::Serialize;
use utoipa::ToSchema;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use super::auth::{AdminAuth, AdminResult, json};
use super::dto::Problem;
use crate::state::AppState;

/// The documented routes of this module, merged into the management API by `api_router`.
pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(get_system_info))
}

/// Facts about the running installation.
#[derive(Debug, Serialize, ToSchema)]
pub struct SystemInfo {
    /// Version of the running `anvilid` binary (e.g. `1.0.0`).
    pub version: String,
}

/// Version of the running server, for console administrators.
#[utoipa::path(
    get,
    path = "/api/admin/v1/system/info",
    tag = "system",
    operation_id = "getSystemInfo",
    responses(
        (status = 200, description = "Facts about the running installation", body = SystemInfo),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "The token carries no admin scope", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:read"]),
        ("oauth2" = ["admin:write"]),
        ("oauth2" = ["admin:tenants:read"]),
        ("oauth2" = ["admin:tenants:write"]),
        ("oauth2" = ["admin:clients:read"]),
        ("oauth2" = ["admin:clients:write"]),
        ("oauth2" = ["admin:users:read"]),
        ("oauth2" = ["admin:users:write"]),
        ("oauth2" = ["admin:sessions:read"]),
        ("oauth2" = ["admin:sessions:write"]),
        ("oauth2" = ["admin:audit:read"]),
        ("oauth2" = ["admin:audit:write"]),
        ("oauth2" = ["admin:settings:read"]),
        ("oauth2" = ["admin:settings:write"]),
        ("oauth2" = ["admin:organizations:read"]),
        ("oauth2" = ["admin:organizations:write"]),
        ("oauth2" = ["admin:users:export"]),
    )
)]
pub(crate) async fn get_system_info(
    auth: AdminAuth,
    State(state): State<AppState>,
) -> AdminResult<Response> {
    auth.require_any_admin_scope()?;
    let version =
        state.config().server_version.clone().ok_or_else(|| {
            CoreError::Internal("the server version is not configured".to_owned())
        })?;
    Ok(json(StatusCode::OK, &SystemInfo { version }))
}

#[cfg(test)]
mod tests {
    use anvil_core::service::admin_scope::ALL_ADMIN_SCOPES;

    /// The documented alternatives are exactly the admin scopes (the handler accepts any).
    #[test]
    fn documented_security_lists_every_admin_scope() {
        let doc = super::super::openapi();
        let op = doc
            .paths
            .paths
            .get("/api/admin/v1/system/info")
            .and_then(|item| item.get.as_ref())
            .expect("getSystemInfo is documented");
        let mut documented: Vec<String> = op
            .security
            .as_ref()
            .expect("security")
            .iter()
            .flat_map(|req| {
                serde_json::to_value(req)
                    .ok()
                    .and_then(|v| v.get("oauth2").cloned())
                    .and_then(|v| serde_json::from_value::<Vec<String>>(v).ok())
                    .unwrap_or_default()
            })
            .collect();
        documented.sort();
        let mut expected: Vec<String> = ALL_ADMIN_SCOPES.iter().map(|s| (*s).to_owned()).collect();
        expected.sort();
        assert_eq!(documented, expected);
    }
}
