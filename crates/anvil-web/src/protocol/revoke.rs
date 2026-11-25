//! Token revocation endpoint (RFC 7009): `POST /revoke`.
//!
//! Same request conventions and client authentication as `/introspect`
//! ([`client_form_request`](super::introspect::client_form_request)); public clients may revoke
//! their own tokens with `client_id`. Success is `200` with an empty body whether or not a token
//! was revoked (RFC 7009 §2.2). Every revocation rule lives in [`RevocationService`].

use anvil_core::service::revoke::RevocationService;
use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;

use crate::errors::oauth_json;
use crate::protocol::introspect::authenticated;
use crate::protocol::token::no_store;
use crate::request_context::AuditContext;
use crate::state::AppState;
use crate::tenant::ResolvedTenant;

impl AppState {
    /// The revocation service on this state's ports.
    pub(crate) fn revocation_service(&self) -> RevocationService {
        RevocationService {
            storage: self.storage_arc(),
            clock: self.clock_arc(),
        }
    }
}

/// The routes of this module (tenant-relative paths). POST only; other methods are 405.
pub fn routes() -> Router<AppState> {
    Router::new().route("/revoke", post(revoke))
}

async fn revoke(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    AuditContext(ctx): AuditContext,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let result = async {
        let (req, caller) =
            authenticated(&state, &tenant.tenant, &tenant.issuer, &headers, &body).await?;
        let token = req.token()?;
        state
            .revocation_service()
            .revoke(
                &tenant.tenant,
                &tenant.issuer,
                &caller,
                token,
                req.hint(),
                &ctx,
            )
            .await
    }
    .await;
    match result {
        Ok(()) => no_store(StatusCode::OK.into_response()),
        Err(e) => oauth_json(&e),
    }
}
