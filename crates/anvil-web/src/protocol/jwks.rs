//! JWK Set endpoint (`GET {issuer}/jwks`): the tenant's published public keys (next, active and
//! not-yet-expired retired keys) through [`KeyService::jwks`]. Public keys only: the set is
//! assembled by anvil-jose, which rejects private members.

use anvil_core::service::key::KeyService;
use axum::Router;
use axum::extract::State;
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;

use crate::errors::oauth_json;
use crate::layers::cors::public_cors;
use crate::state::AppState;
use crate::tenant::ResolvedTenant;

impl AppState {
    /// Key service over this state's storage, KEK and clock.
    pub(crate) fn jwks_key_service(&self) -> KeyService {
        KeyService {
            storage: self.storage_arc(),
            kek: self.kek_arc(),
            clock: self.clock_arc(),
        }
    }
}

async fn jwks(State(state): State<AppState>, tenant: ResolvedTenant) -> Response {
    match state.jwks_key_service().jwks(tenant.tenant.id).await {
        Ok(set) => {
            let mut resp = axum::Json(set).into_response();
            resp.headers_mut().insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=300"),
            );
            resp
        }
        Err(e) => oauth_json(&e),
    }
}

pub(super) fn routes() -> Router<AppState> {
    Router::new().route("/jwks", get(jwks)).layer(public_cors())
}
