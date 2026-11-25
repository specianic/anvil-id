//! JWK Set endpoint (`GET {issuer}/jwks`): the tenant's published public keys (next, active and
//! not-yet-expired retired keys) through [`KeyService::jwks`]. Public keys only: the set is
//! assembled by anvil-jose, which rejects private members.
//!
//! Caching: `Cache-Control: public, max-age=3600` ([`JWKS_MAX_AGE`]) and a strong `ETag` (quoted
//! hex SHA-256 of the body). Key rotation publishes a key for at least `prepublish ≥ JWKS_MAX_AGE`
//! before it signs, so a relying party that honours the max-age always knows the signing key.
//! `If-None-Match` with the current tag answers `304 Not Modified` without a body.

use anvil_core::service::key::KeyService;
use anvil_core::service::key_rotation::JWKS_MAX_AGE;
use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;

use crate::errors::oauth_json;
use crate::http_cache::{if_none_match, strong_etag};
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


async fn jwks(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    headers: HeaderMap,
) -> Response {
    let set = match state.jwks_key_service().jwks(tenant.tenant.id).await {
        Ok(set) => set,
        Err(e) => return oauth_json(&e),
    };
    let body = match serde_json::to_vec(&set) {
        Ok(b) => b,
        Err(_) => {
            return oauth_json(&anvil_core::error::CoreError::Internal(
                "JWKS serialisation failed".to_owned(),
            ));
        }
    };
    let etag = strong_etag(&body);
    let mut resp = if if_none_match(&headers, &etag) {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        (
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            )],
            body,
        )
            .into_response()
    };
    let h = resp.headers_mut();
    let cache = format!("public, max-age={}", JWKS_MAX_AGE.whole_seconds());
    if let Ok(v) = HeaderValue::from_str(&cache) {
        h.insert(header::CACHE_CONTROL, v);
    }
    if let Ok(v) = HeaderValue::from_str(&etag) {
        h.insert(header::ETAG, v);
    }
    resp
}

pub(super) fn routes() -> Router<AppState> {
    Router::new().route("/jwks", get(jwks)).layer(public_cors())
}
