//! OpenID Provider metadata (`/.well-known/openid-configuration`).

use axum::body::Bytes;
use axum::extract::State;
use axum::http::header;
use axum::response::IntoResponse;
use serde::Serialize;

/// OpenID Provider Metadata (OpenID Connect Discovery 1.0, section 3).
///
/// Only values the M1 design targets are advertised. In M0 the authorization, token and JWKS endpoints are
/// advertised but answer `501 Not Implemented` with an explicit JSON error until M1 implements them.
#[derive(Debug, Serialize)]
struct ProviderMetadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    response_types_supported: [&'static str; 1],
    subject_types_supported: [&'static str; 1],
    id_token_signing_alg_values_supported: [&'static str; 1],
    code_challenge_methods_supported: [&'static str; 1],
    grant_types_supported: [&'static str; 1],
    token_endpoint_auth_methods_supported: [&'static str; 1],
    scopes_supported: [&'static str; 1],
}

impl ProviderMetadata {
    fn from_issuer(issuer: &url::Url) -> Self {
        // `Url` normalises an empty path to "/"; the issuer identifier carries no trailing slash.
        let base = issuer.as_str().trim_end_matches('/').to_owned();
        let endpoint = |path: &str| format!("{base}/{path}");
        Self {
            authorization_endpoint: endpoint("authorize"),
            token_endpoint: endpoint("token"),
            jwks_uri: endpoint("jwks"),
            issuer: base.clone(),
            response_types_supported: ["code"],
            subject_types_supported: ["public"],
            id_token_signing_alg_values_supported: ["ES256"],
            code_challenge_methods_supported: ["S256"],
            grant_types_supported: ["authorization_code"],
            token_endpoint_auth_methods_supported: ["client_secret_basic"],
            scopes_supported: ["openid"],
        }
    }
}

/// Pre-serialised discovery document, built once from the issuer.
#[derive(Debug, Clone)]
pub(crate) struct Discovery(Bytes);

impl Discovery {
    pub(crate) fn new(issuer: &url::Url) -> Self {
        let json = serde_json::to_vec(&ProviderMetadata::from_issuer(issuer))
            .expect("provider metadata contains only strings and is always serialisable");
        Self(json.into())
    }
}

pub(crate) async fn handler(State(doc): State<Discovery>) -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "application/json")], doc.0)
}
