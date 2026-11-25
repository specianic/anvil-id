//! OpenID Provider metadata (OpenID Connect Discovery 1.0 §3) and OAuth 2.0 Authorization Server
//! metadata (RFC 8414), per tenant.
//!
//! The same document is served at `{issuer}/.well-known/openid-configuration` and at the RFC 8414
//! inserted path `/.well-known/oauth-authorization-server{base_path}` (the tenant layer rewrites
//! the latter to the tenant-relative `/.well-known/oauth-authorization-server`). It is built per
//! request from the resolved issuer; it is small and cheap, so it is not cached.
//!
//! Only capabilities that are implemented are advertised. `request_uri_parameter_supported`
//! defaults to `true` when omitted, so it is published explicitly as `false`.

use anvil_core::model::ACR_PWD;
use axum::Router;
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde::Serialize;

use crate::layers::cors::public_cors;
use crate::state::AppState;
use crate::tenant::ResolvedTenant;

/// Standard claims the provider can release (OIDC Core §2, §5.1).
const CLAIMS_SUPPORTED: &[&str] = &[
    "sub",
    "iss",
    "aud",
    "exp",
    "iat",
    "auth_time",
    "nonce",
    "acr",
    "amr",
    "azp",
    "sid",
    "name",
    "given_name",
    "family_name",
    "middle_name",
    "nickname",
    "preferred_username",
    "profile",
    "picture",
    "website",
    "gender",
    "birthdate",
    "zoneinfo",
    "locale",
    "updated_at",
    "email",
    "email_verified",
    "address",
    "phone_number",
    "phone_number_verified",
];

/// Provider metadata. Field names are the registered metadata names.
#[derive(Debug, Serialize)]
struct ProviderMetadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
    jwks_uri: String,
    scopes_supported: &'static [&'static str],
    response_types_supported: &'static [&'static str],
    response_modes_supported: &'static [&'static str],
    grant_types_supported: &'static [&'static str],
    subject_types_supported: &'static [&'static str],
    id_token_signing_alg_values_supported: &'static [&'static str],
    token_endpoint_auth_methods_supported: &'static [&'static str],
    token_endpoint_auth_signing_alg_values_supported: &'static [&'static str],
    code_challenge_methods_supported: &'static [&'static str],
    authorization_response_iss_parameter_supported: bool,
    prompt_values_supported: &'static [&'static str],
    acr_values_supported: [&'static str; 1],
    claims_parameter_supported: bool,
    request_parameter_supported: bool,
    request_uri_parameter_supported: bool,
    claims_supported: &'static [&'static str],
}

impl ProviderMetadata {
    fn for_issuer(issuer: &str) -> Self {
        let endpoint = |path: &str| format!("{issuer}{path}");
        Self {
            authorization_endpoint: endpoint("/authorize"),
            token_endpoint: endpoint("/token"),
            userinfo_endpoint: endpoint("/userinfo"),
            jwks_uri: endpoint("/jwks"),
            issuer: issuer.to_owned(),
            scopes_supported: &["openid", "profile", "email", "address", "phone"],
            response_types_supported: &["code"],
            response_modes_supported: &["query"],
            grant_types_supported: &["authorization_code", "refresh_token", "client_credentials"],
            subject_types_supported: &["public"],
            id_token_signing_alg_values_supported: &["RS256"],
            token_endpoint_auth_methods_supported: &[
                "client_secret_basic",
                "client_secret_post",
                "private_key_jwt",
                "none",
            ],
            token_endpoint_auth_signing_alg_values_supported: &["RS256", "PS256", "ES256"],
            code_challenge_methods_supported: &["S256"],
            authorization_response_iss_parameter_supported: true,
            prompt_values_supported: &["none", "login"],
            acr_values_supported: [ACR_PWD],
            claims_parameter_supported: true,
            request_parameter_supported: false,
            request_uri_parameter_supported: false,
            claims_supported: CLAIMS_SUPPORTED,
        }
    }
}

async fn metadata(tenant: ResolvedTenant) -> Response {
    let mut resp = axum::Json(ProviderMetadata::for_issuer(&tenant.issuer)).into_response();
    resp.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=300"),
    );
    resp
}

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route("/.well-known/openid-configuration", get(metadata))
        .route("/.well-known/oauth-authorization-server", get(metadata))
        .layer(public_cors())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_derive_from_the_issuer() {
        let m = ProviderMetadata::for_issuer("https://op.test/t/acme");
        assert_eq!(m.issuer, "https://op.test/t/acme");
        assert_eq!(m.authorization_endpoint, "https://op.test/t/acme/authorize");
        assert_eq!(m.token_endpoint, "https://op.test/t/acme/token");
        assert_eq!(m.userinfo_endpoint, "https://op.test/t/acme/userinfo");
        assert_eq!(m.jwks_uri, "https://op.test/t/acme/jwks");
    }
}
