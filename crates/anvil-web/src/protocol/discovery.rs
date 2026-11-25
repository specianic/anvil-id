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
//!
//! - `response_modes_supported` is [`response_mode::SUPPORTED`] (`query`, `form_post`).
//! - `id_token_signing_alg_values_supported` is the tenant's enabled algorithms
//!   ([`enabled_algs`]; RS256 is always enabled).
//! - Introspection (RFC 7662) refuses public clients, so its auth methods omit `none`; revocation
//!   (RFC 7009) accepts every token-endpoint method, including `none` for public clients.

use anvil_core::model::{ACR_PWD, Tenant};
use anvil_core::oauth::response_mode;
use anvil_core::service::key_rotation::enabled_algs;
use axum::Router;
use axum::extract::State;
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};

use crate::errors::oauth_json;
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

/// Client authentication methods of the token and revocation endpoints.
const TOKEN_AUTH_METHODS: &[&str] = &[
    "client_secret_basic",
    "client_secret_post",
    "private_key_jwt",
    "none",
];

/// Client authentication methods of the introspection endpoint (no `none`: public clients are
/// refused).
const INTROSPECTION_AUTH_METHODS: &[&str] = &[
    "client_secret_basic",
    "client_secret_post",
    "private_key_jwt",
];

/// `private_key_jwt` assertion algorithms (RFC 8414 §2: required when `private_key_jwt` is
/// listed).
const AUTH_SIGNING_ALGS: &[&str] = &["RS256", "PS256", "ES256"];

/// Provider metadata. Field names are the registered metadata names.
#[derive(Debug, Serialize)]
struct ProviderMetadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
    jwks_uri: String,
    introspection_endpoint: String,
    revocation_endpoint: String,
    scopes_supported: &'static [&'static str],
    response_types_supported: &'static [&'static str],
    response_modes_supported: &'static [&'static str],
    grant_types_supported: &'static [&'static str],
    subject_types_supported: &'static [&'static str],
    id_token_signing_alg_values_supported: Vec<&'static str>,
    token_endpoint_auth_methods_supported: &'static [&'static str],
    token_endpoint_auth_signing_alg_values_supported: &'static [&'static str],
    introspection_endpoint_auth_methods_supported: &'static [&'static str],
    introspection_endpoint_auth_signing_alg_values_supported: &'static [&'static str],
    revocation_endpoint_auth_methods_supported: &'static [&'static str],
    revocation_endpoint_auth_signing_alg_values_supported: &'static [&'static str],
    code_challenge_methods_supported: &'static [&'static str],
    authorization_response_iss_parameter_supported: bool,
    prompt_values_supported: &'static [&'static str],
    acr_values_supported: [&'static str; 1],
    claims_parameter_supported: bool,
    request_parameter_supported: bool,
    request_uri_parameter_supported: bool,
    claims_supported: &'static [&'static str],
    /// The locales of the page catalogs ([`crate::i18n::Catalogs::available`]).
    ui_locales_supported: Vec<String>,
}

impl ProviderMetadata {
    /// The document for `issuer`; `id_token_algs` are the tenant's enabled ID token algorithms.
    fn for_issuer(issuer: &str, id_token_algs: Vec<&'static str>, ui_locales: Vec<String>) -> Self {
        let endpoint = |path: &str| format!("{issuer}{path}");
        Self {
            authorization_endpoint: endpoint("/authorize"),
            token_endpoint: endpoint("/token"),
            userinfo_endpoint: endpoint("/userinfo"),
            jwks_uri: endpoint("/jwks"),
            introspection_endpoint: endpoint("/introspect"),
            revocation_endpoint: endpoint("/revoke"),
            issuer: issuer.to_owned(),
            scopes_supported: &["openid", "profile", "email", "address", "phone"],
            response_types_supported: &["code"],
            response_modes_supported: response_mode::SUPPORTED,
            grant_types_supported: &["authorization_code", "refresh_token", "client_credentials"],
            subject_types_supported: &["public"],
            id_token_signing_alg_values_supported: id_token_algs,
            token_endpoint_auth_methods_supported: TOKEN_AUTH_METHODS,
            token_endpoint_auth_signing_alg_values_supported: AUTH_SIGNING_ALGS,
            introspection_endpoint_auth_methods_supported: INTROSPECTION_AUTH_METHODS,
            introspection_endpoint_auth_signing_alg_values_supported: AUTH_SIGNING_ALGS,
            revocation_endpoint_auth_methods_supported: TOKEN_AUTH_METHODS,
            revocation_endpoint_auth_signing_alg_values_supported: AUTH_SIGNING_ALGS,
            code_challenge_methods_supported: &["S256"],
            authorization_response_iss_parameter_supported: true,
            prompt_values_supported: &["none", "login"],
            acr_values_supported: [ACR_PWD],
            claims_parameter_supported: true,
            request_parameter_supported: false,
            request_uri_parameter_supported: false,
            claims_supported: CLAIMS_SUPPORTED,
            ui_locales_supported: ui_locales,
        }
    }
}

/// The tenant's enabled ID token signing algorithms, in settings order.
fn id_token_algs(tenant: &Tenant) -> Result<Vec<&'static str>, anvil_core::error::CoreError> {
    Ok(enabled_algs(tenant)?
        .into_iter()
        .map(|a| a.as_str())
        .collect())
}

async fn metadata(State(state): State<AppState>, tenant: ResolvedTenant) -> Response {
    let algs = match id_token_algs(&tenant.tenant) {
        Ok(a) => a,
        Err(e) => return oauth_json(&e),
    };
    let mut resp = axum::Json(ProviderMetadata::for_issuer(
        &tenant.issuer,
        algs,
        state.renderer().catalogs().available(),
    ))
    .into_response();
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
        let m = ProviderMetadata::for_issuer(
            "https://op.test/t/acme",
            vec!["RS256"],
            vec!["en".into()],
        );
        assert_eq!(m.issuer, "https://op.test/t/acme");
        assert_eq!(m.authorization_endpoint, "https://op.test/t/acme/authorize");
        assert_eq!(m.token_endpoint, "https://op.test/t/acme/token");
        assert_eq!(m.userinfo_endpoint, "https://op.test/t/acme/userinfo");
        assert_eq!(m.jwks_uri, "https://op.test/t/acme/jwks");
        assert_eq!(
            m.introspection_endpoint,
            "https://op.test/t/acme/introspect"
        );
        assert_eq!(m.revocation_endpoint, "https://op.test/t/acme/revoke");
    }

    #[test]
    fn introspection_never_advertises_none() {
        assert!(!INTROSPECTION_AUTH_METHODS.contains(&"none"));
        assert!(TOKEN_AUTH_METHODS.contains(&"none"));
    }
}
