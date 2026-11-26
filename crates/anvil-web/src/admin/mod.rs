//! Management API (`/api/admin/v1`): tenants (with signing algorithms and CAPTCHA), clients,
//! users and their credentials, sessions, the audit log, and email templates/SMTP, authenticated
//! with AnvilID's own OAuth access tokens (system tenant, admin scopes). Errors are RFC 9457
//! problem JSON.
//!
//! The OpenAPI 3.1 document is generated from the handlers ([`openapi`]), served without
//! authentication at `/api/admin/v1/openapi.json` and committed as `docs/openapi/admin-v1.json`
//! (drift test: `tests/openapi_drift.rs`, refresh with `just openapi-update`).

mod audit;
mod auth;
pub(crate) mod branding;
mod clients;
mod connections;
pub mod dto;
mod email;
mod sessions;
mod tenants;
mod users;

// Phase 5 (pre-declared by plan 05-02; the owning plans add their routes)
mod attributes;
mod config;
mod registration;
mod roles;
mod webhooks;

// Phase 6 (pre-declared by plan 06-04; the owning plans add their routes)
mod keys;
mod organizations;

// Phase 7 (pre-declared by plan 07-04; plan 07-17 adds the routes)
mod password_profiles;
mod user_export;
mod user_import;

use anvil_core::error::CoreError;
use anvil_core::service::admin_scope::ALL_ADMIN_SCOPES;
use axum::Router;
use axum::body::Bytes;
use axum::http::request::Parts;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use utoipa::openapi::security::{ClientCredentials, Flow, OAuth2, Scopes, SecurityScheme};
use utoipa::openapi::tag::TagBuilder;
use utoipa::openapi::{Components, InfoBuilder, OpenApi, OpenApiBuilder, OpenApiVersion};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::state::AppState;

/// Path prefix of the management API.
pub const BASE_PATH: &str = "/api/admin/v1";

/// Path of the served OpenAPI document.
pub const OPENAPI_PATH: &str = "/api/admin/v1/openapi.json";

/// Name of the OAuth 2.0 security scheme every operation references.
const SECURITY_SCHEME: &str = "oauth2";

/// Token endpoint of the system tenant, relative so the document does not depend on the
/// deployment's public URL.
const TOKEN_URL: &str = "/t/system/token";

/// Human description of an admin scope for the security scheme.
fn scope_description(scope: &str) -> String {
    match scope {
        "admin:read" => "Read everything: tenants and their settings, clients, users and their \
                         credentials, sessions, the audit log, email templates and SMTP settings"
            .to_owned(),
        "admin:write" => "Full administration: read and write everything (tenants and their \
                          settings, clients, users and their credentials, sessions, email \
                          templates, SMTP settings and test sends)"
            .to_owned(),
        other => {
            let mut parts = other.split(':').skip(1);
            let resource = parts.next().unwrap_or_default();
            match parts.next() {
                Some("write") => format!("Read and write {resource}"),
                _ => format!("Read {resource}"),
            }
        }
    }
}

/// The document skeleton: info, tags and the OAuth 2.0 client-credentials security scheme
/// listing every admin scope.
fn base_document() -> OpenApi {
    let scopes: Scopes = ALL_ADMIN_SCOPES
        .iter()
        .map(|s| ((*s).to_owned(), scope_description(s)))
        .collect();
    let mut components = Components::new();
    components.add_security_scheme(
        SECURITY_SCHEME,
        SecurityScheme::OAuth2(OAuth2::with_description(
            [Flow::ClientCredentials(ClientCredentials::new(
                TOKEN_URL, scopes,
            ))],
            "Access tokens of the system tenant (client_credentials grant of a system-tenant \
             client). Each operation lists the admin scopes that grant it.",
        )),
    );
    let tag = |name: &str, description: &str| {
        TagBuilder::new()
            .name(name)
            .description(Some(description))
            .build()
    };
    OpenApiBuilder::new()
        .openapi(OpenApiVersion::Version31)
        .info(
            InfoBuilder::new()
                .title("AnvilID Management API")
                .version("v1")
                .description(Some(
                    "Installation-level management of tenants, OAuth clients, users, sessions, \
                     the audit log and tenant email settings. Requests carry a Bearer access \
                     token issued by the system tenant. Lists use cursor pagination (`after`, `limit`); errors are RFC 9457 problem details.",
                ))
                .build(),
        )
        .components(Some(components))
        .tags(Some([
            tag("tenants", "Tenants (issuers) of the installation"),
            tag("clients", "OAuth clients of a tenant"),
            tag("users", "Users of a tenant and their credentials"),
            tag("sessions", "Browser sessions of a tenant's users"),
            tag("audit", "Audit log of a tenant"),
            tag("email", "Email templates and SMTP settings of a tenant"),
            tag(
                "connections",
                "Upstream identity providers (social, OIDC, OAuth2) of a tenant",
            ),
            tag(
                "branding",
                "Theme tokens, custom CSS, logo and live preview of a tenant or client",
            ),
            tag("roles", "Roles, permissions and role assignments of a tenant"),
            tag(
                "attributes",
                "Custom user attribute definitions and claim mapping of a tenant",
            ),
            tag(
                "webhooks",
                "Webhook endpoints and the delivery log of a tenant",
            ),
            tag(
                "registration",
                "Dynamic client registration, Client ID Metadata Document policy and initial \
                 access tokens of a tenant",
            ),
            tag(
                "config",
                "Declarative tenant configuration: export, plan and apply",
            ),
            tag(
                "organizations",
                "Organizations of a tenant: members, roles, invitations, domains, enterprise \
                 connections",
            ),
            tag("keys", "Signing keys of a tenant"),
        ]))
        .build()
}

/// The documented routes, shared by [`routes`] and [`openapi`].
fn api_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::with_openapi(base_document())
        .routes(routes!(tenants::list_tenants, tenants::create_tenant))
        .routes(routes!(
            tenants::get_tenant,
            tenants::update_tenant,
            tenants::delete_tenant
        ))
        .routes(routes!(clients::list_clients, clients::create_client))
        .routes(routes!(
            clients::get_client,
            clients::update_client,
            clients::delete_client
        ))
        .routes(routes!(clients::rotate_client_secret))
        .routes(routes!(users::list_users, users::create_user))
        .routes(routes!(
            users::get_user,
            users::update_user,
            users::delete_user
        ))
        .routes(routes!(users::list_user_credentials))
        .routes(routes!(organizations::list_user_organizations))
        .routes(routes!(users::delete_user_credential))
        .routes(routes!(sessions::list_sessions))
        .routes(routes!(sessions::revoke_session))
        .routes(routes!(
            sessions::list_user_sessions,
            sessions::revoke_user_sessions
        ))
        .routes(routes!(audit::list_audit_events))
        .routes(routes!(email::list_email_templates))
        .routes(routes!(
            email::get_email_template,
            email::put_email_template,
            email::reset_email_template
        ))
        .routes(routes!(
            email::get_smtp,
            email::put_smtp,
            email::delete_smtp
        ))
        .routes(routes!(email::test_smtp))
        .routes(routes!(
            connections::list_connections,
            connections::create_connection
        ))
        .routes(routes!(
            connections::get_connection,
            connections::update_connection,
            connections::delete_connection
        ))
        .routes(routes!(connections::put_connection_secret))
        .routes(routes!(
            branding::get_tenant_branding,
            branding::put_tenant_branding,
            branding::delete_tenant_branding
        ))
        .routes(routes!(
            branding::put_tenant_branding_logo,
            branding::delete_tenant_branding_logo
        ))
        .routes(routes!(branding::preview_tenant_branding))
        .routes(routes!(branding::publish_tenant_branding))
        .routes(routes!(
            branding::get_client_branding,
            branding::put_client_branding,
            branding::delete_client_branding
        ))
        .routes(routes!(
            branding::put_client_branding_logo,
            branding::delete_client_branding_logo
        ))
        .routes(routes!(branding::preview_client_branding))
        .routes(routes!(branding::publish_client_branding))
        .merge(roles::routes())
        .merge(attributes::routes())
        .merge(webhooks::routes())
        .merge(registration::routes())
        .merge(config::routes())
        .merge(organizations::routes())
        .merge(keys::routes())
        .merge(user_import::routes())
        .merge(user_export::routes())
        .merge(password_profiles::routes())
}

/// Management API routes, including the served OpenAPI document.
pub fn routes() -> Router<AppState> {
    let (router, api) = api_router().split_for_parts();
    // Serialised once per router; serialising a utoipa document cannot fail (string keys only),
    // and the drift test pins its content.
    let spec = Bytes::from(api.to_pretty_json().unwrap_or_default());
    router
        .route(
            OPENAPI_PATH,
            get(move |parts: Parts| serve_spec(parts, spec.clone())),
        )
        .route(&format!("{BASE_PATH}/{{*rest}}"), any(unknown_route))
}

/// The OpenAPI document of the management API.
pub fn openapi() -> OpenApi {
    api_router().split_for_parts().1
}

/// `GET /api/admin/v1/openapi.json`: public documentation, no authentication, no secrets.
async fn serve_spec(parts: Parts, spec: Bytes) -> Response {
    if let Err(e) = auth::installation_level(&parts) {
        return e.into_response();
    }
    let mut resp = (StatusCode::OK, spec).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    resp
}

/// Unknown paths below the API prefix answer with a problem, not the HTML 404 page.
async fn unknown_route(parts: Parts) -> Response {
    if let Err(e) = auth::installation_level(&parts) {
        return e.into_response();
    }
    auth::AdminError::Core(CoreError::NotFound).into_response()
}
