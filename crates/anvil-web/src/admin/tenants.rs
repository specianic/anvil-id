//! `/api/admin/v1/tenants`: installation-wide tenant management.
//!
//! Tenant settings carry `claims`, the mapping of a user's roles and permissions (tenant-wide
//! and in the active organization) into tokens ([`TokenClaimMapping`]). A rule names the claim, the tokens it goes into and the scope that
//! gates it; names that collide with protocol or standard claims are refused (422) by
//! `TenantService`.
//!
//! The tenant view carries the server-computed canonical `issuer` and its `discovery_url`.
//! Settings carry `dcr` (dynamic client registration policy, allowed redirect hosts, scopes,
//! resources, `client_credentials`, `max_clients`) and `cimd` (Client ID Metadata Document
//! policy, allowed hosts, cache bounds); the system tenant keeps both `disabled` (a PATCH asking
//! otherwise is a 422), and both are validated by `TenantService`. `features.saml` tells whether
//! the operator enabled SAML organization connections (`saml_experimental`).

use anvil_core::model::{
    ClaimMappingSettings, ClaimRule as CoreClaimRule, TokenTarget as CoreTokenTarget,
};
use anvil_core::service::admin_scope::{Access, Resource};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::auth::{
    AdminAuth, AdminJson, AdminQuery, AdminResult, created, json, no_content, page_request,
};
use super::dto::{CreateTenant, ListQuery, Problem, TenantList, TenantView, UpdateTenant};
use crate::request_context::AuditContext;
use crate::state::AppState;

/// List tenants.
#[utoipa::path(
    get,
    path = "/api/admin/v1/tenants",
    tag = "tenants",
    operation_id = "listTenants",
    params(ListQuery),
    responses(
        (status = 200, description = "One page of tenants", body = TenantList),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Invalid query", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:tenants:read"]),
        ("oauth2" = ["admin:tenants:write"]),
        ("oauth2" = ["admin:read"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn list_tenants(
    auth: AdminAuth,
    State(state): State<AppState>,
    AdminQuery(q): AdminQuery<ListQuery>,
) -> AdminResult<Response> {
    auth.require(Resource::Tenants, Access::Read)?;
    let page = state.admin_tenants().list(page_request(q)?).await?;
    Ok(json(
        StatusCode::OK,
        &TenantList::new(
            page,
            |t| state.admin_issuer_of(t),
            state.config().saml_experimental,
        ),
    ))
}

/// Create a tenant (with its first signing key).
#[utoipa::path(
    post,
    path = "/api/admin/v1/tenants",
    tag = "tenants",
    operation_id = "createTenant",
    request_body = CreateTenant,
    responses(
        (status = 201, description = "Created", body = TenantView, headers(("Location" = String, description = "URL of the new tenant"))),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "Slug or host already in use", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:tenants:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn create_tenant(
    auth: AdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    AdminJson(body): AdminJson<CreateTenant>,
) -> AdminResult<Response> {
    auth.require(Resource::Tenants, Access::Write)?;
    let tenant = state
        .admin_tenants()
        .create(
            body.into_input(state.config().installation_smtp, state.config().dev_mode()),
            auth.actor(),
            &ctx,
        )
        .await?;
    let location = format!("/api/admin/v1/tenants/{}", tenant.slug);
    let issuer = state.admin_issuer_of(&tenant);
    Ok(created(
        &location,
        &TenantView::new(tenant, issuer, state.config().saml_experimental),
    ))
}

/// Get a tenant.
#[utoipa::path(
    get,
    path = "/api/admin/v1/tenants/{slug}",
    tag = "tenants",
    operation_id = "getTenant",
    params(("slug" = String, Path, description = "Tenant slug")),
    responses(
        (status = 200, description = "The tenant", body = TenantView),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:tenants:read"]),
        ("oauth2" = ["admin:tenants:write"]),
        ("oauth2" = ["admin:read"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn get_tenant(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> AdminResult<Response> {
    auth.require(Resource::Tenants, Access::Read)?;
    let tenant = state.admin_tenants().get(&slug).await?;
    let issuer = state.admin_issuer_of(&tenant);
    Ok(json(
        StatusCode::OK,
        &TenantView::new(tenant, issuer, state.config().saml_experimental),
    ))
}

/// Update a tenant (the slug is immutable). Settings are merged with the current ones; the
/// CAPTCHA secret is write-only. Turning on `email_otp` or `magic_link` needs SMTP (the tenant's
/// SMTP settings or the installation SMTP). Enabling a signing algorithm creates its key at once; disabling
/// one that a client still uses for its ID tokens is refused (409, the problem lists the
/// clients). `dcr` and `cimd` are merged field by field; the system tenant refuses any policy
/// but `disabled` (422).
#[utoipa::path(
    patch,
    path = "/api/admin/v1/tenants/{slug}",
    tag = "tenants",
    operation_id = "updateTenant",
    params(("slug" = String, Path, description = "Tenant slug")),
    request_body = UpdateTenant,
    responses(
        (status = 200, description = "The updated tenant", body = TenantView),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "Host already in use, or a disabled signing algorithm is still used by clients", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:tenants:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn update_tenant(
    auth: AdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path(slug): Path<String>,
    AdminJson(body): AdminJson<UpdateTenant>,
) -> AdminResult<Response> {
    auth.require(Resource::Tenants, Access::Write)?;
    let tenants = state.admin_tenants();
    let current = tenants.get(&slug).await?;
    let (patch, captcha) = body.into_patch(
        &current.settings,
        state.config().installation_smtp,
        state.config().dev_mode(),
    );
    let tenant = tenants
        .update(&slug, patch, captcha, auth.actor(), &ctx)
        .await?;
    let issuer = state.admin_issuer_of(&tenant);
    Ok(json(
        StatusCode::OK,
        &TenantView::new(tenant, issuer, state.config().saml_experimental),
    ))
}

/// Delete a tenant with all its data. `system` and `default` cannot be deleted (403).
#[utoipa::path(
    delete,
    path = "/api/admin/v1/tenants/{slug}",
    tag = "tenants",
    operation_id = "deleteTenant",
    params(("slug" = String, Path, description = "Tenant slug")),
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope, or a protected tenant", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:tenants:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn delete_tenant(
    auth: AdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path(slug): Path<String>,
) -> AdminResult<Response> {
    auth.require(Resource::Tenants, Access::Write)?;
    state
        .admin_tenants()
        .delete(&slug, auth.actor(), &ctx)
        .await?;
    Ok(no_content())
}

// ---------------------------------------------------------------------------------------------
// Claim mapping DTOs (part of the tenant settings)
// ---------------------------------------------------------------------------------------------

/// Where a mapped claim is emitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TokenTarget {
    AccessToken,
    IdToken,
    Userinfo,
}

impl From<TokenTarget> for CoreTokenTarget {
    fn from(t: TokenTarget) -> Self {
        match t {
            TokenTarget::AccessToken => Self::AccessToken,
            TokenTarget::IdToken => Self::IdToken,
            TokenTarget::Userinfo => Self::Userinfo,
        }
    }
}

impl From<CoreTokenTarget> for TokenTarget {
    fn from(t: CoreTokenTarget) -> Self {
        match t {
            CoreTokenTarget::AccessToken => Self::AccessToken,
            CoreTokenTarget::IdToken => Self::IdToken,
            CoreTokenTarget::Userinfo => Self::Userinfo,
        }
    }
}

/// One claim mapping rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct TokenClaimRule {
    /// The claim name; protocol and standard claims (`sub`, `email`, ...) are refused.
    pub claim: String,
    /// The tokens the claim goes into.
    pub tokens: Vec<TokenTarget>,
    /// A single scope that must be granted for the claim to appear; `null` = always.
    #[serde(default)]
    pub scope: Option<String>,
}

impl From<TokenClaimRule> for CoreClaimRule {
    fn from(r: TokenClaimRule) -> Self {
        Self {
            claim: r.claim,
            tokens: r.tokens.into_iter().map(Into::into).collect(),
            scope: r.scope,
        }
    }
}

impl From<CoreClaimRule> for TokenClaimRule {
    fn from(r: CoreClaimRule) -> Self {
        Self {
            claim: r.claim,
            tokens: r.tokens.into_iter().map(Into::into).collect(),
            scope: r.scope,
        }
    }
}

/// How a user's roles and permissions are mapped into tokens. `null` disables a mapping.
/// Default: `roles` in every token gated by scope `roles`; `permissions` in the access token
/// only, not gated; `org_roles` / `org_permissions` (held in the active organization) likewise.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct TokenClaimMapping {
    pub roles: Option<TokenClaimRule>,
    pub permissions: Option<TokenClaimRule>,
    /// Roles held in the active organization. Absent on input = the default rule (claim
    /// `org_roles` in every token, gated by scope `roles`).
    #[serde(default = "default_org_roles")]
    pub org_roles: Option<TokenClaimRule>,
    /// Permissions held in the active organization. Absent on input = the default rule (claim
    /// `org_permissions` in the access token, not gated).
    #[serde(default = "default_org_permissions")]
    pub org_permissions: Option<TokenClaimRule>,
}

fn default_org_roles() -> Option<TokenClaimRule> {
    ClaimMappingSettings::default().org_roles.map(Into::into)
}

fn default_org_permissions() -> Option<TokenClaimRule> {
    ClaimMappingSettings::default()
        .org_permissions
        .map(Into::into)
}

impl Default for TokenClaimMapping {
    fn default() -> Self {
        ClaimMappingSettings::default().into()
    }
}

impl From<ClaimMappingSettings> for TokenClaimMapping {
    fn from(c: ClaimMappingSettings) -> Self {
        Self {
            roles: c.roles.map(Into::into),
            permissions: c.permissions.map(Into::into),
            org_roles: c.org_roles.map(Into::into),
            org_permissions: c.org_permissions.map(Into::into),
        }
    }
}

impl From<TokenClaimMapping> for ClaimMappingSettings {
    fn from(c: TokenClaimMapping) -> Self {
        Self {
            roles: c.roles.map(Into::into),
            permissions: c.permissions.map(Into::into),
            org_roles: c.org_roles.map(Into::into),
            org_permissions: c.org_permissions.map(Into::into),
        }
    }
}

/// Partial claim mapping update: an absent field keeps the current rule, `null` disables it.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct TokenClaimMappingPatch {
    #[serde(default, deserialize_with = "super::dto::double_option")]
    #[schema(value_type = Option<TokenClaimRule>)]
    pub roles: Option<Option<TokenClaimRule>>,
    #[serde(default, deserialize_with = "super::dto::double_option")]
    #[schema(value_type = Option<TokenClaimRule>)]
    pub permissions: Option<Option<TokenClaimRule>>,
    #[serde(default, deserialize_with = "super::dto::double_option")]
    #[schema(value_type = Option<TokenClaimRule>)]
    pub org_roles: Option<Option<TokenClaimRule>>,
    #[serde(default, deserialize_with = "super::dto::double_option")]
    #[schema(value_type = Option<TokenClaimRule>)]
    pub org_permissions: Option<Option<TokenClaimRule>>,
}

impl TokenClaimMappingPatch {
    /// The mapping after this patch.
    pub fn merge(self, current: &ClaimMappingSettings) -> ClaimMappingSettings {
        ClaimMappingSettings {
            roles: match self.roles {
                None => current.roles.clone(),
                Some(r) => r.map(Into::into),
            },
            permissions: match self.permissions {
                None => current.permissions.clone(),
                Some(p) => p.map(Into::into),
            },
            org_roles: match self.org_roles {
                None => current.org_roles.clone(),
                Some(r) => r.map(Into::into),
            },
            org_permissions: match self.org_permissions {
                None => current.org_permissions.clone(),
                Some(p) => p.map(Into::into),
            },
        }
    }
}
