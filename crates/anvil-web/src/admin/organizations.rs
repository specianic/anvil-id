//! Organization administration API (tag `organizations`, ORG-02/ORG-03): organizations, members,
//! org roles, in-org role assignments and invitations of a tenant. Owned by plan 06-12 (domains,
//! connections and branding sub-routes: 06-17, under the same principal rules).
//!
//! - `GET|POST …/tenants/{slug}/organizations`: list and create (tenant administrators only;
//!   never in the system tenant, 422);
//! - `GET|PATCH|DELETE …/organizations/{org}` (`org` = id or slug): GET also for the org's own
//!   admin; PATCH and DELETE for tenant administrators only;
//! - `GET|POST …/{org}/members`, `DELETE …/{org}/members/{user_id}`: adding a member directly is
//!   for tenant administrators only (org admins invite);
//! - `GET|POST …/{org}/roles`, `GET|PATCH|DELETE …/{org}/roles/{name}`: org-owned roles;
//! - `GET …/{org}/members/{user_id}/roles`, `PUT|DELETE …/{org}/members/{user_id}/roles/{role}`
//!   (`?scope=org|tenant`; without it the org-owned role wins, the tenant role is the fallback);
//! - `GET|POST …/{org}/invitations`, `DELETE …/{org}/invitations/{id}`;
//! - `GET|POST …/{org}/connections`, `GET|PATCH|DELETE …/{org}/connections/{id}`,
//!   `PUT …/{org}/connections/{id}/secret` (OIDC) and `POST …/{org}/connections/saml-metadata`
//!   (prefill from pasted or fetched IdP metadata; stores nothing): the org's enterprise
//!   connections, OIDC or SAML. SAML is experimental: without the operator flag
//!   `saml_experimental` creating, enabling or changing a SAML connection and the metadata import
//!   answer 403 `feature_disabled` (disabling and deleting still work);
//! - `GET|POST …/{org}/domains`, `GET|PATCH|DELETE …/{org}/domains/{id}`,
//!   `POST …/{org}/domains/{id}/verify`: domain claims with the DNS TXT record to publish, one
//!   uniform `pending` answer for every failed check, one verified org per domain (409), and the
//!   routing settings with their guards (see `OrgDomainService`);
//! - `…/{org}/branding` (`GET|PUT|DELETE`, `…/logo`, `…/preview`, `…/publish`): the org's theme,
//!   handled by `admin::branding` with the org scope.
//!
//! **Principals** ([`OrgAdminAuth`]): a system-tenant token needs `admin:organizations:read` for
//! reads and `admin:organizations:write` for writes (or `admin:read` / `admin:write`). On the
//! `{org}` sub-routes an org admin's token of tenant `{slug}` (scope `org:admin`, `org_id` =
//! `{org}`, audience `{public_url}/api/admin/v1`, decision Q1) is accepted too, for that org
//! only. Org admins' removals and demotions go through the lockout guard (409 when the org would
//! lose its last org admin); a tenant administrator may still make them (recovery path).

use anvil_core::error::CoreError;
use anvil_core::model::{
    Connection, ConnectionConfig as CoreConnectionConfig, ConnectionId, OrgDomain, OrgDomainId,
    OrgDomainStatus, OrgInvitation, OrgInvitationId, Organization, Role, RoleId, RoleUpdate,
    Tenant, UserId,
};
use anvil_core::policy::domain_verification;
use anvil_core::service::admin_scope::{Access, Resource};
use anvil_core::service::connection::{ConnectionOwner, ConnectionPatch, NewConnectionInput};
use anvil_core::service::org_domain::{DomainPatch, OrgDomainService, VerifyOutcome};
use anvil_core::service::org_invitation::InvitationInput;
use anvil_core::service::organization::{MemberInfo, OrgInput, OrgPatch, RoleScope};
use anvil_core::service::role::RoleInput;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use uuid::Uuid;

use super::auth::{
    AdminAuth, AdminJson, AdminQuery, AdminResult, OrgAdminAuth, Principal, created, json,
    no_content, page_request,
};
use super::dto::{
    ConnectionList, ConnectionView, CreateConnection, ListQuery, MfaPolicy, Problem,
    PutConnectionSecret, SamlMetadataImport, SamlMetadataView, UpdateConnection, double_option, ts,
};
use crate::adapters::outbound::LIMIT_DOCUMENT;
use crate::request_context::AuditContext;
use crate::state::AppState;

/// The documented routes of this module, merged into the management API by `api_router`.
pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_organizations, create_organization))
        .routes(routes!(
            get_organization,
            update_organization,
            delete_organization
        ))
        .routes(routes!(list_members, add_member))
        .routes(routes!(remove_member))
        .routes(routes!(list_member_roles))
        .routes(routes!(assign_member_role, unassign_member_role))
        .routes(routes!(list_org_roles, create_org_role))
        .routes(routes!(get_org_role, update_org_role, delete_org_role))
        .routes(routes!(list_invitations, create_invitation))
        .routes(routes!(revoke_invitation))
        .routes(routes!(list_org_connections, create_org_connection))
        .routes(routes!(import_saml_metadata))
        .routes(routes!(
            get_org_connection,
            update_org_connection,
            delete_org_connection
        ))
        .routes(routes!(put_org_connection_secret))
        .routes(routes!(list_org_domains, create_org_domain))
        .routes(routes!(
            get_org_domain,
            update_org_domain,
            delete_org_domain
        ))
        .routes(routes!(verify_org_domain))
        .routes(routes!(
            super::branding::get_org_branding,
            super::branding::put_org_branding,
            super::branding::delete_org_branding
        ))
        .routes(routes!(
            super::branding::put_org_branding_logo,
            super::branding::delete_org_branding_logo
        ))
        .routes(routes!(super::branding::preview_org_branding))
        .routes(routes!(super::branding::publish_org_branding))
}

// ---------------------------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------------------------

/// An organization: a business customer inside a tenant.
#[derive(Debug, Serialize, ToSchema)]
pub struct OrganizationView {
    pub id: Uuid,
    /// Unique in the tenant: 2-63 characters of a-z, 0-9 and '-'.
    pub slug: String,
    pub display_name: String,
    /// The org's MFA policy; `null` = no org requirement. The strictest of tenant, org and
    /// client wins.
    pub mfa_policy: Option<MfaPolicy>,
    /// Roles given (in this org) to members created by just-in-time provisioning.
    pub default_role_ids: Vec<Uuid>,
    /// Free-form JSON object for the integrator.
    #[schema(value_type = Object)]
    pub metadata: Value,
    #[schema(format = DateTime)]
    pub created_at: String,
    #[schema(format = DateTime)]
    pub updated_at: String,
}

impl From<Organization> for OrganizationView {
    fn from(o: Organization) -> Self {
        Self {
            id: o.id.0,
            slug: o.slug,
            display_name: o.display_name,
            mfa_policy: o.mfa_policy.map(Into::into),
            default_role_ids: o.settings.default_role_ids.iter().map(|r| r.0).collect(),
            metadata: o.metadata,
            created_at: ts(o.created_at),
            updated_at: ts(o.updated_at),
        }
    }
}

/// One page of organizations (id order).
#[derive(Debug, Serialize, ToSchema)]
pub struct OrganizationList {
    pub items: Vec<OrganizationView>,
    /// Present if and only if more items follow.
    pub next_cursor: Option<Uuid>,
}

/// Body of `POST /tenants/{slug}/organizations`.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NewOrganizationDto {
    /// 2-63 characters of a-z, 0-9 and '-', starting with a letter or digit.
    pub slug: String,
    /// 1-200 characters.
    pub display_name: String,
    /// Default `null` (no org requirement).
    #[serde(default)]
    pub mfa_policy: Option<MfaPolicy>,
    /// A JSON object; default `{}`.
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub metadata: Option<Value>,
}

/// Body of `PATCH …/organizations/{org}`. Absent fields stay unchanged.
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct OrganizationPatchDto {
    #[serde(default)]
    pub slug: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    /// `null` removes the org's MFA requirement.
    #[serde(default, deserialize_with = "double_option")]
    #[schema(value_type = Option<MfaPolicy>)]
    pub mfa_policy: Option<Option<MfaPolicy>>,
    /// Replaces the whole object.
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub metadata: Option<Value>,
    /// Replaces the default roles: ids of tenant roles or of roles owned by this org, none
    /// carrying an admin permission (at most 20).
    #[serde(default)]
    pub default_role_ids: Option<Vec<Uuid>>,
}

/// A member of an organization.
#[derive(Debug, Serialize, ToSchema)]
pub struct MemberView {
    pub user_id: Uuid,
    /// The user's email; `null` if the user no longer exists.
    pub email: Option<String>,
    #[schema(format = DateTime)]
    pub created_at: String,
}

impl From<MemberInfo> for MemberView {
    fn from(m: MemberInfo) -> Self {
        Self {
            user_id: m.membership.user_id.0,
            email: m.email,
            created_at: ts(m.membership.created_at),
        }
    }
}

/// One page of members (user id order).
#[derive(Debug, Serialize, ToSchema)]
pub struct MemberList {
    pub items: Vec<MemberView>,
    /// Present if and only if more items follow.
    pub next_cursor: Option<Uuid>,
}

/// Result of `POST …/{org}/members`.
#[derive(Debug, Serialize, ToSchema)]
pub struct MemberAdded {
    pub user_id: Uuid,
    /// `false` when the user already was a member (nothing changed, roles untouched).
    pub added: bool,
}

/// Body of `POST …/{org}/members`.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AddMemberDto {
    pub user_id: Uuid,
    /// Roles assigned in the org with the membership: ids of tenant roles or of roles owned by
    /// this org, none carrying an admin permission.
    #[serde(default)]
    pub role_ids: Vec<Uuid>,
}

/// Where a role is defined.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum OrgRoleScope {
    /// Owned by the organization.
    Org,
    /// A tenant role (assigned within the organization).
    Tenant,
}

impl From<OrgRoleScope> for RoleScope {
    fn from(s: OrgRoleScope) -> Self {
        match s {
            OrgRoleScope::Org => Self::Org,
            OrgRoleScope::Tenant => Self::Tenant,
        }
    }
}

/// A role as seen from an organization.
#[derive(Debug, Serialize, ToSchema)]
pub struct OrgRoleView {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    /// Sorted, de-duplicated permission strings (`org:admin` makes the holder an org admin).
    pub permissions: Vec<String>,
    pub scope: OrgRoleScope,
    #[schema(format = DateTime)]
    pub created_at: String,
    #[schema(format = DateTime)]
    pub updated_at: String,
}

impl From<Role> for OrgRoleView {
    fn from(r: Role) -> Self {
        Self {
            id: r.id.0,
            scope: if r.org_id.is_some() {
                OrgRoleScope::Org
            } else {
                OrgRoleScope::Tenant
            },
            name: r.name,
            description: r.description,
            permissions: r.permissions,
            created_at: ts(r.created_at),
            updated_at: ts(r.updated_at),
        }
    }
}

/// Roles, in name order.
#[derive(Debug, Serialize, ToSchema)]
pub struct OrgRoleList {
    pub items: Vec<OrgRoleView>,
}

impl From<Vec<Role>> for OrgRoleList {
    fn from(v: Vec<Role>) -> Self {
        Self {
            items: v.into_iter().map(Into::into).collect(),
        }
    }
}

/// Body of `POST …/{org}/roles`.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NewOrgRoleDto {
    /// Unique in the org: 1-64 characters of a-z, 0-9, '_', '.' or '-'.
    pub name: String,
    /// At most 500 characters.
    #[serde(default)]
    pub description: String,
    /// At most 100 permissions; admin permissions (`admin`, `admin:*`) are refused.
    #[serde(default)]
    pub permissions: Vec<String>,
}

/// Body of `PATCH …/{org}/roles/{name}`. `permissions` replaces the whole set.
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct OrgRolePatchDto {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub permissions: Option<Vec<String>>,
}

/// Which role a name refers to.
#[derive(Debug, Clone, Copy, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub struct RoleScopeQuery {
    /// `org` or `tenant`; absent = the org-owned role, else the tenant role of that name.
    pub scope: Option<OrgRoleScope>,
}

/// An in-org role assignment.
#[derive(Debug, Serialize, ToSchema)]
pub struct OrgAssignmentView {
    pub user_id: Uuid,
    pub role: OrgRoleView,
}

/// State of an invitation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum InvitationStatus {
    Open,
    Accepted,
    Revoked,
    Expired,
}

/// An invitation (never its token or token hash).
#[derive(Debug, Serialize, ToSchema)]
pub struct InvitationView {
    pub id: Uuid,
    /// The invited address (normalised to lowercase).
    pub email: String,
    /// Roles assigned in the org on acceptance.
    pub role_ids: Vec<Uuid>,
    pub status: InvitationStatus,
    #[schema(format = DateTime)]
    pub created_at: String,
    #[schema(format = DateTime)]
    pub expires_at: String,
    #[schema(format = DateTime)]
    pub accepted_at: Option<String>,
    pub accepted_user_id: Option<Uuid>,
    #[schema(format = DateTime)]
    pub revoked_at: Option<String>,
}

impl InvitationView {
    fn new(i: OrgInvitation, now: time::OffsetDateTime) -> Self {
        let status = if i.accepted_at.is_some() {
            InvitationStatus::Accepted
        } else if i.revoked_at.is_some() {
            InvitationStatus::Revoked
        } else if i.expires_at <= now {
            InvitationStatus::Expired
        } else {
            InvitationStatus::Open
        };
        Self {
            id: i.id.0,
            email: i.email,
            role_ids: i.role_ids.iter().map(|r| r.0).collect(),
            status,
            created_at: ts(i.created_at),
            expires_at: ts(i.expires_at),
            accepted_at: i.accepted_at.map(ts),
            accepted_user_id: i.accepted_user_id.map(|u| u.0),
            revoked_at: i.revoked_at.map(ts),
        }
    }
}

/// Invitations, newest first.
#[derive(Debug, Serialize, ToSchema)]
pub struct InvitationList {
    pub items: Vec<InvitationView>,
}

/// Body of `POST …/{org}/invitations`.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NewInvitationDto {
    pub email: String,
    /// Roles assigned in the org on acceptance: ids of tenant roles or of roles owned by this
    /// org, none carrying an admin permission (at most 20).
    #[serde(default)]
    pub role_ids: Vec<Uuid>,
}

/// Invitation list filter.
#[derive(Debug, Clone, Copy, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub struct InvitationQuery {
    /// Also list accepted and revoked invitations (default `false`: open and expired ones).
    pub include_closed: Option<bool>,
}

// ---------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------

/// The tenant of a tenant-level organization route (system administrators only).
async fn tenant_for(
    state: &AppState,
    auth: &AdminAuth,
    slug: &str,
    access: Access,
) -> AdminResult<Tenant> {
    auth.require(Resource::Organizations, access)?;
    Ok(state.admin_tenants().get(slug).await?)
}

/// The tenant and org of an `{org}` sub-route. A system administrator needs the organizations
/// scope for `access`; an org admin's tenant and org were resolved from this path and checked by
/// [`OrgAdminAuth`].
pub(super) async fn org_for(
    state: &AppState,
    auth: &AdminAuth,
    slug: &str,
    org: &str,
    access: Access,
) -> AdminResult<(Tenant, Organization)> {
    match &auth.principal {
        Principal::SystemAdmin => {
            let tenant = tenant_for(state, auth, slug, access).await?;
            let org = state.admin_orgs().get(tenant.id, org).await?;
            Ok((tenant, org))
        }
        Principal::OrgAdmin { tenant, org, .. } => Ok(((**tenant).clone(), (**org).clone())),
    }
}

/// A uuid from the path; anything else names nothing (404).
fn path_uuid(raw: &str) -> AdminResult<Uuid> {
    Uuid::parse_str(raw).map_err(|_| CoreError::NotFound.into())
}

fn role_ids(v: Vec<Uuid>) -> Vec<RoleId> {
    v.into_iter().map(RoleId).collect()
}

fn org_location(tenant: &Tenant, org: &Organization) -> String {
    format!(
        "/api/admin/v1/tenants/{}/organizations/{}",
        tenant.slug, org.id
    )
}

// ---------------------------------------------------------------------------------------------
// Organizations
// ---------------------------------------------------------------------------------------------

/// List the organizations of a tenant.
#[utoipa::path(
    get,
    path = "/api/admin/v1/tenants/{slug}/organizations",
    tag = "organizations",
    operation_id = "listOrganizations",
    params(("slug" = String, Path, description = "Tenant slug"), ListQuery),
    responses(
        (status = 200, description = "One page of organizations, in id order", body = OrganizationList),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Invalid query", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:organizations:read"]),
        ("oauth2" = ["admin:organizations:write"]),
        ("oauth2" = ["admin:read"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn list_organizations(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(slug): Path<String>,
    AdminQuery(q): AdminQuery<ListQuery>,
) -> AdminResult<Response> {
    let tenant = tenant_for(&state, &auth, &slug, Access::Read).await?;
    let page = state.admin_orgs().list(tenant.id, page_request(q)?).await?;
    Ok(json(
        StatusCode::OK,
        &OrganizationList {
            items: page.items.into_iter().map(Into::into).collect(),
            next_cursor: page.next_cursor,
        },
    ))
}

/// Create an organization. Not available in the system tenant (422).
#[utoipa::path(
    post,
    path = "/api/admin/v1/tenants/{slug}/organizations",
    tag = "organizations",
    operation_id = "createOrganization",
    params(("slug" = String, Path, description = "Tenant slug")),
    request_body = NewOrganizationDto,
    responses(
        (status = 201, description = "Created", body = OrganizationView, headers(("Location" = String, description = "URL of the new organization"))),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "An organization with this slug already exists", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed, or the tenant is the system tenant", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:organizations:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn create_organization(
    auth: AdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path(slug): Path<String>,
    AdminJson(body): AdminJson<NewOrganizationDto>,
) -> AdminResult<Response> {
    let tenant = tenant_for(&state, &auth, &slug, Access::Write).await?;
    let org = state
        .admin_orgs()
        .create(
            &tenant,
            OrgInput {
                slug: body.slug,
                display_name: body.display_name,
                mfa_policy: body.mfa_policy.map(Into::into),
                metadata: body.metadata,
            },
            &auth.org_actor(),
            &ctx,
        )
        .await?;
    Ok(created(
        &org_location(&tenant, &org),
        &OrganizationView::from(org),
    ))
}

/// Get an organization (by id or slug). Also allowed for the org's own admin.
#[utoipa::path(
    get,
    path = "/api/admin/v1/tenants/{slug}/organizations/{org}",
    tag = "organizations",
    operation_id = "getOrganization",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("org" = String, Path, description = "Organization id or slug"),
    ),
    responses(
        (status = 200, description = "The organization", body = OrganizationView),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope, or an org admin token of another organization", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant or organization", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:organizations:read"]),
        ("oauth2" = ["admin:organizations:write"]),
        ("oauth2" = ["admin:read"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn get_organization(
    OrgAdminAuth(auth): OrgAdminAuth,
    State(state): State<AppState>,
    Path((slug, org)): Path<(String, String)>,
) -> AdminResult<Response> {
    let (_, org) = org_for(&state, &auth, &slug, &org, Access::Read).await?;
    Ok(json(StatusCode::OK, &OrganizationView::from(org)))
}

/// Update an organization (tenant administrators only).
#[utoipa::path(
    patch,
    path = "/api/admin/v1/tenants/{slug}/organizations/{org}",
    tag = "organizations",
    operation_id = "updateOrganization",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("org" = String, Path, description = "Organization id or slug"),
    ),
    request_body = OrganizationPatchDto,
    responses(
        (status = 200, description = "The updated organization", body = OrganizationView),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope, or an org admin token", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant, organization or default role", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "Slug already in use", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:organizations:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn update_organization(
    OrgAdminAuth(auth): OrgAdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path((slug, org)): Path<(String, String)>,
    AdminJson(body): AdminJson<OrganizationPatchDto>,
) -> AdminResult<Response> {
    auth.require_system_admin()?;
    let (tenant, org) = org_for(&state, &auth, &slug, &org, Access::Write).await?;
    let org = state
        .admin_orgs()
        .update(
            &tenant,
            &org,
            OrgPatch {
                slug: body.slug,
                display_name: body.display_name,
                mfa_policy: body.mfa_policy.map(|m| m.map(Into::into)),
                metadata: body.metadata,
                default_role_ids: body.default_role_ids.map(role_ids),
            },
            &auth.org_actor(),
            &ctx,
        )
        .await?;
    Ok(json(StatusCode::OK, &OrganizationView::from(org)))
}

/// Delete an organization with its memberships, org roles, assignments, connections, domains and
/// invitations; its token families are revoked (tenant administrators only).
#[utoipa::path(
    delete,
    path = "/api/admin/v1/tenants/{slug}/organizations/{org}",
    tag = "organizations",
    operation_id = "deleteOrganization",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("org" = String, Path, description = "Organization id or slug"),
    ),
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope, or an org admin token", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant or organization", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:organizations:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn delete_organization(
    OrgAdminAuth(auth): OrgAdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path((slug, org)): Path<(String, String)>,
) -> AdminResult<Response> {
    auth.require_system_admin()?;
    let (tenant, org) = org_for(&state, &auth, &slug, &org, Access::Write).await?;
    state
        .admin_orgs()
        .delete(&tenant, &org, &auth.org_actor(), &ctx)
        .await?;
    Ok(no_content())
}

// ---------------------------------------------------------------------------------------------
// Members
// ---------------------------------------------------------------------------------------------

/// List the members of an organization.
#[utoipa::path(
    get,
    path = "/api/admin/v1/tenants/{slug}/organizations/{org}/members",
    tag = "organizations",
    operation_id = "listOrganizationMembers",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("org" = String, Path, description = "Organization id or slug"),
        ListQuery,
    ),
    responses(
        (status = 200, description = "One page of members, in user id order", body = MemberList),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope, or an org admin token of another organization", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant or organization", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Invalid query", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:organizations:read"]),
        ("oauth2" = ["admin:organizations:write"]),
        ("oauth2" = ["admin:read"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn list_members(
    OrgAdminAuth(auth): OrgAdminAuth,
    State(state): State<AppState>,
    Path((slug, org)): Path<(String, String)>,
    AdminQuery(q): AdminQuery<ListQuery>,
) -> AdminResult<Response> {
    let (tenant, org) = org_for(&state, &auth, &slug, &org, Access::Read).await?;
    let page = state
        .admin_orgs()
        .list_members(tenant.id, org.id, page_request(q)?)
        .await?;
    Ok(json(
        StatusCode::OK,
        &MemberList {
            items: page.items.into_iter().map(Into::into).collect(),
            next_cursor: page.next_cursor,
        },
    ))
}

/// Add a user of the tenant to the organization directly, with roles assigned in the org
/// (idempotent: an existing member is kept unchanged, 200). Tenant administrators only: org
/// admins invite members instead.
#[utoipa::path(
    post,
    path = "/api/admin/v1/tenants/{slug}/organizations/{org}/members",
    tag = "organizations",
    operation_id = "addOrganizationMember",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("org" = String, Path, description = "Organization id or slug"),
    ),
    request_body = AddMemberDto,
    responses(
        (status = 201, description = "Added", body = MemberAdded),
        (status = 200, description = "Already a member (unchanged)", body = MemberAdded),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope, or an org admin token", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant, organization, user or role (or a role of another organization)", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed, or a role carries admin permissions", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:organizations:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn add_member(
    OrgAdminAuth(auth): OrgAdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path((slug, org)): Path<(String, String)>,
    AdminJson(body): AdminJson<AddMemberDto>,
) -> AdminResult<Response> {
    auth.require_system_admin()?;
    let (tenant, org) = org_for(&state, &auth, &slug, &org, Access::Write).await?;
    let user = UserId(body.user_id);
    let added = state
        .admin_orgs()
        .add_member(
            &tenant,
            &org,
            user,
            role_ids(body.role_ids),
            &auth.org_actor(),
            &ctx,
        )
        .await?;
    let status = if added {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok(json(
        status,
        &MemberAdded {
            user_id: user.0,
            added,
        },
    ))
}

/// Remove a member: their org role assignments go with the membership and their token families
/// bound to this org are revoked, in one storage intent. An org admin may not remove the last
/// org admin (409); a tenant administrator may.
#[utoipa::path(
    delete,
    path = "/api/admin/v1/tenants/{slug}/organizations/{org}/members/{user_id}",
    tag = "organizations",
    operation_id = "removeOrganizationMember",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("org" = String, Path, description = "Organization id or slug"),
        ("user_id" = uuid::Uuid, Path, description = "User id"),
    ),
    responses(
        (status = 204, description = "Removed"),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope, or an org admin token of another organization", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant or organization, or the user is not a member", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "The organization would have no org admin", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:organizations:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn remove_member(
    OrgAdminAuth(auth): OrgAdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path((slug, org, user)): Path<(String, String, String)>,
) -> AdminResult<Response> {
    let (tenant, org) = org_for(&state, &auth, &slug, &org, Access::Write).await?;
    let user = UserId(path_uuid(&user)?);
    state
        .admin_orgs()
        .remove_member(&tenant, &org, user, &auth.org_actor(), &ctx)
        .await?;
    Ok(no_content())
}

// ---------------------------------------------------------------------------------------------
// Assignments
// ---------------------------------------------------------------------------------------------

/// List the roles a member holds in the organization (org-owned and tenant roles).
#[utoipa::path(
    get,
    path = "/api/admin/v1/tenants/{slug}/organizations/{org}/members/{user_id}/roles",
    tag = "organizations",
    operation_id = "listOrganizationMemberRoles",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("org" = String, Path, description = "Organization id or slug"),
        ("user_id" = uuid::Uuid, Path, description = "User id"),
    ),
    responses(
        (status = 200, description = "The member's roles in the org, in name order", body = OrgRoleList),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope, or an org admin token of another organization", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant or organization, or the user is not a member", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:organizations:read"]),
        ("oauth2" = ["admin:organizations:write"]),
        ("oauth2" = ["admin:read"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn list_member_roles(
    OrgAdminAuth(auth): OrgAdminAuth,
    State(state): State<AppState>,
    Path((slug, org, user)): Path<(String, String, String)>,
) -> AdminResult<Response> {
    let (tenant, org) = org_for(&state, &auth, &slug, &org, Access::Read).await?;
    let user = UserId(path_uuid(&user)?);
    let roles = state
        .admin_orgs()
        .member_roles(tenant.id, org.id, user)
        .await?;
    Ok(json(StatusCode::OK, &OrgRoleList::from(roles)))
}

/// Assign a role to a member within the organization (idempotent). The role is an org-owned role
/// of this org or a tenant role; a role carrying an admin permission is refused (422).
#[utoipa::path(
    put,
    path = "/api/admin/v1/tenants/{slug}/organizations/{org}/members/{user_id}/roles/{role}",
    tag = "organizations",
    operation_id = "assignOrganizationMemberRole",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("org" = String, Path, description = "Organization id or slug"),
        ("user_id" = uuid::Uuid, Path, description = "User id"),
        ("role" = String, Path, description = "Role name"),
        RoleScopeQuery,
    ),
    responses(
        (status = 200, description = "The member holds the role in the org", body = OrgAssignmentView),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope, or an org admin token of another organization", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant, organization or role, or the user is not a member", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "The role carries admin permissions, or invalid query", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:organizations:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn assign_member_role(
    OrgAdminAuth(auth): OrgAdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path((slug, org, user, role)): Path<(String, String, String, String)>,
    AdminQuery(q): AdminQuery<RoleScopeQuery>,
) -> AdminResult<Response> {
    let (tenant, org) = org_for(&state, &auth, &slug, &org, Access::Write).await?;
    let user = UserId(path_uuid(&user)?);
    let orgs = state.admin_orgs();
    let role = orgs
        .resolve_role(tenant.id, org.id, &role, q.scope.map(Into::into))
        .await?;
    orgs.assign(&tenant, &org, user, &role, &auth.org_actor(), &ctx)
        .await?;
    Ok(json(
        StatusCode::OK,
        &OrgAssignmentView {
            user_id: user.0,
            role: role.into(),
        },
    ))
}

/// Remove a role from a member within the organization. An org admin may not remove the last org
/// admin's `org:admin` (409); a tenant administrator may.
#[utoipa::path(
    delete,
    path = "/api/admin/v1/tenants/{slug}/organizations/{org}/members/{user_id}/roles/{role}",
    tag = "organizations",
    operation_id = "unassignOrganizationMemberRole",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("org" = String, Path, description = "Organization id or slug"),
        ("user_id" = uuid::Uuid, Path, description = "User id"),
        ("role" = String, Path, description = "Role name"),
        RoleScopeQuery,
    ),
    responses(
        (status = 204, description = "Removed"),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope, or an org admin token of another organization", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant, organization or role, or the member does not hold it", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "The organization would have no org admin", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Invalid query", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:organizations:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn unassign_member_role(
    OrgAdminAuth(auth): OrgAdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path((slug, org, user, role)): Path<(String, String, String, String)>,
    AdminQuery(q): AdminQuery<RoleScopeQuery>,
) -> AdminResult<Response> {
    let (tenant, org) = org_for(&state, &auth, &slug, &org, Access::Write).await?;
    let user = UserId(path_uuid(&user)?);
    let orgs = state.admin_orgs();
    let role = orgs
        .resolve_role(tenant.id, org.id, &role, q.scope.map(Into::into))
        .await?;
    orgs.unassign(&tenant, &org, user, &role, &auth.org_actor(), &ctx)
        .await?;
    Ok(no_content())
}

// ---------------------------------------------------------------------------------------------
// Org roles
// ---------------------------------------------------------------------------------------------

/// List the roles owned by the organization.
#[utoipa::path(
    get,
    path = "/api/admin/v1/tenants/{slug}/organizations/{org}/roles",
    tag = "organizations",
    operation_id = "listOrganizationRoles",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("org" = String, Path, description = "Organization id or slug"),
    ),
    responses(
        (status = 200, description = "The org-owned roles, in name order", body = OrgRoleList),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope, or an org admin token of another organization", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant or organization", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:organizations:read"]),
        ("oauth2" = ["admin:organizations:write"]),
        ("oauth2" = ["admin:read"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn list_org_roles(
    OrgAdminAuth(auth): OrgAdminAuth,
    State(state): State<AppState>,
    Path((slug, org)): Path<(String, String)>,
) -> AdminResult<Response> {
    let (tenant, org) = org_for(&state, &auth, &slug, &org, Access::Read).await?;
    let roles = state.admin_orgs().list_roles(tenant.id, org.id).await?;
    Ok(json(StatusCode::OK, &OrgRoleList::from(roles)))
}

/// Create an org-owned role. Admin permissions (`admin`, `admin:*`) are refused (422);
/// `org:admin` makes holders org admins.
#[utoipa::path(
    post,
    path = "/api/admin/v1/tenants/{slug}/organizations/{org}/roles",
    tag = "organizations",
    operation_id = "createOrganizationRole",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("org" = String, Path, description = "Organization id or slug"),
    ),
    request_body = NewOrgRoleDto,
    responses(
        (status = 201, description = "Created", body = OrgRoleView, headers(("Location" = String, description = "URL of the new role"))),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope, or an org admin token of another organization", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant or organization", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "A role with this name already exists in the organization", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed, or an admin permission", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:organizations:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn create_org_role(
    OrgAdminAuth(auth): OrgAdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path((slug, org)): Path<(String, String)>,
    AdminJson(body): AdminJson<NewOrgRoleDto>,
) -> AdminResult<Response> {
    let (tenant, org) = org_for(&state, &auth, &slug, &org, Access::Write).await?;
    let role = state
        .admin_orgs()
        .create_role(
            &tenant,
            &org,
            RoleInput {
                name: body.name,
                description: body.description,
                permissions: body.permissions,
            },
            &auth.org_actor(),
            &ctx,
        )
        .await?;
    let location = format!("{}/roles/{}", org_location(&tenant, &org), role.name);
    Ok(created(&location, &OrgRoleView::from(role)))
}

/// Get an org-owned role.
#[utoipa::path(
    get,
    path = "/api/admin/v1/tenants/{slug}/organizations/{org}/roles/{name}",
    tag = "organizations",
    operation_id = "getOrganizationRole",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("org" = String, Path, description = "Organization id or slug"),
        ("name" = String, Path, description = "Role name"),
    ),
    responses(
        (status = 200, description = "The role", body = OrgRoleView),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope, or an org admin token of another organization", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant, organization or role", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:organizations:read"]),
        ("oauth2" = ["admin:organizations:write"]),
        ("oauth2" = ["admin:read"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn get_org_role(
    OrgAdminAuth(auth): OrgAdminAuth,
    State(state): State<AppState>,
    Path((slug, org, name)): Path<(String, String, String)>,
) -> AdminResult<Response> {
    let (tenant, org) = org_for(&state, &auth, &slug, &org, Access::Read).await?;
    let role = state
        .admin_orgs()
        .get_role(tenant.id, org.id, &name)
        .await?;
    Ok(json(StatusCode::OK, &OrgRoleView::from(role)))
}

/// Update an org-owned role. An org admin may not drop `org:admin` when that leaves the org
/// without an org admin (409).
#[utoipa::path(
    patch,
    path = "/api/admin/v1/tenants/{slug}/organizations/{org}/roles/{name}",
    tag = "organizations",
    operation_id = "updateOrganizationRole",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("org" = String, Path, description = "Organization id or slug"),
        ("name" = String, Path, description = "Role name"),
    ),
    request_body = OrgRolePatchDto,
    responses(
        (status = 200, description = "The updated role", body = OrgRoleView),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope, or an org admin token of another organization", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant, organization or role", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "Name already in use, or the organization would have no org admin", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed, or an admin permission", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:organizations:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn update_org_role(
    OrgAdminAuth(auth): OrgAdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path((slug, org, name)): Path<(String, String, String)>,
    AdminJson(body): AdminJson<OrgRolePatchDto>,
) -> AdminResult<Response> {
    let (tenant, org) = org_for(&state, &auth, &slug, &org, Access::Write).await?;
    let role = state
        .admin_orgs()
        .update_role(
            &tenant,
            &org,
            &name,
            RoleUpdate {
                name: body.name,
                description: body.description,
                permissions: body.permissions,
            },
            &auth.org_actor(),
            &ctx,
        )
        .await?;
    Ok(json(StatusCode::OK, &OrgRoleView::from(role)))
}

/// Delete an org-owned role and its assignments. An org admin may not delete an `org:admin` role
/// when that leaves the org without an org admin (409).
#[utoipa::path(
    delete,
    path = "/api/admin/v1/tenants/{slug}/organizations/{org}/roles/{name}",
    tag = "organizations",
    operation_id = "deleteOrganizationRole",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("org" = String, Path, description = "Organization id or slug"),
        ("name" = String, Path, description = "Role name"),
    ),
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope, or an org admin token of another organization", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant, organization or role", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "The organization would have no org admin", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:organizations:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn delete_org_role(
    OrgAdminAuth(auth): OrgAdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path((slug, org, name)): Path<(String, String, String)>,
) -> AdminResult<Response> {
    let (tenant, org) = org_for(&state, &auth, &slug, &org, Access::Write).await?;
    state
        .admin_orgs()
        .delete_role(&tenant, &org, &name, &auth.org_actor(), &ctx)
        .await?;
    Ok(no_content())
}

// ---------------------------------------------------------------------------------------------
// Invitations
// ---------------------------------------------------------------------------------------------

/// List the organization's invitations, newest first (never the token or its hash).
#[utoipa::path(
    get,
    path = "/api/admin/v1/tenants/{slug}/organizations/{org}/invitations",
    tag = "organizations",
    operation_id = "listOrganizationInvitations",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("org" = String, Path, description = "Organization id or slug"),
        InvitationQuery,
    ),
    responses(
        (status = 200, description = "Invitations, newest first", body = InvitationList),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope, or an org admin token of another organization", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant or organization", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Invalid query", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:organizations:read"]),
        ("oauth2" = ["admin:organizations:write"]),
        ("oauth2" = ["admin:read"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn list_invitations(
    OrgAdminAuth(auth): OrgAdminAuth,
    State(state): State<AppState>,
    Path((slug, org)): Path<(String, String)>,
    AdminQuery(q): AdminQuery<InvitationQuery>,
) -> AdminResult<Response> {
    let (tenant, org) = org_for(&state, &auth, &slug, &org, Access::Read).await?;
    let list = state
        .admin_org_invitations()
        .list(tenant.id, org.id, q.include_closed.unwrap_or(false))
        .await?;
    let now = state.clock().now();
    Ok(json(
        StatusCode::OK,
        &InvitationList {
            items: list
                .into_iter()
                .map(|i| InvitationView::new(i, now))
                .collect(),
        },
    ))
}

/// Invite an address to the organization: stores only the SHA-256 of a 256-bit token, expires
/// after 7 days and enqueues the `org_invitation` email with the link. The answer is the same
/// whether or not an account exists for the address.
#[utoipa::path(
    post,
    path = "/api/admin/v1/tenants/{slug}/organizations/{org}/invitations",
    tag = "organizations",
    operation_id = "createOrganizationInvitation",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("org" = String, Path, description = "Organization id or slug"),
    ),
    request_body = NewInvitationDto,
    responses(
        (status = 201, description = "Invitation created and its email queued", body = InvitationView),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope, or an org admin token of another organization", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant, organization or role (or a role of another organization)", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed, or a role carries admin permissions", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:organizations:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn create_invitation(
    OrgAdminAuth(auth): OrgAdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path((slug, org)): Path<(String, String)>,
    AdminJson(body): AdminJson<NewInvitationDto>,
) -> AdminResult<Response> {
    let (tenant, org) = org_for(&state, &auth, &slug, &org, Access::Write).await?;
    let issuer = state.admin_issuer_of(&tenant);
    let invitation = state
        .admin_org_invitations()
        .create(
            &tenant,
            &org,
            &issuer,
            InvitationInput {
                email: body.email,
                role_ids: role_ids(body.role_ids),
            },
            &auth.org_actor(),
            &ctx,
        )
        .await?;
    let location = format!(
        "{}/invitations/{}",
        org_location(&tenant, &org),
        invitation.id
    );
    let view = InvitationView::new(invitation, state.clock().now());
    Ok(created(&location, &view))
}

/// Revoke an open invitation.
#[utoipa::path(
    delete,
    path = "/api/admin/v1/tenants/{slug}/organizations/{org}/invitations/{id}",
    tag = "organizations",
    operation_id = "revokeOrganizationInvitation",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("org" = String, Path, description = "Organization id or slug"),
        ("id" = uuid::Uuid, Path, description = "Invitation id"),
    ),
    responses(
        (status = 204, description = "Revoked"),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope, or an org admin token of another organization", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant or organization, or no open invitation with this id", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:organizations:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn revoke_invitation(
    OrgAdminAuth(auth): OrgAdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path((slug, org, id)): Path<(String, String, String)>,
) -> AdminResult<Response> {
    let (tenant, org) = org_for(&state, &auth, &slug, &org, Access::Write).await?;
    let id = OrgInvitationId(path_uuid(&id)?);
    state
        .admin_org_invitations()
        .revoke(&tenant, &org, id, &auth.org_actor(), &ctx)
        .await?;
    Ok(no_content())
}

// ---------------------------------------------------------------------------------------------
// Connections (06-17)
// ---------------------------------------------------------------------------------------------

/// Every IdP signing certificate of a SAML config must load as an X.509 certificate with the
/// same loader the SAML adapter verifies signatures with (422 `config.signing_certs`).
fn check_saml_certs(config: &CoreConnectionConfig) -> AdminResult<()> {
    if let CoreConnectionConfig::Saml(c) = config
        && c.signing_certs
            .iter()
            .any(|pem| bergshamra_keys::loader::load_x509_cert_pem(pem.as_bytes()).is_err())
    {
        return Err(CoreError::Validation {
            field: "config.signing_certs",
            message: "each entry must be a valid X.509 certificate in PEM form".to_owned(),
        }
        .into());
    }
    Ok(())
}

fn connection_id(raw: &str) -> AdminResult<ConnectionId> {
    Ok(ConnectionId(path_uuid(raw)?))
}

fn connection_location(tenant: &Tenant, org: &Organization, conn: &Connection) -> String {
    format!("{}/connections/{}", org_location(tenant, org), conn.id)
}

/// List the organization's enterprise connections (OIDC and SAML).
#[utoipa::path(
    get,
    path = "/api/admin/v1/tenants/{slug}/organizations/{org}/connections",
    tag = "organizations",
    operation_id = "listOrganizationConnections",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("org" = String, Path, description = "Organization id or slug"),
    ),
    responses(
        (status = 200, description = "The organization's connections, in slug order", body = ConnectionList),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope, or an org admin token of another organization", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant or organization", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:organizations:read"]),
        ("oauth2" = ["admin:organizations:write"]),
        ("oauth2" = ["admin:read"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn list_org_connections(
    OrgAdminAuth(auth): OrgAdminAuth,
    State(state): State<AppState>,
    Path((slug, org)): Path<(String, String)>,
) -> AdminResult<Response> {
    let (tenant, org) = org_for(&state, &auth, &slug, &org, Access::Read).await?;
    let issuer = state.admin_issuer_of(&tenant);
    let items = state
        .admin_connections()
        .list_for_org(tenant.id, &org)
        .await?
        .into_iter()
        .map(|c| ConnectionView::new(c, &issuer))
        .collect();
    Ok(json(StatusCode::OK, &ConnectionList { items }))
}

/// Create an enterprise connection of the organization: OIDC (client secret sealed, never
/// returned) or SAML (experimental: 403 `feature_disabled` unless the operator enabled
/// `saml_experimental`). Slugs share the tenant's namespace. A SAML view carries the
/// service-provider values to register at the IdP (`sp`).
#[utoipa::path(
    post,
    path = "/api/admin/v1/tenants/{slug}/organizations/{org}/connections",
    tag = "organizations",
    operation_id = "createOrganizationConnection",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("org" = String, Path, description = "Organization id or slug"),
    ),
    request_body = CreateConnection,
    responses(
        (status = 201, description = "Created", body = ConnectionView, headers(("Location" = String, description = "URL of the new connection"))),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope, an org admin token of another organization, or SAML is not enabled (`feature_disabled`)", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant or organization", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "Slug already in use in this tenant", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed (also: a kind other than OIDC or SAML)", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:organizations:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn create_org_connection(
    OrgAdminAuth(auth): OrgAdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path((slug, org)): Path<(String, String)>,
    AdminJson(body): AdminJson<CreateConnection>,
) -> AdminResult<Response> {
    let (tenant, org) = org_for(&state, &auth, &slug, &org, Access::Write).await?;
    let input: NewConnectionInput = body.into();
    check_saml_certs(&input.config)?;
    let conn = state
        .admin_connections()
        .create_as(
            tenant.id,
            ConnectionOwner::Org(&org),
            input,
            auth.actor(),
            &ctx,
        )
        .await?;
    let location = connection_location(&tenant, &org, &conn);
    Ok(created(
        &location,
        &ConnectionView::new(conn, &state.admin_issuer_of(&tenant)),
    ))
}

/// Get one of the organization's connections (never its secret).
#[utoipa::path(
    get,
    path = "/api/admin/v1/tenants/{slug}/organizations/{org}/connections/{id}",
    tag = "organizations",
    operation_id = "getOrganizationConnection",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("org" = String, Path, description = "Organization id or slug"),
        ("id" = uuid::Uuid, Path, description = "Connection id"),
    ),
    responses(
        (status = 200, description = "The connection", body = ConnectionView),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope, or an org admin token of another organization", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant, organization or connection (or another organization's connection)", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:organizations:read"]),
        ("oauth2" = ["admin:organizations:write"]),
        ("oauth2" = ["admin:read"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn get_org_connection(
    OrgAdminAuth(auth): OrgAdminAuth,
    State(state): State<AppState>,
    Path((slug, org, id)): Path<(String, String, String)>,
) -> AdminResult<Response> {
    let (tenant, org) = org_for(&state, &auth, &slug, &org, Access::Read).await?;
    let conn = state
        .admin_connections()
        .get_owned(tenant.id, ConnectionOwner::Org(&org), connection_id(&id)?)
        .await?;
    Ok(json(
        StatusCode::OK,
        &ConnectionView::new(conn, &state.admin_issuer_of(&tenant)),
    ))
}

/// Update one of the organization's connections. Absent fields stay unchanged; the slug and
/// kind are fixed. Every change to a SAML connection except disabling it needs the operator flag
/// (403 `feature_disabled`).
#[utoipa::path(
    patch,
    path = "/api/admin/v1/tenants/{slug}/organizations/{org}/connections/{id}",
    tag = "organizations",
    operation_id = "updateOrganizationConnection",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("org" = String, Path, description = "Organization id or slug"),
        ("id" = uuid::Uuid, Path, description = "Connection id"),
    ),
    request_body = UpdateConnection,
    responses(
        (status = 200, description = "The updated connection", body = ConnectionView),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope, an org admin token of another organization, or SAML is not enabled (`feature_disabled`)", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant, organization or connection (or another organization's connection)", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:organizations:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn update_org_connection(
    OrgAdminAuth(auth): OrgAdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path((slug, org, id)): Path<(String, String, String)>,
    AdminJson(body): AdminJson<UpdateConnection>,
) -> AdminResult<Response> {
    let (tenant, org) = org_for(&state, &auth, &slug, &org, Access::Write).await?;
    let patch: ConnectionPatch = body.into();
    if let Some(config) = &patch.config {
        check_saml_certs(config)?;
    }
    let conn = state
        .admin_connections()
        .update_as(
            tenant.id,
            ConnectionOwner::Org(&org),
            connection_id(&id)?,
            patch,
            auth.actor(),
            &ctx,
        )
        .await?;
    Ok(json(
        StatusCode::OK,
        &ConnectionView::new(conn, &state.admin_issuer_of(&tenant)),
    ))
}

/// Delete one of the organization's connections with its identity links. Domains routed to it
/// stop routing (their claim and verification stay).
#[utoipa::path(
    delete,
    path = "/api/admin/v1/tenants/{slug}/organizations/{org}/connections/{id}",
    tag = "organizations",
    operation_id = "deleteOrganizationConnection",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("org" = String, Path, description = "Organization id or slug"),
        ("id" = uuid::Uuid, Path, description = "Connection id"),
    ),
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope, or an org admin token of another organization", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant, organization or connection (or another organization's connection)", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:organizations:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn delete_org_connection(
    OrgAdminAuth(auth): OrgAdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path((slug, org, id)): Path<(String, String, String)>,
) -> AdminResult<Response> {
    let (tenant, org) = org_for(&state, &auth, &slug, &org, Access::Write).await?;
    state
        .admin_connections()
        .delete_as(
            tenant.id,
            ConnectionOwner::Org(&org),
            connection_id(&id)?,
            auth.actor(),
            &ctx,
        )
        .await?;
    Ok(no_content())
}

/// Set or remove the client secret of an OIDC connection of the organization. Write-only: the
/// response reports `secret_configured`. SAML connections have no secret (422).
#[utoipa::path(
    put,
    path = "/api/admin/v1/tenants/{slug}/organizations/{org}/connections/{id}/secret",
    tag = "organizations",
    operation_id = "putOrganizationConnectionSecret",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("org" = String, Path, description = "Organization id or slug"),
        ("id" = uuid::Uuid, Path, description = "Connection id"),
    ),
    request_body = PutConnectionSecret,
    responses(
        (status = 200, description = "The connection", body = ConnectionView),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope, or an org admin token of another organization", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant, organization or connection (or another organization's connection)", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:organizations:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn put_org_connection_secret(
    OrgAdminAuth(auth): OrgAdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path((slug, org, id)): Path<(String, String, String)>,
    AdminJson(body): AdminJson<PutConnectionSecret>,
) -> AdminResult<Response> {
    let (tenant, org) = org_for(&state, &auth, &slug, &org, Access::Write).await?;
    let id = connection_id(&id)?;
    let secret = body.secret.ok_or_else(|| CoreError::Validation {
        field: "secret",
        message: "is required (null removes the secret)".to_owned(),
    })?;
    let conn = state
        .admin_connections()
        .set_secret_as(
            tenant.id,
            ConnectionOwner::Org(&org),
            id,
            secret.map(SecretString::from),
            auth.actor(),
            &ctx,
        )
        .await?;
    Ok(json(
        StatusCode::OK,
        &ConnectionView::new(conn, &state.admin_issuer_of(&tenant)),
    ))
}

/// The single answer for every metadata URL that could not be fetched (blocked destination,
/// network error, status, size): never the URL, an address or the response.
fn metadata_fetch_failed() -> CoreError {
    CoreError::Validation {
        field: "url",
        message: "the metadata could not be fetched (an https URL of a public host, answering \
                  with at most 1 MiB)"
            .to_owned(),
    }
}

/// Read SAML IdP metadata to prefill a connection: the pasted document (`xml`) or a metadata URL
/// (`url`, https, fetched through the SSRF-guarded outbound client, at most 1 MiB). Persists
/// nothing. Needs the operator flag `saml_experimental` (403 `feature_disabled`).
#[utoipa::path(
    post,
    path = "/api/admin/v1/tenants/{slug}/organizations/{org}/connections/saml-metadata",
    tag = "organizations",
    operation_id = "importOrganizationSamlMetadata",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("org" = String, Path, description = "Organization id or slug"),
    ),
    request_body = SamlMetadataImport,
    responses(
        (status = 200, description = "The values read from the metadata", body = SamlMetadataView),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope, an org admin token of another organization, or SAML is not enabled (`feature_disabled`)", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant or organization", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Not exactly one of xml and url, the URL could not be fetched, or the document is not usable IdP metadata", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:organizations:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn import_saml_metadata(
    OrgAdminAuth(auth): OrgAdminAuth,
    State(state): State<AppState>,
    Path((slug, org)): Path<(String, String)>,
    AdminJson(body): AdminJson<SamlMetadataImport>,
) -> AdminResult<Response> {
    let _ = org_for(&state, &auth, &slug, &org, Access::Write).await?;
    let service = state.admin_connections();
    if !service.saml_enabled {
        return Err(CoreError::FeatureDisabled("saml").into());
    }
    let (field, xml, url) = match (body.xml, body.url) {
        (Some(xml), None) => ("xml", xml.into_bytes(), None),
        (None, Some(url)) => {
            let xml = state
                .outbound()
                .get(&url)
                .map_err(|_| metadata_fetch_failed())?
                .fetch(LIMIT_DOCUMENT)
                .await
                .map_err(|_| metadata_fetch_failed())?;
            ("url", xml, Some(url))
        }
        _ => {
            return Err(CoreError::Validation {
                field: "xml",
                message: "exactly one of xml and url is required".to_owned(),
            }
            .into());
        }
    };
    // The SAML adapter's `SamlXml::parse_metadata` (size caps, no DTD) through the service.
    let metadata = service.parse_idp_metadata(field, &xml)?;
    Ok(json(StatusCode::OK, &SamlMetadataView::new(metadata, url)))
}

// ---------------------------------------------------------------------------------------------
// Domains (06-17)
// ---------------------------------------------------------------------------------------------

impl AppState {
    fn admin_org_domains(&self) -> OrgDomainService {
        OrgDomainService {
            storage: self.storage_arc(),
            clock: self.clock_arc(),
            lookup: self.domain_txt_arc(),
        }
    }
}

/// Verification state of a domain claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DomainStatus {
    Pending,
    Verified,
}

/// A domain claimed by an organization, with the DNS record that proves it and its routing
/// settings.
#[derive(Debug, Serialize, ToSchema)]
pub struct DomainView {
    pub id: Uuid,
    /// Lowercase A-label.
    pub domain: String,
    pub status: DomainStatus,
    /// The TXT record name to publish: `_anvilid-challenge.{domain}.`.
    pub record_name: String,
    /// The TXT record value to publish: `anvilid-domain-verification={token}`.
    pub record_value: String,
    /// The connection (of this organization) users of this domain are routed to.
    pub connection_id: Option<Uuid>,
    /// Whether identifier-first sign-in routes this domain to `connection_id`.
    pub routing: bool,
    /// Whether password sign-in stays available for this domain (default `true`).
    pub allow_local_password: bool,
    #[schema(format = DateTime)]
    pub verified_at: Option<String>,
    #[schema(format = DateTime)]
    pub last_checked_at: Option<String>,
    /// Start of the current run of failed re-checks of a verified domain.
    #[schema(format = DateTime)]
    pub failing_since: Option<String>,
    #[schema(format = DateTime)]
    pub created_at: String,
}

impl From<OrgDomain> for DomainView {
    fn from(d: OrgDomain) -> Self {
        Self {
            id: d.id.0,
            record_name: domain_verification::record_name(&d.domain),
            record_value: domain_verification::record_value(&d.token),
            status: match d.status {
                OrgDomainStatus::Pending => DomainStatus::Pending,
                OrgDomainStatus::Verified => DomainStatus::Verified,
            },
            domain: d.domain,
            connection_id: d.connection_id.map(|c| c.0),
            routing: d.routing,
            allow_local_password: d.allow_local_password,
            verified_at: d.verified_at.map(ts),
            last_checked_at: d.last_checked_at.map(ts),
            failing_since: d.failing_since.map(ts),
            created_at: ts(d.created_at),
        }
    }
}

/// The organization's domain claims, in domain order.
#[derive(Debug, Serialize, ToSchema)]
pub struct DomainList {
    pub items: Vec<DomainView>,
}

/// Body of `POST …/{org}/domains`.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NewDomainDto {
    /// A registrable domain name (no scheme, port, path, wildcard, IP address, reserved name or
    /// public suffix); stored as a lowercase A-label.
    pub domain: String,
}

/// Body of `PATCH …/{org}/domains/{id}`. Absent fields stay unchanged.
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct DomainPatchDto {
    /// A connection of this organization; `null` removes the target.
    #[serde(default, deserialize_with = "double_option")]
    #[schema(value_type = Option<Uuid>)]
    pub connection_id: Option<Option<Uuid>>,
    /// Needs a verified domain and an enabled target connection.
    #[serde(default)]
    pub routing: Option<bool>,
    /// `false` enforces SSO for the domain; it needs routing on and a target connection that has
    /// completed at least one sign-in (409 otherwise).
    #[serde(default)]
    pub allow_local_password: Option<bool>,
}

fn domain_id(raw: &str) -> AdminResult<OrgDomainId> {
    Ok(OrgDomainId(path_uuid(raw)?))
}

/// List the organization's domain claims.
#[utoipa::path(
    get,
    path = "/api/admin/v1/tenants/{slug}/organizations/{org}/domains",
    tag = "organizations",
    operation_id = "listOrganizationDomains",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("org" = String, Path, description = "Organization id or slug"),
    ),
    responses(
        (status = 200, description = "The domain claims, in domain order", body = DomainList),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope, or an org admin token of another organization", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant or organization", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:organizations:read"]),
        ("oauth2" = ["admin:organizations:write"]),
        ("oauth2" = ["admin:read"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn list_org_domains(
    OrgAdminAuth(auth): OrgAdminAuth,
    State(state): State<AppState>,
    Path((slug, org)): Path<(String, String)>,
) -> AdminResult<Response> {
    let (_, org) = org_for(&state, &auth, &slug, &org, Access::Read).await?;
    let items = state
        .admin_org_domains()
        .list(&org)
        .await?
        .into_iter()
        .map(Into::into)
        .collect();
    Ok(json(StatusCode::OK, &DomainList { items }))
}

/// Claim a domain for the organization. The answer carries the TXT record to publish; the claim
/// stays `pending` until verified.
#[utoipa::path(
    post,
    path = "/api/admin/v1/tenants/{slug}/organizations/{org}/domains",
    tag = "organizations",
    operation_id = "createOrganizationDomain",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("org" = String, Path, description = "Organization id or slug"),
    ),
    request_body = NewDomainDto,
    responses(
        (status = 201, description = "Claimed (pending)", body = DomainView, headers(("Location" = String, description = "URL of the new claim"))),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope, or an org admin token of another organization", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant or organization", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "The organization already claimed this domain", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Not an acceptable domain (the message names the reason)", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:organizations:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn create_org_domain(
    OrgAdminAuth(auth): OrgAdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path((slug, org)): Path<(String, String)>,
    AdminJson(body): AdminJson<NewDomainDto>,
) -> AdminResult<Response> {
    let (tenant, org) = org_for(&state, &auth, &slug, &org, Access::Write).await?;
    let claim = state
        .admin_org_domains()
        .add(&org, &body.domain, auth.actor(), &ctx)
        .await?;
    let location = format!("{}/domains/{}", org_location(&tenant, &org), claim.id);
    Ok(created(&location, &DomainView::from(claim)))
}

/// Get one of the organization's domain claims.
#[utoipa::path(
    get,
    path = "/api/admin/v1/tenants/{slug}/organizations/{org}/domains/{id}",
    tag = "organizations",
    operation_id = "getOrganizationDomain",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("org" = String, Path, description = "Organization id or slug"),
        ("id" = uuid::Uuid, Path, description = "Domain claim id"),
    ),
    responses(
        (status = 200, description = "The domain claim", body = DomainView),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope, or an org admin token of another organization", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant, organization or claim (or another organization's claim)", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:organizations:read"]),
        ("oauth2" = ["admin:organizations:write"]),
        ("oauth2" = ["admin:read"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn get_org_domain(
    OrgAdminAuth(auth): OrgAdminAuth,
    State(state): State<AppState>,
    Path((slug, org, id)): Path<(String, String, String)>,
) -> AdminResult<Response> {
    let (_, org) = org_for(&state, &auth, &slug, &org, Access::Read).await?;
    let claim = state.admin_org_domains().get(&org, domain_id(&id)?).await?;
    Ok(json(StatusCode::OK, &DomainView::from(claim)))
}

/// Change the routing settings of a domain claim. Routing needs a verified domain and an
/// enabled connection of this organization; turning password sign-in off additionally needs a
/// connection that has completed at least one sign-in (409, lockout guard). Setting
/// `routing: false, allow_local_password: true` always works (recovery).
#[utoipa::path(
    patch,
    path = "/api/admin/v1/tenants/{slug}/organizations/{org}/domains/{id}",
    tag = "organizations",
    operation_id = "updateOrganizationDomain",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("org" = String, Path, description = "Organization id or slug"),
        ("id" = uuid::Uuid, Path, description = "Domain claim id"),
    ),
    request_body = DomainPatchDto,
    responses(
        (status = 200, description = "The updated claim", body = DomainView),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope, or an org admin token of another organization", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant, organization or claim (or another organization's claim)", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "The settings are not allowed in the claim's state (pending domain, no or disabled target, lockout guard)", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed (also: the target is not a connection of this organization)", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:organizations:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn update_org_domain(
    OrgAdminAuth(auth): OrgAdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path((slug, org, id)): Path<(String, String, String)>,
    AdminJson(body): AdminJson<DomainPatchDto>,
) -> AdminResult<Response> {
    let (_, org) = org_for(&state, &auth, &slug, &org, Access::Write).await?;
    let claim = state
        .admin_org_domains()
        .update(
            &org,
            domain_id(&id)?,
            DomainPatch {
                connection_id: body.connection_id.map(|c| c.map(ConnectionId)),
                routing: body.routing,
                allow_local_password: body.allow_local_password,
            },
            auth.actor(),
            &ctx,
        )
        .await?;
    Ok(json(StatusCode::OK, &DomainView::from(claim)))
}

/// Delete a domain claim; routing for the domain stops.
#[utoipa::path(
    delete,
    path = "/api/admin/v1/tenants/{slug}/organizations/{org}/domains/{id}",
    tag = "organizations",
    operation_id = "deleteOrganizationDomain",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("org" = String, Path, description = "Organization id or slug"),
        ("id" = uuid::Uuid, Path, description = "Domain claim id"),
    ),
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope, or an org admin token of another organization", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant, organization or claim (or another organization's claim)", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:organizations:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn delete_org_domain(
    OrgAdminAuth(auth): OrgAdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path((slug, org, id)): Path<(String, String, String)>,
) -> AdminResult<Response> {
    let (_, org) = org_for(&state, &auth, &slug, &org, Access::Write).await?;
    state
        .admin_org_domains()
        .delete(&org, domain_id(&id)?, auth.actor(), &ctx)
        .await?;
    Ok(no_content())
}

/// Check the claim's DNS TXT record now. Answers 200 with `status`: `verified`, or `pending`
/// with the same body whatever the cause (no record, wrong value, DNS failure). 409 when another
/// organization of the tenant has already verified the domain.
#[utoipa::path(
    post,
    path = "/api/admin/v1/tenants/{slug}/organizations/{org}/domains/{id}/verify",
    tag = "organizations",
    operation_id = "verifyOrganizationDomain",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("org" = String, Path, description = "Organization id or slug"),
        ("id" = uuid::Uuid, Path, description = "Domain claim id"),
    ),
    responses(
        (status = 200, description = "The claim after the check (`status` verified or pending)", body = DomainView),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope, or an org admin token of another organization", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant, organization or claim (or another organization's claim)", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "Another organization of the tenant has already verified this domain", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:organizations:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn verify_org_domain(
    OrgAdminAuth(auth): OrgAdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path((slug, org, id)): Path<(String, String, String)>,
) -> AdminResult<Response> {
    let (_, org) = org_for(&state, &auth, &slug, &org, Access::Write).await?;
    let claim = match state
        .admin_org_domains()
        .verify(&org, domain_id(&id)?, auth.actor(), &ctx)
        .await?
    {
        VerifyOutcome::Verified(d) | VerifyOutcome::Pending(d) => d,
    };
    Ok(json(StatusCode::OK, &DomainView::from(claim)))
}
