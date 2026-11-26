//! Organization administration (ORG-02, ORG-03): [`OrgService`].
//!
//! - **Organizations**: create, read (by id or slug), list, update and delete the organizations of
//!   an application tenant. Organizations never exist in the `system` tenant (`Validation`).
//! - **Members**: a tenant administrator adds members directly ([`OrgService::add_member`]); an
//!   org admin only through invitations (the admin API enforces the principal). Removing a member
//!   is one storage intent that also drops the member's org role assignments and revokes their
//!   token families bound to the org ([`crate::ports::OrgRepo::remove_member`]).
//! - **Org roles** (decision Q5, hybrid): an org owns roles (name unique per org); org-owned roles
//!   of this org and tenant roles can be assigned to a member **within** the org. Eligibility is
//!   decided by one function, [`check_assignable`], used by assignments, default roles and
//!   invitations: an org-owned role of another org is `NotFound`, a role carrying an `admin:*`
//!   permission is refused (`Validation`). `org:admin` is a valid org-role permission.
//! - **Lockout** (decision Q1): an org admin ([`OrgActor::OrgAdmin`]) may not remove, unassign or
//!   demote (role edit dropping `org:admin`, role delete) the last active holder of `org:admin` in
//!   the org (`Conflict`). A tenant administrator ([`OrgActor::TenantAdmin`]) skips the guard: that
//!   is the documented recovery path. Like the tenant last-administrator guard, the check reads
//!   and then writes, so two concurrent demotions of the last two org admins can both pass; a
//!   tenant administrator restores access.
//! - **Org-admin principal**: [`OrgService::org_admin_principal`] decides whether an access token
//!   of the org's own tenant may act as that org's admin (re-checked on every request).
//!
//! Every change is audited in the org's tenant: `organization_created|updated|deleted` (target =
//! org id), `org_member_added|removed` and `org_role_assigned|unassigned` (target = user id),
//! `role_created|updated|deleted` for org-owned roles (target = role id); all with the org in the
//! details ([`AuditDetails::org`]). Failed calls record nothing.

use std::collections::BTreeSet;
use std::sync::Arc;

use crate::clock::Clock;
use crate::error::CoreError;
use crate::model::{
    AuditAction, AuditActor, AuditDetails, AuditOutcome, MAX_ORG_DISPLAY_NAME, MfaPolicy,
    NewMembership, NewOrganization, NewRole, OrgId, OrgMembership, OrgSettings, Organization,
    OrganizationUpdate, Page, PageRequest, RequestContext, Role, RoleId, RoleUpdate,
    SYSTEM_TENANT_SLUG, Tenant, TenantId, UserId, UserStatus, normalize_permissions,
    validate_org_slug, validate_role_name,
};
use crate::ports::{AddMemberOutcome, Storage, StorageError};
use crate::service::admin_scope::{ORG_ADMIN_SCOPE, is_reserved_admin_token};
use crate::service::audit::AuditService;
use crate::service::role::{RoleInput, validate_description};
use crate::service::tenant::admin_page;
use crate::service::userinfo::AccessTokenClaims;

/// The permission that makes a member an org admin (the same string as the scope).
pub const ORG_ADMIN_PERMISSION: &str = ORG_ADMIN_SCOPE;

/// Most default roles an organization may carry.
pub const MAX_DEFAULT_ROLES: usize = 20;

/// Page size of the member walk of the lockout guard.
const GUARD_PAGE: u32 = 200;

// ---------------------------------------------------------------------------------------------
// Actors
// ---------------------------------------------------------------------------------------------

/// Who performs an organization administration call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrgActor {
    /// A tenant administrator (system-tenant admin token). Skips the org-admin lockout guard.
    TenantAdmin(AuditActor),
    /// An org admin of the org being changed (a user of the org's tenant).
    OrgAdmin(UserId),
}

impl OrgActor {
    /// The audit actor: the administrator as given, or the org admin as a user.
    pub fn audit_actor(&self) -> AuditActor {
        match self {
            Self::TenantAdmin(a) => a.clone(),
            Self::OrgAdmin(user) => AuditActor::user(user),
        }
    }

    /// Whether the lockout guard applies.
    pub fn is_org_admin(&self) -> bool {
        matches!(self, Self::OrgAdmin(_))
    }
}

// ---------------------------------------------------------------------------------------------
// Pure rules
// ---------------------------------------------------------------------------------------------

/// Organizations never exist in the system tenant.
pub fn refuse_system_tenant(tenant: &Tenant) -> Result<(), CoreError> {
    if tenant.slug == SYSTEM_TENANT_SLUG {
        Err(CoreError::Validation {
            field: "tenant",
            message: "organizations do not exist in the system tenant".to_owned(),
        })
    } else {
        Ok(())
    }
}

/// Validates and trims an organization display name (1-200 characters, no control characters).
pub fn validate_display_name(raw: &str) -> Result<String, CoreError> {
    let d = raw.trim();
    if d.is_empty() || d.chars().count() > MAX_ORG_DISPLAY_NAME || d.chars().any(char::is_control) {
        return Err(CoreError::Validation {
            field: "display_name",
            message: format!(
                "must be 1-{MAX_ORG_DISPLAY_NAME} characters without control characters"
            ),
        });
    }
    Ok(d.to_owned())
}

/// Integrator metadata must be a JSON object.
pub fn validate_metadata(v: &serde_json::Value) -> Result<(), CoreError> {
    if v.is_object() {
        Ok(())
    } else {
        Err(CoreError::Validation {
            field: "metadata",
            message: "must be a JSON object".to_owned(),
        })
    }
}

/// Refuses permissions in the reserved admin namespace (`admin`, `admin:*`): organizations and
/// their roles can never grant management API access.
pub fn refuse_admin_permissions(permissions: &[String]) -> Result<(), CoreError> {
    if permissions.iter().any(|p| is_reserved_admin_token(p)) {
        Err(CoreError::Validation {
            field: "permissions",
            message: "admin permissions cannot be used in an organization".to_owned(),
        })
    } else {
        Ok(())
    }
}

/// Whether `role` grants `org:admin`.
pub fn grants_org_admin(role: &Role) -> bool {
    role.permissions.iter().any(|p| p == ORG_ADMIN_PERMISSION)
}

/// The single role-eligibility rule for an org (assignments, default roles, invitations): the
/// role is a tenant role or owned by `org` (an org-owned role of another org is `NotFound`, so
/// its existence is not revealed), and it carries no `admin:*` permission (`Validation`).
pub fn check_assignable(org: OrgId, role: &Role) -> Result<(), CoreError> {
    match role.org_id {
        None => {}
        Some(owner) if owner == org => {}
        Some(_) => return Err(CoreError::NotFound),
    }
    if role.permissions.iter().any(|p| is_reserved_admin_token(p)) {
        return Err(CoreError::Validation {
            field: "role",
            message: "a role carrying admin permissions cannot be assigned in an organization"
                .to_owned(),
        });
    }
    Ok(())
}

/// A change the lockout guard evaluates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockoutChange {
    /// The member leaves the org.
    RemoveMember(UserId),
    /// The member loses one role in the org.
    Unassign(RoleId, UserId),
    /// The role stops granting `org:admin` (edited or deleted) for every holder.
    RoleLosesAdmin(RoleId),
}

impl LockoutChange {
    fn affects_single_user(self) -> bool {
        !matches!(self, Self::RoleLosesAdmin(_))
    }
}

/// Whether `member` still holds `org:admin` through `roles` (its roles in the org) after `change`.
pub fn holds_org_admin_after(member: UserId, roles: &[Role], change: LockoutChange) -> bool {
    match change {
        LockoutChange::RemoveMember(u) if u == member => false,
        LockoutChange::RemoveMember(_) => roles.iter().any(grants_org_admin),
        LockoutChange::Unassign(r, u) => roles
            .iter()
            .filter(|role| !(u == member && role.id == r))
            .any(grants_org_admin),
        LockoutChange::RoleLosesAdmin(r) => roles
            .iter()
            .filter(|role| role.id != r)
            .any(grants_org_admin),
    }
}

/// Matches `key` against an org id (canonical UUID) first, then the exact slug (the same order
/// as the `organization` authorization parameter).
fn parse_org_key(key: &str) -> Option<OrgId> {
    uuid::Uuid::parse_str(key)
        .ok()
        .filter(|u| u.hyphenated().to_string() == key)
        .map(OrgId)
}

fn org_conflict(e: StorageError) -> CoreError {
    match e {
        StorageError::Conflict(_) => {
            CoreError::Conflict("an organization with this slug already exists".to_owned())
        }
        other => other.into(),
    }
}

fn role_conflict(e: StorageError) -> CoreError {
    match e {
        StorageError::Conflict(_) => {
            CoreError::Conflict("a role with this name already exists in the organization".into())
        }
        other => other.into(),
    }
}

fn lockout() -> CoreError {
    CoreError::Conflict("the organization would have no org admin".to_owned())
}

fn invalid_token() -> CoreError {
    CoreError::InvalidToken("the access token is invalid or expired".to_owned())
}

fn not_org_admin() -> CoreError {
    CoreError::InsufficientScope(
        "this token does not grant administration of this organization".to_owned(),
    )
}

// ---------------------------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------------------------

/// An organization to create.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgInput {
    pub slug: String,
    pub display_name: String,
    pub mfa_policy: Option<MfaPolicy>,
    /// Free-form JSON object; `None` = `{}`.
    pub metadata: Option<serde_json::Value>,
}

/// A partial organization update; `None` leaves a field unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OrgPatch {
    pub slug: Option<String>,
    pub display_name: Option<String>,
    /// `Some(None)` removes the org's MFA requirement.
    pub mfa_policy: Option<Option<MfaPolicy>>,
    pub metadata: Option<serde_json::Value>,
    /// Roles given (in this org) to members created by just-in-time provisioning; each must
    /// pass [`check_assignable`].
    pub default_role_ids: Option<Vec<RoleId>>,
}

/// One member with the user's email (for administration views).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberInfo {
    pub membership: OrgMembership,
    /// `None` if the user vanished between the two reads.
    pub email: Option<String>,
}

/// Which role a name refers to when an org-owned role and a tenant role share it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleScope {
    Org,
    Tenant,
}

// ---------------------------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------------------------

/// Organization, member and org-role administration.
#[derive(Clone)]
pub struct OrgService {
    pub storage: Arc<dyn Storage>,
    pub clock: Arc<dyn Clock>,
}

impl OrgService {
    #[expect(clippy::too_many_arguments)]
    async fn record(
        &self,
        tenant: TenantId,
        actor: &OrgActor,
        action: AuditAction,
        target: String,
        org: &Organization,
        extra: Option<AuditDetails>,
        ctx: &RequestContext,
    ) -> Result<(), CoreError> {
        let mut details = AuditDetails::org(org.id, &org.slug);
        if let Some(e) = extra {
            details = details.with(e);
        }
        AuditService {
            storage: self.storage.clone(),
            clock: self.clock.clone(),
        }
        .record(
            tenant,
            actor.audit_actor(),
            action,
            Some(target),
            AuditOutcome::Success,
            ctx,
            details,
        )
        .await
    }

    // ---- organizations ----

    /// Creates an organization (`Validation` in the system tenant or for a bad slug, display name
    /// or metadata; `Conflict` for a slug already used in the tenant).
    pub async fn create(
        &self,
        tenant: &Tenant,
        input: OrgInput,
        actor: &OrgActor,
        ctx: &RequestContext,
    ) -> Result<Organization, CoreError> {
        refuse_system_tenant(tenant)?;
        validate_org_slug(&input.slug)?;
        let display_name = validate_display_name(&input.display_name)?;
        let metadata = input
            .metadata
            .unwrap_or_else(|| serde_json::Value::Object(serde_json::Map::new()));
        validate_metadata(&metadata)?;
        let org = self
            .storage
            .organizations()
            .create(
                tenant.id,
                &NewOrganization {
                    id: OrgId::new_v7(),
                    slug: input.slug,
                    display_name,
                    mfa_policy: input.mfa_policy,
                    settings: OrgSettings::default(),
                    metadata,
                    created_at: self.clock.now(),
                },
            )
            .await
            .map_err(org_conflict)?;
        self.record(
            tenant.id,
            actor,
            AuditAction::OrganizationCreated,
            org.id.to_string(),
            &org,
            None,
            ctx,
        )
        .await?;
        Ok(org)
    }

    /// An organization by id (canonical UUID) or slug; `NotFound` otherwise (also for an org of
    /// another tenant).
    pub async fn get(&self, tenant: TenantId, key: &str) -> Result<Organization, CoreError> {
        let orgs = self.storage.organizations();
        if let Some(id) = parse_org_key(key)
            && let Some(org) = orgs.get(tenant, id).await?
        {
            return Ok(org);
        }
        orgs.get_by_slug(tenant, key)
            .await?
            .ok_or(CoreError::NotFound)
    }

    /// One page of the tenant's organizations (id order).
    pub async fn list(
        &self,
        tenant: TenantId,
        page: PageRequest,
    ) -> Result<Page<Organization>, CoreError> {
        Ok(self
            .storage
            .organizations()
            .list(tenant, admin_page(page))
            .await?)
    }

    /// Updates an organization. Default roles are checked with [`check_assignable`].
    pub async fn update(
        &self,
        tenant: &Tenant,
        org: &Organization,
        patch: OrgPatch,
        actor: &OrgActor,
        ctx: &RequestContext,
    ) -> Result<Organization, CoreError> {
        if let Some(s) = &patch.slug {
            validate_org_slug(s)?;
        }
        let display_name = patch
            .display_name
            .as_deref()
            .map(validate_display_name)
            .transpose()?;
        if let Some(m) = &patch.metadata {
            validate_metadata(m)?;
        }
        let settings = match patch.default_role_ids {
            None => None,
            Some(ids) => {
                let ids: Vec<RoleId> = ids
                    .into_iter()
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect();
                if ids.len() > MAX_DEFAULT_ROLES {
                    return Err(CoreError::Validation {
                        field: "default_role_ids",
                        message: format!("at most {MAX_DEFAULT_ROLES} roles"),
                    });
                }
                for id in &ids {
                    self.assignable_role_by_id(tenant.id, org.id, *id).await?;
                }
                let mut settings = org.settings.clone();
                settings.default_role_ids = ids;
                Some(settings)
            }
        };
        let update = OrganizationUpdate {
            slug: patch.slug,
            display_name,
            mfa_policy: patch.mfa_policy,
            settings,
            metadata: patch.metadata,
        };
        let updated = self
            .storage
            .organizations()
            .update(tenant.id, org.id, &update, self.clock.now())
            .await
            .map_err(org_conflict)?
            .ok_or(CoreError::NotFound)?;
        self.record(
            tenant.id,
            actor,
            AuditAction::OrganizationUpdated,
            updated.id.to_string(),
            &updated,
            None,
            ctx,
        )
        .await?;
        Ok(updated)
    }

    /// Deletes an organization with everything it owns (one storage intent; its token families
    /// are revoked).
    pub async fn delete(
        &self,
        tenant: &Tenant,
        org: &Organization,
        actor: &OrgActor,
        ctx: &RequestContext,
    ) -> Result<(), CoreError> {
        let deleted = self
            .storage
            .organizations()
            .delete(tenant.id, org.id, self.clock.now())
            .await?;
        if !deleted {
            return Err(CoreError::NotFound);
        }
        self.record(
            tenant.id,
            actor,
            AuditAction::OrganizationDeleted,
            org.id.to_string(),
            org,
            None,
            ctx,
        )
        .await
    }

    // ---- members ----

    /// Adds `user` to the org with `role_ids` assigned in the org (each checked with
    /// [`check_assignable`]). Idempotent: an existing member is kept unchanged and nothing is
    /// audited. `NotFound` for a user of another tenant. Returns whether the member was added.
    pub async fn add_member(
        &self,
        tenant: &Tenant,
        org: &Organization,
        user: UserId,
        role_ids: Vec<RoleId>,
        actor: &OrgActor,
        ctx: &RequestContext,
    ) -> Result<bool, CoreError> {
        let role_ids: Vec<RoleId> = role_ids
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        for id in &role_ids {
            self.assignable_role_by_id(tenant.id, org.id, *id).await?;
        }
        let outcome = self
            .storage
            .organizations()
            .add_member(
                tenant.id,
                &NewMembership {
                    org_id: org.id,
                    user_id: user,
                    role_ids: role_ids.clone(),
                    created_at: self.clock.now(),
                },
            )
            .await?;
        match outcome {
            AddMemberOutcome::Added => {
                self.record(
                    tenant.id,
                    actor,
                    AuditAction::OrgMemberAdded,
                    user.to_string(),
                    org,
                    None,
                    ctx,
                )
                .await?;
                Ok(true)
            }
            AddMemberOutcome::AlreadyMember => Ok(false),
            AddMemberOutcome::NotFound => Err(CoreError::NotFound),
        }
    }

    /// Removes a member: one storage intent deletes the membership and the member's org role
    /// assignments and revokes their token families bound to the org. An org admin may not
    /// remove the last org admin (`Conflict`). `NotFound` if `user` is not a member.
    pub async fn remove_member(
        &self,
        tenant: &Tenant,
        org: &Organization,
        user: UserId,
        actor: &OrgActor,
        ctx: &RequestContext,
    ) -> Result<(), CoreError> {
        if !self
            .storage
            .organizations()
            .is_member(tenant.id, org.id, user)
            .await?
        {
            return Err(CoreError::NotFound);
        }
        if actor.is_org_admin() {
            self.guard_lockout(tenant.id, org.id, LockoutChange::RemoveMember(user))
                .await?;
        }
        let removed = self
            .storage
            .organizations()
            .remove_member(tenant.id, org.id, user, self.clock.now())
            .await?;
        if !removed {
            return Err(CoreError::NotFound);
        }
        self.record(
            tenant.id,
            actor,
            AuditAction::OrgMemberRemoved,
            user.to_string(),
            org,
            None,
            ctx,
        )
        .await
    }

    /// One page of members (user id order) with their emails.
    pub async fn list_members(
        &self,
        tenant: TenantId,
        org: OrgId,
        page: PageRequest,
    ) -> Result<Page<MemberInfo>, CoreError> {
        let page = self
            .storage
            .organizations()
            .list_members(tenant, org, admin_page(page))
            .await?;
        let mut items = Vec::with_capacity(page.items.len());
        for membership in page.items {
            let email = self
                .storage
                .users()
                .get(tenant, membership.user_id)
                .await?
                .map(|u| u.email);
            items.push(MemberInfo { membership, email });
        }
        Ok(Page {
            items,
            next_cursor: page.next_cursor,
        })
    }

    /// The roles `user` holds in the org (`NotFound` for a non-member).
    pub async fn member_roles(
        &self,
        tenant: TenantId,
        org: OrgId,
        user: UserId,
    ) -> Result<Vec<Role>, CoreError> {
        if !self
            .storage
            .organizations()
            .is_member(tenant, org, user)
            .await?
        {
            return Err(CoreError::NotFound);
        }
        Ok(self
            .storage
            .roles()
            .roles_for_user_in_org(tenant, user, org)
            .await?)
    }

    // ---- org roles ----

    /// The roles owned by the org, in name order.
    pub async fn list_roles(&self, tenant: TenantId, org: OrgId) -> Result<Vec<Role>, CoreError> {
        Ok(self.storage.roles().list_org_roles(tenant, org).await?)
    }

    /// An org-owned role by name.
    pub async fn get_role(
        &self,
        tenant: TenantId,
        org: OrgId,
        name: &str,
    ) -> Result<Role, CoreError> {
        self.list_roles(tenant, org)
            .await?
            .into_iter()
            .find(|r| r.name == name)
            .ok_or(CoreError::NotFound)
    }

    /// The role a name refers to within the org: the org-owned role, or the tenant role.
    /// Without `scope` the org-owned role wins and the tenant role is the fallback.
    pub async fn resolve_role(
        &self,
        tenant: TenantId,
        org: OrgId,
        name: &str,
        scope: Option<RoleScope>,
    ) -> Result<Role, CoreError> {
        if scope != Some(RoleScope::Tenant) {
            match self.get_role(tenant, org, name).await {
                Ok(r) => return Ok(r),
                Err(CoreError::NotFound) if scope.is_none() => {}
                Err(e) => return Err(e),
            }
        }
        self.storage
            .roles()
            .get_by_name(tenant, name)
            .await?
            .ok_or(CoreError::NotFound)
    }

    /// A role by id that may be assigned in the org ([`check_assignable`]).
    pub async fn assignable_role_by_id(
        &self,
        tenant: TenantId,
        org: OrgId,
        id: RoleId,
    ) -> Result<Role, CoreError> {
        let role = self
            .storage
            .roles()
            .get(tenant, id)
            .await?
            .ok_or(CoreError::NotFound)?;
        check_assignable(org, &role)?;
        Ok(role)
    }

    /// Creates an org-owned role (`admin:*` permissions refused).
    pub async fn create_role(
        &self,
        tenant: &Tenant,
        org: &Organization,
        input: RoleInput,
        actor: &OrgActor,
        ctx: &RequestContext,
    ) -> Result<Role, CoreError> {
        validate_role_name(&input.name)?;
        let description = validate_description(&input.description)?;
        let permissions = normalize_permissions(&input.permissions)?;
        refuse_admin_permissions(&permissions)?;
        let role = self
            .storage
            .roles()
            .create(
                tenant.id,
                &NewRole {
                    id: RoleId::new_v7(),
                    org_id: Some(org.id),
                    name: input.name,
                    description,
                    permissions,
                    created_at: self.clock.now(),
                },
            )
            .await
            .map_err(role_conflict)?;
        self.record(
            tenant.id,
            actor,
            AuditAction::RoleCreated,
            role.id.to_string(),
            org,
            Some(AuditDetails::role(&role.name)),
            ctx,
        )
        .await?;
        Ok(role)
    }

    /// Updates an org-owned role (`admin:*` permissions refused). An org admin may not drop
    /// `org:admin` from the role when that leaves the org without an org admin (`Conflict`).
    pub async fn update_role(
        &self,
        tenant: &Tenant,
        org: &Organization,
        name: &str,
        patch: RoleUpdate,
        actor: &OrgActor,
        ctx: &RequestContext,
    ) -> Result<Role, CoreError> {
        let current = self.get_role(tenant.id, org.id, name).await?;
        if let Some(n) = &patch.name {
            validate_role_name(n)?;
        }
        let update = RoleUpdate {
            name: patch.name,
            description: patch
                .description
                .as_deref()
                .map(validate_description)
                .transpose()?,
            permissions: patch
                .permissions
                .as_deref()
                .map(normalize_permissions)
                .transpose()?,
        };
        if let Some(p) = &update.permissions {
            refuse_admin_permissions(p)?;
            let keeps = p.iter().any(|x| x == ORG_ADMIN_PERMISSION);
            if actor.is_org_admin() && grants_org_admin(&current) && !keeps {
                self.guard_lockout(tenant.id, org.id, LockoutChange::RoleLosesAdmin(current.id))
                    .await?;
            }
        }
        let role = self
            .storage
            .roles()
            .update(tenant.id, current.id, &update, self.clock.now())
            .await
            .map_err(role_conflict)?
            .ok_or(CoreError::NotFound)?;
        self.record(
            tenant.id,
            actor,
            AuditAction::RoleUpdated,
            role.id.to_string(),
            org,
            Some(AuditDetails::role(&role.name)),
            ctx,
        )
        .await?;
        Ok(role)
    }

    /// Deletes an org-owned role with its assignments. An org admin may not delete an
    /// `org:admin` role when that leaves the org without an org admin (`Conflict`).
    pub async fn delete_role(
        &self,
        tenant: &Tenant,
        org: &Organization,
        name: &str,
        actor: &OrgActor,
        ctx: &RequestContext,
    ) -> Result<(), CoreError> {
        let current = self.get_role(tenant.id, org.id, name).await?;
        if actor.is_org_admin() && grants_org_admin(&current) {
            self.guard_lockout(tenant.id, org.id, LockoutChange::RoleLosesAdmin(current.id))
                .await?;
        }
        if !self.storage.roles().delete(tenant.id, current.id).await? {
            return Err(CoreError::NotFound);
        }
        self.record(
            tenant.id,
            actor,
            AuditAction::RoleDeleted,
            current.id.to_string(),
            org,
            Some(AuditDetails::role(&current.name)),
            ctx,
        )
        .await
    }

    // ---- assignments ----

    /// Assigns `role` to the member `user` within the org (idempotent). The role must pass
    /// [`check_assignable`]; a non-member is `NotFound`.
    pub async fn assign(
        &self,
        tenant: &Tenant,
        org: &Organization,
        user: UserId,
        role: &Role,
        actor: &OrgActor,
        ctx: &RequestContext,
    ) -> Result<(), CoreError> {
        check_assignable(org.id, role)?;
        if !self
            .storage
            .organizations()
            .is_member(tenant.id, org.id, user)
            .await?
        {
            return Err(CoreError::NotFound);
        }
        let ok = self
            .storage
            .roles()
            .assign_in_org(tenant.id, role.id, user, org.id, self.clock.now())
            .await?;
        if !ok {
            return Err(CoreError::NotFound);
        }
        self.record(
            tenant.id,
            actor,
            AuditAction::OrgRoleAssigned,
            user.to_string(),
            org,
            Some(AuditDetails::role(&role.name)),
            ctx,
        )
        .await
    }

    /// Removes `role` from `user` within the org. An org admin may not remove the last org
    /// admin's `org:admin` (`Conflict`). `NotFound` if the user does not hold it in the org.
    pub async fn unassign(
        &self,
        tenant: &Tenant,
        org: &Organization,
        user: UserId,
        role: &Role,
        actor: &OrgActor,
        ctx: &RequestContext,
    ) -> Result<(), CoreError> {
        if actor.is_org_admin() && grants_org_admin(role) {
            self.guard_lockout(tenant.id, org.id, LockoutChange::Unassign(role.id, user))
                .await?;
        }
        let removed = self
            .storage
            .roles()
            .unassign_in_org(tenant.id, role.id, user, org.id)
            .await?;
        if !removed {
            return Err(CoreError::NotFound);
        }
        self.record(
            tenant.id,
            actor,
            AuditAction::OrgRoleUnassigned,
            user.to_string(),
            org,
            Some(AuditDetails::role(&role.name)),
            ctx,
        )
        .await
    }

    // ---- lockout guard ----

    /// Refuses `change` (`Conflict`) when no active member would hold `org:admin` afterwards.
    async fn guard_lockout(
        &self,
        tenant: TenantId,
        org: OrgId,
        change: LockoutChange,
    ) -> Result<(), CoreError> {
        let roles = self.storage.roles();
        // A change to one user leaves at least one of two or more holders.
        if change.affects_single_user()
            && roles
                .org_holders_of_permission(tenant, org, ORG_ADMIN_PERMISSION)
                .await?
                >= 2
        {
            return Ok(());
        }
        let mut after = None;
        loop {
            let page = self
                .storage
                .organizations()
                .list_members(
                    tenant,
                    org,
                    PageRequest {
                        after,
                        limit: GUARD_PAGE,
                    },
                )
                .await?;
            for m in &page.items {
                let held = roles.roles_for_user_in_org(tenant, m.user_id, org).await?;
                if holds_org_admin_after(m.user_id, &held, change)
                    && matches!(
                        self.storage.users().get(tenant, m.user_id).await?,
                        Some(u) if u.status == UserStatus::Active
                    )
                {
                    return Ok(());
                }
            }
            match page.next_cursor {
                Some(next) => after = Some(next),
                None => return Err(lockout()),
            }
        }
    }

    // ---- org-admin principal (decision Q1) ----

    /// Decides whether an access token of `tenant` (already verified against the tenant's issuer
    /// by [`crate::service::userinfo::AccessTokenVerifier`], audience already checked by the
    /// caller) may administer the org named `org_key`. Re-checked on every request:
    ///
    /// - the token carries the `org:admin` scope and its `org_id` claim names this org
    ///   (`InsufficientScope` otherwise, also for an unknown org so other orgs are not revealed);
    /// - it is a user token whose live family is bound to this org and to the token's user
    ///   (`InvalidToken` otherwise);
    /// - the user is active, still a member, and still holds `org:admin` in the org through
    ///   `roles_for_user_in_org` (`InsufficientScope` otherwise).
    pub async fn org_admin_principal(
        &self,
        tenant: &Tenant,
        org_key: &str,
        claims: &AccessTokenClaims,
        org_id_claim: Option<&str>,
    ) -> Result<(Organization, UserId), CoreError> {
        if tenant.slug == SYSTEM_TENANT_SLUG || !claims.scope.contains(ORG_ADMIN_SCOPE) {
            return Err(not_org_admin());
        }
        let org = match self.get(tenant.id, org_key).await {
            Ok(o) => o,
            Err(CoreError::NotFound) => return Err(not_org_admin()),
            Err(e) => return Err(e),
        };
        if org_id_claim != Some(org.id.to_string().as_str()) {
            return Err(not_org_admin());
        }
        let fid = claims.family_id.ok_or_else(invalid_token)?;
        let family = self
            .storage
            .grants()
            .get_family(tenant.id, fid)
            .await?
            .ok_or_else(invalid_token)?;
        let user = family.user_id.ok_or_else(invalid_token)?;
        if family.revoked_at.is_some()
            || family.client_id != claims.client_id
            || family.org_id != Some(org.id)
            || user.to_string() != claims.sub
        {
            return Err(invalid_token());
        }
        match self.storage.users().get(tenant.id, user).await? {
            Some(u) if u.status == UserStatus::Active => {}
            _ => return Err(invalid_token()),
        }
        if !self
            .storage
            .organizations()
            .is_member(tenant.id, org.id, user)
            .await?
        {
            return Err(not_org_admin());
        }
        let held = self
            .storage
            .roles()
            .roles_for_user_in_org(tenant.id, user, org.id)
            .await?;
        if !held.iter().any(grants_org_admin) {
            return Err(not_org_admin());
        }
        Ok((org, user))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::TenantSettings;
    use time::OffsetDateTime;

    fn role(id: RoleId, org: Option<OrgId>, perms: &[&str]) -> Role {
        Role {
            id,
            tenant_id: TenantId::new_v7(),
            org_id: org,
            name: "r".into(),
            description: String::new(),
            permissions: perms.iter().map(|p| (*p).to_owned()).collect(),
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    fn tenant(slug: &str) -> Tenant {
        Tenant {
            id: TenantId::new_v7(),
            slug: slug.into(),
            display_name: slug.into(),
            host: None,
            settings: TenantSettings::default(),
            created_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn system_tenant_is_refused() {
        assert!(matches!(
            refuse_system_tenant(&tenant(SYSTEM_TENANT_SLUG)),
            Err(CoreError::Validation {
                field: "tenant",
                ..
            })
        ));
        assert!(refuse_system_tenant(&tenant("acme")).is_ok());
    }

    #[test]
    fn display_names_are_trimmed_and_bounded() {
        assert_eq!(validate_display_name("  Acme  ").unwrap(), "Acme");
        assert!(validate_display_name("   ").is_err());
        assert!(validate_display_name("a\u{7}b").is_err());
        assert!(validate_display_name(&"a".repeat(MAX_ORG_DISPLAY_NAME)).is_ok());
        assert!(validate_display_name(&"a".repeat(MAX_ORG_DISPLAY_NAME + 1)).is_err());
    }

    #[test]
    fn metadata_must_be_an_object() {
        assert!(validate_metadata(&serde_json::json!({"a": 1})).is_ok());
        for bad in [
            serde_json::json!([]),
            serde_json::json!("x"),
            serde_json::Value::Null,
        ] {
            assert!(validate_metadata(&bad).is_err());
        }
    }

    #[test]
    fn admin_permissions_are_refused_but_org_admin_is_allowed() {
        assert!(refuse_admin_permissions(&["org:admin".into(), "docs:read".into()]).is_ok());
        for bad in ["admin", "admin:write", "admin:users:read", "admin:anything"] {
            assert!(
                refuse_admin_permissions(&[bad.to_owned()]).is_err(),
                "{bad} must be refused"
            );
        }
    }

    #[test]
    fn assignability_is_one_rule() {
        let org = OrgId::new_v7();
        let other = OrgId::new_v7();
        assert!(check_assignable(org, &role(RoleId::new_v7(), None, &["docs:read"])).is_ok());
        assert!(check_assignable(org, &role(RoleId::new_v7(), Some(org), &["org:admin"])).is_ok());
        assert!(matches!(
            check_assignable(org, &role(RoleId::new_v7(), Some(other), &[])),
            Err(CoreError::NotFound)
        ));
        assert!(matches!(
            check_assignable(org, &role(RoleId::new_v7(), None, &["admin:write"])),
            Err(CoreError::Validation { field: "role", .. })
        ));
    }

    #[test]
    fn lockout_evaluation() {
        let admin = RoleId::new_v7();
        let plain = RoleId::new_v7();
        let other_admin = RoleId::new_v7();
        let me = UserId::new_v7();
        let you = UserId::new_v7();
        let only_admin = [role(admin, None, &["org:admin"])];
        let both = [
            role(admin, None, &["org:admin"]),
            role(other_admin, None, &["org:admin", "x"]),
        ];
        let none = [role(plain, None, &["x"])];

        assert!(!holds_org_admin_after(
            me,
            &only_admin,
            LockoutChange::RemoveMember(me)
        ));
        assert!(holds_org_admin_after(
            me,
            &only_admin,
            LockoutChange::RemoveMember(you)
        ));
        assert!(!holds_org_admin_after(
            me,
            &only_admin,
            LockoutChange::Unassign(admin, me)
        ));
        assert!(holds_org_admin_after(
            me,
            &only_admin,
            LockoutChange::Unassign(admin, you)
        ));
        assert!(holds_org_admin_after(
            me,
            &both,
            LockoutChange::Unassign(admin, me)
        ));
        assert!(!holds_org_admin_after(
            me,
            &only_admin,
            LockoutChange::RoleLosesAdmin(admin)
        ));
        assert!(holds_org_admin_after(
            me,
            &both,
            LockoutChange::RoleLosesAdmin(admin)
        ));
        assert!(!holds_org_admin_after(
            me,
            &none,
            LockoutChange::RemoveMember(you)
        ));
    }

    #[test]
    fn org_keys_are_canonical_uuids() {
        let id = OrgId::new_v7();
        assert_eq!(parse_org_key(&id.to_string()), Some(id));
        assert_eq!(parse_org_key(&id.to_string().to_uppercase()), None);
        assert_eq!(parse_org_key("acme"), None);
    }

    #[test]
    fn actors() {
        let u = UserId::new_v7();
        assert!(OrgActor::OrgAdmin(u).is_org_admin());
        assert_eq!(OrgActor::OrgAdmin(u).audit_actor(), AuditActor::user(u));
        let a = OrgActor::TenantAdmin(AuditActor::admin("c"));
        assert!(!a.is_org_admin());
        assert_eq!(a.audit_actor(), AuditActor::admin("c"));
    }
}
