//! Roles, permissions and role assignments (ORG-05), the claims they feed, and the guards that
//! keep the system tenant administrable.
//!
//! - [`RoleService`]: create, update, delete, list, assign and unassign roles of a tenant. Every
//!   change is audited in the role's tenant (`role_created`, `role_updated`, `role_deleted`,
//!   `role_assigned`, `role_unassigned`); failed calls record nothing.
//! - **System-tenant roles are admin API scopes** (decision Q3). A system user's console token
//!   carries an admin scope only when one of the user's roles grants it
//!   ([`effective_admin_scopes`], [`bound_admin_scope`]). Coverage is the single rule
//!   [`scope_covers`]: `admin:write` covers every admin scope (including `admin:users:export`),
//!   `admin:read` every read scope, `admin:{resource}:write` that resource's read scope. Roles
//!   of any other tenant never grant admin scopes, whatever their permission strings look like.
//! - **Last administrator**: in the system tenant, no unassignment, role deletion, role
//!   permission edit, user deletion or user block may leave zero active holders of
//!   `admin:write` ([`CoreError::LastAdministrator`]). The check reads the current holders and
//!   then writes, so two concurrent removals of the last two administrators can both pass; the
//!   operator escape hatch is `anvilid admin recover` (plan 05-17).
//! - **Escalation**: in the system tenant, a caller may only create, edit, assign or unassign a
//!   role whose admin-scope permissions its own token scopes cover ([`check_escalation`]).
//! - [`UserClaimSource`]: the per-issuance load of a user's roles and attributes for
//!   [`claims_mapping::mapped_claims`](crate::policy::claims_mapping::mapped_claims), and of the
//!   active organization's membership and org roles ([`OrgClaims`]); used by the token service
//!   (code exchange and every refresh), UserInfo and introspection.

use std::collections::BTreeSet;
use std::sync::Arc;

use serde_json::{Map, Value};

use crate::clock::Clock;
use crate::error::CoreError;
use crate::model::{
    AttributeDefinition, AuditAction, AuditActor, AuditDetails, AuditOutcome, NewRole, OrgClaims,
    OrgId, Page, PageRequest, RequestContext, Role, RoleId, RoleUpdate, SYSTEM_TENANT_SLUG, Scope,
    Tenant, TenantId, TokenTarget, User, UserId, UserStatus, normalize_permissions,
    validate_role_name,
};
use crate::policy::claims_mapping::{ClaimInputs, mapped_claims};
use crate::policy::org_claims::{bound_org_admin_scope, org_claims_json};
use crate::ports::{AttributeSchemaCheck, Storage, StorageError};
use crate::service::admin_scope::{ADMIN_WRITE, ALL_ADMIN_SCOPES, is_admin_scope, scope_covers};
use crate::service::audit::AuditService;
use crate::service::tenant::admin_page;

/// Longest role description, in characters.
pub const MAX_ROLE_DESCRIPTION_LEN: usize = 500;

/// Page size used when the guards walk role holders.
const GUARD_PAGE: u32 = 200;

// ---------------------------------------------------------------------------------------------
// Pure rules
// ---------------------------------------------------------------------------------------------

/// Every admin scope granted by `held` (non-admin strings grant nothing).
pub fn admin_scopes_covered_by<'a>(held: impl IntoIterator<Item = &'a str>) -> BTreeSet<String> {
    let held: Vec<&str> = held.into_iter().filter(|h| is_admin_scope(h)).collect();
    ALL_ADMIN_SCOPES
        .iter()
        .filter(|s| held.iter().any(|h| scope_covers(h, s)))
        .map(|s| (*s).to_owned())
        .collect()
}

/// The admin scopes a system-tenant user's roles grant (expanded, see
/// [`admin_scopes_covered_by`]). Roles of any other tenant grant none.
pub fn effective_admin_scopes(tenant: &Tenant, roles: &[Role]) -> BTreeSet<String> {
    if tenant.slug != SYSTEM_TENANT_SLUG {
        return BTreeSet::new();
    }
    admin_scopes_covered_by(
        roles
            .iter()
            .flat_map(|r| r.permissions.iter().map(String::as_str)),
    )
}

/// The scope a user token is issued with: non-admin scopes unchanged; admin scopes =
/// (what the requested scopes cover) ∩ `effective`, written with the fewest scope strings
/// (a scope covered by another kept scope is dropped). A user requesting `admin:write` whose
/// roles grant `admin:read` gets `admin:read`; a user without roles gets no admin scope.
pub fn bound_admin_scope(requested: &Scope, effective: &BTreeSet<String>) -> Scope {
    let requested_admin = admin_scopes_covered_by(requested.iter());
    let kept: Vec<&String> = requested_admin.intersection(effective).collect();
    let minimal = kept
        .iter()
        .filter(|s| !kept.iter().any(|t| t != *s && scope_covers(t, s)))
        .map(|s| (*s).clone());
    requested
        .iter()
        .filter(|s| !is_admin_scope(s))
        .map(str::to_owned)
        .chain(minimal)
        .collect()
}

/// Refuses (`InsufficientScope`) when `permissions` carry an admin scope that `caller` does not
/// cover. Only meaningful in the system tenant: elsewhere admin-shaped permissions are inert.
pub fn check_escalation(caller: &Scope, permissions: &[String]) -> Result<(), CoreError> {
    let covered = admin_scopes_covered_by(caller.iter());
    let missing: Vec<&str> = permissions
        .iter()
        .map(String::as_str)
        .filter(|p| is_admin_scope(p) && !covered.contains(*p))
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(CoreError::InsufficientScope(format!(
            "a role carrying {} needs a token holding that scope",
            missing.join(", ")
        )))
    }
}

/// Whether `role` grants `admin:write`.
fn grants_admin_write(role: &Role) -> bool {
    role.permissions.iter().any(|p| p == ADMIN_WRITE)
}

fn is_system(tenant: &Tenant) -> bool {
    tenant.slug == SYSTEM_TENANT_SLUG
}

pub(crate) fn validate_description(d: &str) -> Result<String, CoreError> {
    let d = d.trim();
    if d.chars().count() > MAX_ROLE_DESCRIPTION_LEN || d.chars().any(char::is_control) {
        return Err(CoreError::Validation {
            field: "description",
            message: format!(
                "must be at most {MAX_ROLE_DESCRIPTION_LEN} characters without control characters"
            ),
        });
    }
    Ok(d.to_owned())
}

fn map_conflict(e: StorageError) -> CoreError {
    match e {
        StorageError::Conflict(_) => {
            CoreError::Conflict("a role with this name already exists".to_owned())
        }
        other => other.into(),
    }
}

// ---------------------------------------------------------------------------------------------
// Claims
// ---------------------------------------------------------------------------------------------

/// A user's roles and attribute data, and the active organization's claims, loaded once per
/// issuance.
#[derive(Debug, Clone, Default)]
pub struct UserClaimSource {
    /// Tenant-wide roles (never assignments made inside an org).
    pub roles: Vec<Role>,
    role_names: Vec<String>,
    permissions: Vec<String>,
    attributes: Vec<AttributeDefinition>,
    values: Map<String, Value>,
    /// The active org's claims: `Some` only when an org was asked for and the user is still a
    /// member of it.
    pub org: Option<OrgClaims>,
    /// An org was asked for, but it no longer exists or the user is no longer a member.
    org_lost: bool,
}

impl UserClaimSource {
    /// Loads the user's tenant-wide roles and, when `with_attributes` and some attribute
    /// definition has a claim rule, the definitions and the user's values. With `active_org`
    /// (the org bound to the grant) it also checks the membership and loads the roles the user
    /// holds **in** that org ([`OrgClaims`]); a vanished org or membership leaves `org` empty
    /// and sets [`Self::lost_active_org`], which every caller turns into a refusal.
    pub async fn load(
        storage: &dyn Storage,
        tenant: TenantId,
        user: UserId,
        with_attributes: bool,
        active_org: Option<OrgId>,
    ) -> Result<Self, CoreError> {
        let roles = storage.roles().roles_for_user(tenant, user).await?;
        let role_names = roles.iter().map(|r| r.name.clone()).collect();
        let permissions = roles
            .iter()
            .flat_map(|r| r.permissions.iter().cloned())
            .collect();
        let (attributes, values) = if with_attributes {
            let defs: Vec<AttributeDefinition> = storage
                .attributes()
                .list(tenant)
                .await?
                .into_iter()
                .filter(|d| d.claim.is_some())
                .collect();
            if defs.is_empty() {
                (defs, Map::new())
            } else {
                let values = storage
                    .attributes()
                    .user_values(tenant, user)
                    .await?
                    .unwrap_or_default();
                (defs, values)
            }
        } else {
            (Vec::new(), Map::new())
        };
        let (org, org_lost) = match active_org {
            None => (None, false),
            Some(org_id) => load_org_claims(storage, tenant, user, org_id)
                .await?
                .map_or((None, true), |c| (Some(c), false)),
        };
        Ok(Self {
            roles,
            role_names,
            permissions,
            attributes,
            values,
            org,
            org_lost,
        })
    }

    /// Whether the grant's org is gone or the user left it: the grant must not be used.
    pub fn lost_active_org(&self) -> bool {
        self.org_lost
    }

    /// The org claims for one token ([`org_claims_json`]): empty without an active org.
    pub fn org_claims(
        &self,
        tenant: &Tenant,
        granted: &Scope,
        target: TokenTarget,
    ) -> Map<String, Value> {
        org_claims_json(self.org.as_ref(), &tenant.settings.claims, target, granted)
    }

    /// `granted` with `org:admin` kept only when the user's permissions in the active org
    /// include it ([`bound_org_admin_scope`]); never without an active org.
    pub fn bound_org_admin(&self, granted: &Scope) -> Scope {
        bound_org_admin_scope(granted, self.org.as_ref().map(|o| o.permissions.as_slice()))
    }

    /// The mapped claims for one token. Attribute claims need `check` (each value is validated
    /// against its current schema); without it they are omitted, never emitted unvalidated.
    pub fn claims(
        &self,
        tenant: &Tenant,
        granted: &Scope,
        target: TokenTarget,
        check: Option<&dyn AttributeSchemaCheck>,
    ) -> Map<String, Value> {
        let attributes: &[AttributeDefinition] = match check {
            Some(_) => &self.attributes,
            None => &[],
        };
        let is_valid = |def: &AttributeDefinition, v: &Value| {
            check.is_some_and(|c| c.validate(&def.schema, v).is_ok())
        };
        mapped_claims(
            &ClaimInputs {
                roles: &self.role_names,
                permissions: &self.permissions,
                attribute_values: &self.values,
                attributes,
            },
            &tenant.settings.claims,
            granted,
            target,
            &is_valid,
        )
    }

    /// The admin scopes this user's roles grant ([`effective_admin_scopes`]).
    pub fn effective_admin_scopes(&self, tenant: &Tenant) -> BTreeSet<String> {
        effective_admin_scopes(tenant, &self.roles)
    }
}

/// The org claims of `user` in `org`: `None` when the org does not exist (in this tenant) or the
/// user is not a member. Roles are the ones held in the org only
/// ([`RoleRepo::roles_for_user_in_org`](crate::ports::RoleRepo::roles_for_user_in_org)).
async fn load_org_claims(
    storage: &dyn Storage,
    tenant: TenantId,
    user: UserId,
    org_id: OrgId,
) -> Result<Option<OrgClaims>, CoreError> {
    let Some(org) = storage.organizations().get(tenant, org_id).await? else {
        return Ok(None);
    };
    if !storage
        .organizations()
        .is_member(tenant, org_id, user)
        .await?
    {
        return Ok(None);
    }
    let roles = storage
        .roles()
        .roles_for_user_in_org(tenant, user, org_id)
        .await?;
    Ok(Some(OrgClaims {
        org_id,
        org_slug: org.slug,
        roles: roles.iter().map(|r| r.name.clone()).collect(),
        permissions: roles
            .iter()
            .flat_map(|r| r.permissions.iter().cloned())
            .collect(),
    }))
}

// ---------------------------------------------------------------------------------------------
// Last-administrator guard (shared with UserService)
// ---------------------------------------------------------------------------------------------

/// Whether at least one active user other than `except_user` holds `admin:write` through a role
/// not in `except_roles`. Walks the holders of each other `admin:write` role and stops at
/// the first match.
async fn other_admin_exists(
    storage: &dyn Storage,
    tenant: TenantId,
    except_roles: &[RoleId],
    except_user: Option<UserId>,
    unassign: Option<(RoleId, UserId)>,
) -> Result<bool, CoreError> {
    for role in storage.roles().list(tenant).await? {
        if except_roles.contains(&role.id) || !grants_admin_write(&role) {
            continue;
        }
        let mut after = None;
        loop {
            let page = storage
                .roles()
                .users_with_role(
                    tenant,
                    role.id,
                    PageRequest {
                        after,
                        limit: GUARD_PAGE,
                    },
                )
                .await?;
            let found = page.items.iter().any(|u| {
                u.status == UserStatus::Active
                    && Some(u.id) != except_user
                    && unassign != Some((role.id, u.id))
            });
            if found {
                return Ok(true);
            }
            match page.next_cursor {
                Some(next) => after = Some(next),
                None => break,
            }
        }
    }
    Ok(false)
}

/// The last-administrator guard for removing or blocking `user`: refuses when `user` is in the
/// system tenant, is an active holder of `admin:write`, and no other active holder exists.
/// Used by `UserService::delete` and by `UserService::update` when it blocks a user.
pub async fn guard_user_removal(
    storage: &dyn Storage,
    tenant: TenantId,
    user: UserId,
) -> Result<(), CoreError> {
    let Some(t) = storage.tenants().get(tenant).await? else {
        return Ok(());
    };
    if t.slug != SYSTEM_TENANT_SLUG {
        return Ok(());
    }
    let active = matches!(
        storage.users().get(tenant, user).await?,
        Some(u) if u.status == UserStatus::Active
    );
    let holds = storage
        .roles()
        .roles_for_user(tenant, user)
        .await?
        .iter()
        .any(grants_admin_write);
    if !active || !holds {
        return Ok(());
    }
    if other_admin_exists(storage, tenant, &[], Some(user), None).await? {
        Ok(())
    } else {
        Err(CoreError::LastAdministrator)
    }
}

/// The last-administrator guard for a batch of role changes in the system tenant (declarative
/// configuration): `losing` are the roles that stop granting `admin:write` (deleted, or edited
/// without it). Refuses with `LastAdministrator` unless an active user keeps `admin:write`
/// through another role. Lets the caller refuse the whole batch before changing anything;
/// [`RoleService::update`] and [`RoleService::delete`] still check every single change.
pub async fn guard_roles_losing_admin(
    storage: &dyn Storage,
    tenant: &Tenant,
    losing: &[RoleId],
) -> Result<(), CoreError> {
    if !is_system(tenant) || losing.is_empty() {
        return Ok(());
    }
    if other_admin_exists(storage, tenant.id, losing, None, None).await? {
        Ok(())
    } else {
        Err(CoreError::LastAdministrator)
    }
}

// ---------------------------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------------------------

/// A role to create.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleInput {
    pub name: String,
    pub description: String,
    pub permissions: Vec<String>,
}

/// Role management.
#[derive(Clone)]
pub struct RoleService {
    pub storage: Arc<dyn Storage>,
    pub clock: Arc<dyn Clock>,
}

impl RoleService {
    async fn record(
        &self,
        tenant: TenantId,
        actor: AuditActor,
        action: AuditAction,
        target: String,
        role: &str,
        ctx: &RequestContext,
    ) -> Result<(), CoreError> {
        AuditService {
            storage: self.storage.clone(),
            clock: self.clock.clone(),
        }
        .record(
            tenant,
            actor,
            action,
            Some(target),
            AuditOutcome::Success,
            ctx,
            AuditDetails::role(role),
        )
        .await
    }

    /// Every role of the tenant, in name order.
    pub async fn list(&self, tenant: TenantId) -> Result<Vec<Role>, CoreError> {
        Ok(self.storage.roles().list(tenant).await?)
    }

    /// A role by name (`NotFound` for a name of another tenant).
    pub async fn get(&self, tenant: TenantId, name: &str) -> Result<Role, CoreError> {
        self.storage
            .roles()
            .get_by_name(tenant, name)
            .await?
            .ok_or(CoreError::NotFound)
    }

    /// Creates a role. In the system tenant `caller` must cover its admin permissions.
    pub async fn create(
        &self,
        tenant: &Tenant,
        input: RoleInput,
        caller: &Scope,
        actor: AuditActor,
        ctx: &RequestContext,
    ) -> Result<Role, CoreError> {
        validate_role_name(&input.name)?;
        let description = validate_description(&input.description)?;
        let permissions = normalize_permissions(&input.permissions)?;
        if is_system(tenant) {
            check_escalation(caller, &permissions)?;
        }
        let role = self
            .storage
            .roles()
            .create(
                tenant.id,
                &NewRole {
                    id: RoleId::new_v7(),
                    org_id: None,
                    name: input.name,
                    description,
                    permissions,
                    created_at: self.clock.now(),
                },
            )
            .await
            .map_err(map_conflict)?;
        self.record(
            tenant.id,
            actor,
            AuditAction::RoleCreated,
            role.id.to_string(),
            &role.name,
            ctx,
        )
        .await?;
        Ok(role)
    }

    /// Updates a role. In the system tenant `caller` must cover both the current and the new
    /// admin permissions, and dropping `admin:write` must leave another administrator.
    pub async fn update(
        &self,
        tenant: &Tenant,
        name: &str,
        patch: RoleUpdate,
        caller: &Scope,
        actor: AuditActor,
        ctx: &RequestContext,
    ) -> Result<Role, CoreError> {
        let current = self.get(tenant.id, name).await?;
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
        if is_system(tenant) {
            check_escalation(caller, &current.permissions)?;
            if let Some(p) = &update.permissions {
                check_escalation(caller, p)?;
                let keeps = p.iter().any(|x| x == ADMIN_WRITE);
                if grants_admin_write(&current) && !keeps {
                    self.refuse_without_other_admin(tenant.id, Some(current.id), None)
                        .await?;
                }
            }
        }
        let role = self
            .storage
            .roles()
            .update(tenant.id, current.id, &update, self.clock.now())
            .await
            .map_err(map_conflict)?
            .ok_or(CoreError::NotFound)?;
        self.record(
            tenant.id,
            actor,
            AuditAction::RoleUpdated,
            role.id.to_string(),
            &role.name,
            ctx,
        )
        .await?;
        Ok(role)
    }

    /// Deletes a role with its assignments. In the system tenant `caller` must cover its admin
    /// permissions, and deleting an `admin:write` role must leave another administrator.
    pub async fn delete(
        &self,
        tenant: &Tenant,
        name: &str,
        caller: &Scope,
        actor: AuditActor,
        ctx: &RequestContext,
    ) -> Result<(), CoreError> {
        let role = self.get(tenant.id, name).await?;
        if is_system(tenant) {
            check_escalation(caller, &role.permissions)?;
            if grants_admin_write(&role) {
                self.refuse_without_other_admin(tenant.id, Some(role.id), None)
                    .await?;
            }
        }
        if !self.storage.roles().delete(tenant.id, role.id).await? {
            return Err(CoreError::NotFound);
        }
        self.record(
            tenant.id,
            actor,
            AuditAction::RoleDeleted,
            role.id.to_string(),
            &role.name,
            ctx,
        )
        .await
    }

    /// Assigns a role (idempotent). A role or user of another tenant is `NotFound`. In the
    /// system tenant `caller` must cover the role's admin permissions.
    pub async fn assign(
        &self,
        tenant: &Tenant,
        name: &str,
        user: UserId,
        caller: &Scope,
        actor: AuditActor,
        ctx: &RequestContext,
    ) -> Result<Role, CoreError> {
        let role = self.get(tenant.id, name).await?;
        if is_system(tenant) {
            check_escalation(caller, &role.permissions)?;
        }
        if !self
            .storage
            .roles()
            .assign(tenant.id, role.id, user, self.clock.now())
            .await?
        {
            return Err(CoreError::NotFound);
        }
        self.record(
            tenant.id,
            actor,
            AuditAction::RoleAssigned,
            user.to_string(),
            &role.name,
            ctx,
        )
        .await?;
        Ok(role)
    }

    /// Removes an assignment (`NotFound` if there was none). In the system tenant `caller` must
    /// cover the role's admin permissions and removing the last administrator is refused.
    pub async fn unassign(
        &self,
        tenant: &Tenant,
        name: &str,
        user: UserId,
        caller: &Scope,
        actor: AuditActor,
        ctx: &RequestContext,
    ) -> Result<(), CoreError> {
        let role = self.get(tenant.id, name).await?;
        if is_system(tenant) {
            check_escalation(caller, &role.permissions)?;
            if grants_admin_write(&role) {
                self.refuse_without_other_admin(tenant.id, None, Some((role.id, user)))
                    .await?;
            }
        }
        if !self
            .storage
            .roles()
            .unassign(tenant.id, role.id, user)
            .await?
        {
            return Err(CoreError::NotFound);
        }
        self.record(
            tenant.id,
            actor,
            AuditAction::RoleUnassigned,
            user.to_string(),
            &role.name,
            ctx,
        )
        .await
    }

    /// The roles of a user of this tenant (`NotFound` for an unknown user).
    pub async fn roles_for_user(
        &self,
        tenant: TenantId,
        user: UserId,
    ) -> Result<Vec<Role>, CoreError> {
        if self.storage.users().get(tenant, user).await?.is_none() {
            return Err(CoreError::NotFound);
        }
        Ok(self.storage.roles().roles_for_user(tenant, user).await?)
    }

    /// One page of the users holding a role.
    pub async fn users_with_role(
        &self,
        tenant: TenantId,
        name: &str,
        page: PageRequest,
    ) -> Result<Page<User>, CoreError> {
        let role = self.get(tenant, name).await?;
        Ok(self
            .storage
            .roles()
            .users_with_role(tenant, role.id, admin_page(page))
            .await?)
    }

    /// The admin scopes `user`'s roles grant (empty outside the system tenant).
    pub async fn effective_admin_scopes(
        &self,
        tenant: &Tenant,
        user: UserId,
    ) -> Result<BTreeSet<String>, CoreError> {
        if !is_system(tenant) {
            return Ok(BTreeSet::new());
        }
        let roles = self.storage.roles().roles_for_user(tenant.id, user).await?;
        Ok(effective_admin_scopes(tenant, &roles))
    }

    async fn refuse_without_other_admin(
        &self,
        tenant: TenantId,
        except_role: Option<RoleId>,
        unassign: Option<(RoleId, UserId)>,
    ) -> Result<(), CoreError> {
        let except: Vec<RoleId> = except_role.into_iter().collect();
        if other_admin_exists(self.storage.as_ref(), tenant, &except, None, unassign).await? {
            Ok(())
        } else {
            Err(CoreError::LastAdministrator)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::TenantSettings;
    use crate::service::admin_scope::ADMIN_READ;
    use time::OffsetDateTime;

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

    fn role(t: &Tenant, perms: &[&str]) -> Role {
        Role {
            id: RoleId::new_v7(),
            tenant_id: t.id,
            org_id: None,
            name: "r".into(),
            description: String::new(),
            permissions: perms.iter().map(|p| (*p).to_owned()).collect(),
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    fn scope(s: &str) -> Scope {
        Scope::parse(s).unwrap()
    }

    fn strs(s: &Scope) -> Vec<String> {
        let mut v: Vec<String> = s.iter().map(str::to_owned).collect();
        v.sort();
        v
    }

    #[test]
    fn admin_write_covers_everything_and_read_covers_reads() {
        let all = admin_scopes_covered_by([ADMIN_WRITE]);
        assert_eq!(all.len(), ALL_ADMIN_SCOPES.len());
        let reads = admin_scopes_covered_by([ADMIN_READ]);
        assert!(reads.iter().all(|s| s.ends_with(":read")));
        assert!(reads.contains("admin:users:read"));
        assert!(!reads.contains(ADMIN_WRITE));
        let users = admin_scopes_covered_by(["admin:users:write"]);
        assert_eq!(
            users.into_iter().collect::<Vec<_>>(),
            ["admin:users:read", "admin:users:write"]
        );
        assert!(admin_scopes_covered_by(["docs:write", "admin", "admin:x:write"]).is_empty());
    }

    #[test]
    fn non_system_roles_never_grant_admin_scopes() {
        let acme = tenant("acme");
        let r = role(&acme, &[ADMIN_WRITE]);
        assert!(effective_admin_scopes(&acme, &[r]).is_empty());
        let sys = tenant(SYSTEM_TENANT_SLUG);
        let r = role(&sys, &[ADMIN_WRITE]);
        assert_eq!(
            effective_admin_scopes(&sys, &[r]).len(),
            ALL_ADMIN_SCOPES.len()
        );
    }

    #[test]
    fn bound_admin_scope_intersects_with_roles() {
        let requested = scope("openid admin:read admin:write");
        let full = admin_scopes_covered_by([ADMIN_WRITE]);
        assert_eq!(
            strs(&bound_admin_scope(&requested, &full)),
            ["admin:write", "openid"]
        );

        let read_only = admin_scopes_covered_by([ADMIN_READ]);
        assert_eq!(
            strs(&bound_admin_scope(&scope("openid admin:write"), &read_only)),
            ["admin:read", "openid"]
        );

        let none = BTreeSet::new();
        assert_eq!(strs(&bound_admin_scope(&requested, &none)), ["openid"]);

        let users = admin_scopes_covered_by(["admin:users:write"]);
        assert_eq!(
            strs(&bound_admin_scope(&scope("admin:write"), &users)),
            ["admin:users:write"]
        );
        // Never more than requested.
        assert_eq!(
            strs(&bound_admin_scope(&scope("openid admin:read"), &full)),
            ["admin:read", "openid"]
        );
    }

    #[test]
    fn escalation_is_refused_beyond_the_callers_scopes() {
        let perms = |p: &[&str]| p.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        assert!(check_escalation(&scope("admin:write"), &perms(&[ADMIN_WRITE])).is_ok());
        assert!(matches!(
            check_escalation(&scope("admin:users:write"), &perms(&[ADMIN_WRITE])),
            Err(CoreError::InsufficientScope(_))
        ));
        assert!(
            check_escalation(&scope("admin:users:write"), &perms(&["admin:users:read"])).is_ok()
        );
        assert!(check_escalation(&scope("admin:read"), &perms(&["admin:users:write"])).is_err());
        // Non-admin permissions are never escalation.
        assert!(check_escalation(&scope("admin:users:write"), &perms(&["docs:write"])).is_ok());
    }

    #[test]
    fn role_escalation_users_write_cannot_grant_export() {
        let export = vec!["admin:users:export".to_owned()];
        for caller in [
            "admin:users:write",
            "admin:users:read admin:users:write",
            "admin:read admin:users:write",
        ] {
            assert!(
                matches!(
                    check_escalation(&scope(caller), &export),
                    Err(CoreError::InsufficientScope(_))
                ),
                "{caller} must not grant admin:users:export"
            );
        }
        assert!(check_escalation(&scope("admin:write"), &export).is_ok());
        assert!(check_escalation(&scope("admin:users:export"), &export).is_ok());
        // Role expansion follows the same rule: users:write never yields the export scope.
        assert!(!admin_scopes_covered_by(["admin:users:write"]).contains("admin:users:export"));
        assert!(admin_scopes_covered_by([ADMIN_WRITE]).contains("admin:users:export"));
        assert!(!admin_scopes_covered_by([ADMIN_READ]).contains("admin:users:export"));
    }

    fn org_source(perms: &[&str]) -> UserClaimSource {
        UserClaimSource {
            org: Some(OrgClaims {
                org_id: OrgId::new_v7(),
                org_slug: "acme".into(),
                roles: vec!["member".into()],
                permissions: perms.iter().map(|p| (*p).to_owned()).collect(),
            }),
            ..UserClaimSource::default()
        }
    }

    #[test]
    fn org_admin_scope_follows_the_active_org_permissions() {
        let requested = scope("openid org:admin");
        assert_eq!(
            strs(&org_source(&["org:admin"]).bound_org_admin(&requested)),
            ["openid", "org:admin"]
        );
        assert_eq!(
            strs(&org_source(&["docs:read"]).bound_org_admin(&requested)),
            ["openid"]
        );
        // Never without an active org, whatever the tenant-wide roles say.
        let t = tenant("acme");
        let no_org = UserClaimSource {
            roles: vec![role(&t, &["org:admin"])],
            permissions: vec!["org:admin".into()],
            ..UserClaimSource::default()
        };
        assert_eq!(strs(&no_org.bound_org_admin(&requested)), ["openid"]);
    }

    #[test]
    fn org_claims_only_with_an_active_org() {
        let t = tenant("acme");
        let granted = scope("openid roles");
        assert!(
            UserClaimSource::default()
                .org_claims(&t, &granted, TokenTarget::AccessToken)
                .is_empty()
        );
        let src = org_source(&["docs:read"]);
        let at = src.org_claims(&t, &granted, TokenTarget::AccessToken);
        assert_eq!(at["org_slug"], "acme");
        assert_eq!(at["org_roles"], serde_json::json!(["member"]));
        assert_eq!(at["org_permissions"], serde_json::json!(["docs:read"]));
        let id = src.org_claims(&t, &granted, TokenTarget::IdToken);
        assert!(id.contains_key("org_id") && !id.contains_key("org_permissions"));
        // Org roles never leak into the tenant-wide claims.
        let tenant_claims = src.claims(&t, &granted, TokenTarget::AccessToken, None);
        assert!(!tenant_claims.contains_key("roles"), "{tenant_claims:?}");
        assert!(!src.lost_active_org());
    }
}
