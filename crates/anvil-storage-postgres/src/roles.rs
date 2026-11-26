//! `RoleRepo` on Postgres: tenant-scoped roles and their assignments to users.
//!
//! Tenant isolation is enforced by the schema: assignments reference the role and the user through
//! composite `(tenant_id, id)` foreign keys, so a role or user of another tenant can never be
//! paired. Tenant-level role names are unique per tenant (partial unique index
//! `WHERE org_id IS NULL`), org-owned role names per org; duplicates surface as `Conflict`.
//!
//! One assignment table holds both levels: `org_id` NULL is a tenant-wide assignment (0.4
//! semantics, the only one the 0.4 methods see), `org_id` set holds only in that org and
//! references the membership, so ending the membership removes it.

use anvil_core::model::{
    NewRole, OrgId, Page, PageRequest, Role, RoleAssignment, RoleId, RoleUpdate, SYSTEM_ADMIN_ROLE,
    TenantId, User, UserId, UserStatus,
};
use anvil_core::ports::{RoleRepo, StorageError};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::convert::{fetch_limit, into_page, map_err};
use crate::organizations::{fk_conflict, is_fk_violation};
use crate::users::UserRow;

/// Permissions of the system tenant's administrator role (also written by the 0006 backfill).
const ADMIN_PERMISSIONS: &[&str] = &["admin:write"];

#[derive(Debug, Clone)]
pub(crate) struct PgRoles {
    pub(crate) pool: PgPool,
}

struct RoleRow {
    id: Uuid,
    tenant_id: Uuid,
    org_id: Option<Uuid>,
    name: String,
    description: String,
    permissions: Vec<String>,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

impl RoleRow {
    fn into_model(self) -> Role {
        Role {
            id: RoleId(self.id),
            tenant_id: TenantId(self.tenant_id),
            org_id: self.org_id.map(OrgId),
            name: self.name,
            description: self.description,
            permissions: self.permissions,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

/// Inserts a role on any executor (`updated_at = created_at`). `Conflict` on a duplicate id, a
/// duplicate tenant-level name, a duplicate name among the roles of the same org, or an `org_id`
/// that is not an org of `tenant` (composite foreign key).
pub(crate) async fn insert_role<'e, E>(
    exec: E,
    tenant: TenantId,
    role: &NewRole,
) -> Result<(), StorageError>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query!(
        "INSERT INTO role
             (id, tenant_id, org_id, name, description, permissions, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $7)",
        role.id.0,
        tenant.0,
        role.org_id.map(|o| o.0),
        role.name,
        role.description,
        &role.permissions,
        role.created_at,
    )
    .execute(exec)
    .await
    .map_err(|e| fk_conflict(e, "the organization does not exist in this tenant"))?;
    Ok(())
}

/// Assigns a tenant role tenant-wide on any executor (idempotent). `true` if `user` holds `role`
/// afterwards, `false` (nothing stored) if the role or the user is not in `tenant` or the role is
/// org-owned.
pub(crate) async fn assign_role<'e, E>(
    exec: E,
    tenant: TenantId,
    role: RoleId,
    user: UserId,
    now: OffsetDateTime,
) -> Result<bool, StorageError>
where
    E: sqlx::PgExecutor<'e>,
{
    // `DO UPDATE` (a no-op keeping created_at) rather than `DO NOTHING`, so an existing or a
    // concurrently inserted assignment still returns its row: `true` means "held afterwards".
    let row = sqlx::query_scalar!(
        "INSERT INTO role_assignment (tenant_id, role_id, user_id, org_id, created_at)
         SELECT $1, $2, $3, NULL, $4
          WHERE EXISTS (SELECT 1 FROM role WHERE tenant_id = $1 AND id = $2 AND org_id IS NULL)
            AND EXISTS (SELECT 1 FROM \"user\" WHERE tenant_id = $1 AND id = $3)
         ON CONFLICT (tenant_id, role_id, user_id) WHERE org_id IS NULL DO UPDATE
            SET created_at = role_assignment.created_at
      RETURNING user_id",
        tenant.0,
        role.0,
        user.0,
        now,
    )
    .fetch_optional(exec)
    .await
    .map_err(map_err)?;
    Ok(row.is_some())
}

/// Assigns `role` to `user` within `org` on any executor (idempotent). `true` if the user holds
/// the role in that org afterwards; `false` (nothing stored) if the role is not a tenant role or
/// a role of `org`, or `user` is not a member of `org` (the assignment references the
/// membership; a membership removed concurrently fails the foreign key and is also `false`).
pub(crate) async fn assign_role_in_org<'e, E>(
    exec: E,
    tenant: TenantId,
    role: RoleId,
    user: UserId,
    org: OrgId,
    now: OffsetDateTime,
) -> Result<bool, StorageError>
where
    E: sqlx::PgExecutor<'e>,
{
    let row = sqlx::query_scalar!(
        "INSERT INTO role_assignment (tenant_id, role_id, user_id, org_id, created_at)
         SELECT r.tenant_id, r.id, $3, $4, $5
           FROM role r
          WHERE r.tenant_id = $1 AND r.id = $2 AND (r.org_id IS NULL OR r.org_id = $4)
            AND EXISTS (SELECT 1 FROM org_membership m
                         WHERE m.tenant_id = $1 AND m.org_id = $4 AND m.user_id = $3)
         ON CONFLICT (tenant_id, role_id, user_id, org_id) WHERE org_id IS NOT NULL DO UPDATE
            SET created_at = role_assignment.created_at
      RETURNING user_id",
        tenant.0,
        role.0,
        user.0,
        org.0,
        now,
    )
    .fetch_optional(exec)
    .await;
    match row {
        Ok(row) => Ok(row.is_some()),
        Err(e) if is_fk_violation(&e) => Ok(false),
        Err(e) => Err(map_err(e)),
    }
}

/// Creates the tenant's [`SYSTEM_ADMIN_ROLE`] role on the caller's transaction
/// (`SetupRepo::install`).
pub(crate) async fn insert_admin_role(
    conn: &mut sqlx::PgConnection,
    tenant: TenantId,
    now: OffsetDateTime,
) -> Result<(), StorageError> {
    let role = NewRole {
        id: RoleId::new_v7(),
        org_id: None,
        name: SYSTEM_ADMIN_ROLE.to_owned(),
        description: "Full administrative access".to_owned(),
        permissions: ADMIN_PERMISSIONS.iter().map(|p| (*p).to_owned()).collect(),
        created_at: now,
    };
    insert_role(conn, tenant, &role).await
}

/// Assigns the tenant's [`SYSTEM_ADMIN_ROLE`] role to `user` on the caller's transaction
/// (`SetupRepo::complete_setup`). `Conflict` if the tenant has no such role (or the user is not
/// in it), so the caller's transaction rolls back instead of creating an administrator without
/// the role.
pub(crate) async fn assign_admin_role(
    conn: &mut sqlx::PgConnection,
    tenant: TenantId,
    user: UserId,
    now: OffsetDateTime,
) -> Result<(), StorageError> {
    let row = sqlx::query_scalar!(
        "INSERT INTO role_assignment (tenant_id, role_id, user_id, created_at)
         SELECT r.tenant_id, r.id, u.id, $4
           FROM role r
           JOIN \"user\" u ON u.tenant_id = r.tenant_id
          WHERE r.tenant_id = $1 AND r.name = $2 AND r.org_id IS NULL AND u.id = $3
         ON CONFLICT (tenant_id, role_id, user_id) WHERE org_id IS NULL DO UPDATE
            SET created_at = role_assignment.created_at
      RETURNING user_id",
        tenant.0,
        SYSTEM_ADMIN_ROLE,
        user.0,
        now,
    )
    .fetch_optional(conn)
    .await
    .map_err(map_err)?;
    if row.is_none() {
        return Err(StorageError::Conflict(format!(
            "the admin tenant has no {SYSTEM_ADMIN_ROLE} role"
        )));
    }
    Ok(())
}

#[async_trait::async_trait]
impl RoleRepo for PgRoles {
    async fn create(&self, tenant: TenantId, role: &NewRole) -> Result<Role, StorageError> {
        insert_role(&self.pool, tenant, role).await?;
        Ok(Role {
            id: role.id,
            tenant_id: tenant,
            org_id: role.org_id,
            name: role.name.clone(),
            description: role.description.clone(),
            permissions: role.permissions.clone(),
            created_at: role.created_at,
            updated_at: role.created_at,
        })
    }

    async fn get(&self, tenant: TenantId, id: RoleId) -> Result<Option<Role>, StorageError> {
        Ok(sqlx::query_as!(
            RoleRow,
            "SELECT id, tenant_id, org_id, name, description, permissions, created_at, updated_at
               FROM role
              WHERE tenant_id = $1 AND id = $2",
            tenant.0,
            id.0,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?
        .map(RoleRow::into_model))
    }

    async fn get_by_name(
        &self,
        tenant: TenantId,
        name: &str,
    ) -> Result<Option<Role>, StorageError> {
        Ok(sqlx::query_as!(
            RoleRow,
            "SELECT id, tenant_id, org_id, name, description, permissions, created_at, updated_at
               FROM role
              WHERE tenant_id = $1 AND org_id IS NULL AND name = $2",
            tenant.0,
            name,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?
        .map(RoleRow::into_model))
    }

    async fn list(&self, tenant: TenantId) -> Result<Vec<Role>, StorageError> {
        Ok(sqlx::query_as!(
            RoleRow,
            "SELECT id, tenant_id, org_id, name, description, permissions, created_at, updated_at
               FROM role
              WHERE tenant_id = $1 AND org_id IS NULL
              ORDER BY name COLLATE \"C\", id",
            tenant.0,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?
        .into_iter()
        .map(RoleRow::into_model)
        .collect())
    }

    async fn update(
        &self,
        tenant: TenantId,
        id: RoleId,
        update: &RoleUpdate,
        now: OffsetDateTime,
    ) -> Result<Option<Role>, StorageError> {
        Ok(sqlx::query_as!(
            RoleRow,
            "UPDATE role
                SET name = COALESCE($3, name),
                    description = COALESCE($4, description),
                    permissions = COALESCE($5, permissions),
                    updated_at = $6
              WHERE tenant_id = $1 AND id = $2
          RETURNING id, tenant_id, org_id, name, description, permissions, created_at,
                    updated_at",
            tenant.0,
            id.0,
            update.name,
            update.description,
            update.permissions.as_deref(),
            now,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?
        .map(RoleRow::into_model))
    }

    async fn delete(&self, tenant: TenantId, id: RoleId) -> Result<bool, StorageError> {
        // Assignments go by the cascading composite foreign key, in this statement.
        let done = sqlx::query!(
            "DELETE FROM role WHERE tenant_id = $1 AND id = $2",
            tenant.0,
            id.0,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(done.rows_affected() > 0)
    }

    async fn assign(
        &self,
        tenant: TenantId,
        role: RoleId,
        user: UserId,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        assign_role(&self.pool, tenant, role, user, now).await
    }

    async fn unassign(
        &self,
        tenant: TenantId,
        role: RoleId,
        user: UserId,
    ) -> Result<bool, StorageError> {
        let done = sqlx::query!(
            "DELETE FROM role_assignment
              WHERE tenant_id = $1 AND role_id = $2 AND user_id = $3 AND org_id IS NULL",
            tenant.0,
            role.0,
            user.0,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(done.rows_affected() > 0)
    }

    async fn roles_for_user(
        &self,
        tenant: TenantId,
        user: UserId,
    ) -> Result<Vec<Role>, StorageError> {
        Ok(sqlx::query_as!(
            RoleRow,
            "SELECT r.id, r.tenant_id, r.org_id, r.name, r.description, r.permissions,
                    r.created_at, r.updated_at
               FROM role_assignment a
               JOIN role r ON r.tenant_id = a.tenant_id AND r.id = a.role_id
              WHERE a.tenant_id = $1 AND a.user_id = $2 AND a.org_id IS NULL
                AND r.org_id IS NULL
              ORDER BY r.name COLLATE \"C\", r.id",
            tenant.0,
            user.0,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?
        .into_iter()
        .map(RoleRow::into_model)
        .collect())
    }

    async fn users_with_role(
        &self,
        tenant: TenantId,
        role: RoleId,
        page: PageRequest,
    ) -> Result<Page<User>, StorageError> {
        let limit = page.clamped_limit();
        let rows = sqlx::query_as!(
            UserRow,
            "SELECT u.id, u.tenant_id, u.email, u.email_verified, u.username, u.claims, u.status,
                    u.created_at, u.updated_at, u.last_login_at
               FROM role_assignment a
               JOIN \"user\" u ON u.tenant_id = a.tenant_id AND u.id = a.user_id
              WHERE a.tenant_id = $1 AND a.role_id = $2 AND a.org_id IS NULL
                AND ($3::uuid IS NULL OR u.id > $3)
              ORDER BY u.id
              LIMIT $4",
            tenant.0,
            role.0,
            page.after,
            fetch_limit(limit),
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?;
        let items = rows
            .into_iter()
            .map(UserRow::into_model)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(into_page(items, limit, |u| u.id.0))
    }

    async fn holders_of_permission(
        &self,
        tenant: TenantId,
        permission: &str,
    ) -> Result<u64, StorageError> {
        let count = sqlx::query_scalar!(
            "SELECT count(DISTINCT a.user_id) AS \"count!\"
               FROM role_assignment a
               JOIN role r ON r.tenant_id = a.tenant_id AND r.id = a.role_id
               JOIN \"user\" u ON u.tenant_id = a.tenant_id AND u.id = a.user_id
              WHERE a.tenant_id = $1 AND a.org_id IS NULL AND r.org_id IS NULL
                AND $2 = ANY (r.permissions) AND u.status = $3",
            tenant.0,
            permission,
            UserStatus::Active.as_str(),
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_err)?;
        u64::try_from(count)
            .map_err(|_| StorageError::Corrupt(format!("role holder count: negative {count}")))
    }

    async fn list_org_roles(
        &self,
        tenant: TenantId,
        org: OrgId,
    ) -> Result<Vec<Role>, StorageError> {
        Ok(sqlx::query_as!(
            RoleRow,
            "SELECT id, tenant_id, org_id, name, description, permissions, created_at, updated_at
               FROM role
              WHERE tenant_id = $1 AND org_id = $2
              ORDER BY name COLLATE \"C\", id",
            tenant.0,
            org.0,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?
        .into_iter()
        .map(RoleRow::into_model)
        .collect())
    }

    async fn assign_in_org(
        &self,
        tenant: TenantId,
        role: RoleId,
        user: UserId,
        org: OrgId,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        assign_role_in_org(&self.pool, tenant, role, user, org, now).await
    }

    async fn unassign_in_org(
        &self,
        tenant: TenantId,
        role: RoleId,
        user: UserId,
        org: OrgId,
    ) -> Result<bool, StorageError> {
        let done = sqlx::query!(
            "DELETE FROM role_assignment
              WHERE tenant_id = $1 AND role_id = $2 AND user_id = $3 AND org_id = $4",
            tenant.0,
            role.0,
            user.0,
            org.0,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(done.rows_affected() > 0)
    }

    async fn roles_for_user_in_org(
        &self,
        tenant: TenantId,
        user: UserId,
        org: OrgId,
    ) -> Result<Vec<Role>, StorageError> {
        // One row per (role, user, org) by the partial unique index, so no duplicates.
        Ok(sqlx::query_as!(
            RoleRow,
            "SELECT r.id, r.tenant_id, r.org_id, r.name, r.description, r.permissions,
                    r.created_at, r.updated_at
               FROM role_assignment a
               JOIN role r ON r.tenant_id = a.tenant_id AND r.id = a.role_id
              WHERE a.tenant_id = $1 AND a.user_id = $2 AND a.org_id = $3
                AND (r.org_id IS NULL OR r.org_id = $3)
              ORDER BY r.name COLLATE \"C\", r.id",
            tenant.0,
            user.0,
            org.0,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?
        .into_iter()
        .map(RoleRow::into_model)
        .collect())
    }

    async fn org_assignments(
        &self,
        tenant: TenantId,
        org: OrgId,
        user: UserId,
    ) -> Result<Vec<RoleAssignment>, StorageError> {
        Ok(sqlx::query!(
            "SELECT role_id, user_id
               FROM role_assignment
              WHERE tenant_id = $1 AND org_id = $2 AND user_id = $3
              ORDER BY role_id",
            tenant.0,
            org.0,
            user.0,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?
        .into_iter()
        .map(|r| RoleAssignment {
            role_id: RoleId(r.role_id),
            user_id: UserId(r.user_id),
            org_id: Some(org),
        })
        .collect())
    }

    async fn org_holders_of_permission(
        &self,
        tenant: TenantId,
        org: OrgId,
        permission: &str,
    ) -> Result<u64, StorageError> {
        let count = sqlx::query_scalar!(
            "SELECT count(DISTINCT a.user_id) AS \"count!\"
               FROM role_assignment a
               JOIN role r ON r.tenant_id = a.tenant_id AND r.id = a.role_id
               JOIN \"user\" u ON u.tenant_id = a.tenant_id AND u.id = a.user_id
              WHERE a.tenant_id = $1 AND a.org_id = $2 AND (r.org_id IS NULL OR r.org_id = $2)
                AND $3 = ANY (r.permissions) AND u.status = $4",
            tenant.0,
            org.0,
            permission,
            UserStatus::Active.as_str(),
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_err)?;
        u64::try_from(count)
            .map_err(|_| StorageError::Corrupt(format!("org role holder count: negative {count}")))
    }
}
