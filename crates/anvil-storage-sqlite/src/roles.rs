//! `RoleRepo` on SQLite: tenant roles, org-owned roles and their assignments.
//!
//! Assignments reference the role and the user through composite (tenant_id, id) foreign keys
//! with ON DELETE CASCADE, so an assignment can never cross tenants and goes with its role or
//! user. `role_assignment.org_id` NULL is a tenant-wide assignment; set, the assignment holds only
//! in that org and references the membership `(tenant_id, org_id, user_id)` with ON DELETE
//! CASCADE, so it goes with the membership. An org-owned role (`role.org_id` set) references its
//! org and goes with it; it is only ever assigned in its own org.

use anvil_core::model::{
    NewRole, OrgId, Page, PageRequest, Role, RoleAssignment, RoleId, RoleUpdate, SYSTEM_ADMIN_ROLE,
    TenantId, User, UserId,
};
use anvil_core::ports::{RoleRepo, StorageError};
use sqlx::{SqliteConnection, SqlitePool};
use time::OffsetDateTime;

use crate::convert::{from_json, into_page, map_err, ms_to_odt, odt_to_ms, to_json};
use crate::organizations::map_fk_err;
use crate::users::UserRow;

/// Permission set of the system tenant's administrator role.
const ADMIN_PERMISSIONS: &[&str] = &["admin:write"];

#[derive(Debug, Clone)]
pub(crate) struct SqliteRoles {
    pub(crate) writer: SqlitePool,
    pub(crate) reader: SqlitePool,
}

struct RoleRow {
    id: uuid::Uuid,
    tenant_id: uuid::Uuid,
    org_id: Option<uuid::Uuid>,
    name: String,
    description: String,
    permissions: String,
    created_at: i64,
    updated_at: i64,
}

impl TryFrom<RoleRow> for Role {
    type Error = StorageError;

    fn try_from(r: RoleRow) -> Result<Self, StorageError> {
        Ok(Role {
            id: RoleId(r.id),
            tenant_id: TenantId(r.tenant_id),
            org_id: r.org_id.map(OrgId),
            name: r.name,
            description: r.description,
            permissions: from_json(&r.permissions, "role.permissions")?,
            created_at: ms_to_odt(r.created_at)?,
            updated_at: ms_to_odt(r.updated_at)?,
        })
    }
}

/// Inserts a role on `conn` and returns the stored record. `Conflict` on a duplicate id, a
/// duplicate tenant-level name, a duplicate name within the owning org, or an owning org that is
/// not an org of `tenant` (foreign key).
pub(crate) async fn insert_role(
    conn: &mut SqliteConnection,
    tenant: TenantId,
    role: &NewRole,
) -> Result<Role, StorageError> {
    let org_id = role.org_id.map(|o| o.0);
    let permissions = to_json(&role.permissions, "role.permissions")?;
    let created_at = odt_to_ms(role.created_at);
    sqlx::query!(
        "INSERT INTO role
             (id, tenant_id, org_id, name, description, permissions, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)",
        role.id.0,
        tenant.0,
        org_id,
        role.name,
        role.description,
        permissions,
        created_at,
    )
    .execute(conn)
    .await
    .map_err(map_fk_err("role references an org outside the tenant"))?;
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

/// Creates the tenant's [`SYSTEM_ADMIN_ROLE`] (`[admin:write]`) on `conn` (the install
/// transaction).
pub(crate) async fn insert_admin_role(
    conn: &mut SqliteConnection,
    tenant: TenantId,
    now: OffsetDateTime,
) -> Result<Role, StorageError> {
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

/// Assigns the tenant's [`SYSTEM_ADMIN_ROLE`] to `user` on `conn` (the setup transaction).
/// `Conflict` if the tenant has no such role, so setup never creates an administrator without
/// administrative permissions.
pub(crate) async fn assign_admin_role(
    conn: &mut SqliteConnection,
    tenant: TenantId,
    user: UserId,
    now: OffsetDateTime,
) -> Result<(), StorageError> {
    let now_ms = odt_to_ms(now);
    // `WHERE` before `ON CONFLICT` is required: SQLite would otherwise parse the upsert's `ON`
    // as a join constraint of the SELECT.
    let done = sqlx::query!(
        "INSERT INTO role_assignment (tenant_id, role_id, user_id, created_at)
         SELECT r.tenant_id, r.id, u.id, ?4
           FROM role r JOIN user u ON u.tenant_id = r.tenant_id
          WHERE r.tenant_id = ?1 AND r.name = ?2 AND r.org_id IS NULL AND u.id = ?3
         ON CONFLICT (tenant_id, role_id, user_id) WHERE org_id IS NULL DO NOTHING",
        tenant.0,
        SYSTEM_ADMIN_ROLE,
        user.0,
        now_ms,
    )
    .execute(conn)
    .await
    .map_err(map_err)?;
    if done.rows_affected() == 0 {
        return Err(StorageError::Conflict(format!(
            "the admin tenant has no {SYSTEM_ADMIN_ROLE} role"
        )));
    }
    Ok(())
}

/// Assigns `role` to `user` within `org` on `conn` (idempotent). `true` if the user holds the
/// role in the org afterwards; `false` (nothing stored) unless the role exists in `tenant` and
/// is a tenant role or owned by `org`, and the user is a member of `org` (the membership row
/// stands for org and user existing in the tenant).
pub(crate) async fn assign_in_org_on(
    conn: &mut SqliteConnection,
    tenant: TenantId,
    role: RoleId,
    user: UserId,
    org: OrgId,
    now: OffsetDateTime,
) -> Result<bool, StorageError> {
    let now_ms = odt_to_ms(now);
    sqlx::query!(
        "INSERT INTO role_assignment (tenant_id, role_id, user_id, org_id, created_at)
         SELECT r.tenant_id, r.id, m.user_id, m.org_id, ?5
           FROM role r JOIN org_membership m ON m.tenant_id = r.tenant_id
          WHERE r.tenant_id = ?1 AND r.id = ?2 AND m.user_id = ?3 AND m.org_id = ?4
            AND (r.org_id IS NULL OR r.org_id = ?4)
         ON CONFLICT (tenant_id, role_id, user_id, org_id) WHERE org_id IS NOT NULL DO NOTHING",
        tenant.0,
        role.0,
        user.0,
        org.0,
        now_ms,
    )
    .execute(&mut *conn)
    .await
    .map_err(map_err)?;
    sqlx::query_scalar!(
        r#"SELECT EXISTS(SELECT 1 FROM role_assignment
                          WHERE tenant_id = ?1 AND role_id = ?2 AND user_id = ?3
                            AND org_id = ?4)
                  AS "held!: bool""#,
        tenant.0,
        role.0,
        user.0,
        org.0,
    )
    .fetch_one(conn)
    .await
    .map_err(map_err)
}

#[async_trait::async_trait]
impl RoleRepo for SqliteRoles {
    async fn create(&self, tenant: TenantId, role: &NewRole) -> Result<Role, StorageError> {
        let mut conn = self.writer.acquire().await.map_err(map_err)?;
        insert_role(&mut conn, tenant, role).await
    }

    async fn get(&self, tenant: TenantId, id: RoleId) -> Result<Option<Role>, StorageError> {
        sqlx::query_as!(
            RoleRow,
            r#"SELECT id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      org_id AS "org_id?: uuid::Uuid", name AS "name!",
                      description AS "description!", permissions AS "permissions!",
                      created_at AS "created_at!", updated_at AS "updated_at!"
                 FROM role WHERE tenant_id = ?1 AND id = ?2"#,
            tenant.0,
            id.0,
        )
        .fetch_optional(&self.reader)
        .await
        .map_err(map_err)?
        .map(Role::try_from)
        .transpose()
    }

    async fn get_by_name(
        &self,
        tenant: TenantId,
        name: &str,
    ) -> Result<Option<Role>, StorageError> {
        sqlx::query_as!(
            RoleRow,
            r#"SELECT id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      org_id AS "org_id?: uuid::Uuid", name AS "name!",
                      description AS "description!", permissions AS "permissions!",
                      created_at AS "created_at!", updated_at AS "updated_at!"
                 FROM role WHERE tenant_id = ?1 AND name = ?2 AND org_id IS NULL"#,
            tenant.0,
            name,
        )
        .fetch_optional(&self.reader)
        .await
        .map_err(map_err)?
        .map(Role::try_from)
        .transpose()
    }

    async fn list(&self, tenant: TenantId) -> Result<Vec<Role>, StorageError> {
        sqlx::query_as!(
            RoleRow,
            r#"SELECT id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      org_id AS "org_id?: uuid::Uuid", name AS "name!",
                      description AS "description!", permissions AS "permissions!",
                      created_at AS "created_at!", updated_at AS "updated_at!"
                 FROM role WHERE tenant_id = ?1 AND org_id IS NULL
                ORDER BY name, id"#,
            tenant.0,
        )
        .fetch_all(&self.reader)
        .await
        .map_err(map_err)?
        .into_iter()
        .map(Role::try_from)
        .collect()
    }

    async fn update(
        &self,
        tenant: TenantId,
        id: RoleId,
        update: &RoleUpdate,
        now: OffsetDateTime,
    ) -> Result<Option<Role>, StorageError> {
        let permissions = update
            .permissions
            .as_ref()
            .map(|p| to_json(p, "role.permissions"))
            .transpose()?;
        let now_ms = odt_to_ms(now);
        sqlx::query_as!(
            RoleRow,
            r#"UPDATE role
                  SET name = COALESCE(?3, name),
                      description = COALESCE(?4, description),
                      permissions = COALESCE(?5, permissions),
                      updated_at = ?6
                WHERE tenant_id = ?1 AND id = ?2
            RETURNING id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      org_id AS "org_id?: uuid::Uuid", name AS "name!",
                      description AS "description!", permissions AS "permissions!",
                      created_at AS "created_at!", updated_at AS "updated_at!""#,
            tenant.0,
            id.0,
            update.name,
            update.description,
            permissions,
            now_ms,
        )
        .fetch_optional(&self.writer)
        .await
        .map_err(map_err)?
        .map(Role::try_from)
        .transpose()
    }

    async fn delete(&self, tenant: TenantId, id: RoleId) -> Result<bool, StorageError> {
        // One statement; the assignments go with it by ON DELETE CASCADE.
        let done = sqlx::query!(
            "DELETE FROM role WHERE tenant_id = ?1 AND id = ?2",
            tenant.0,
            id.0,
        )
        .execute(&self.writer)
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
        let now_ms = odt_to_ms(now);
        // The SELECT only yields a row if both the role and the user exist in `tenant` and the
        // role is a tenant role; an existing assignment is kept as is. The single writer
        // serialises the insert and the check below.
        let mut tx = self.writer.begin().await.map_err(map_err)?;
        sqlx::query!(
            "INSERT INTO role_assignment (tenant_id, role_id, user_id, created_at)
             SELECT r.tenant_id, r.id, u.id, ?4
               FROM role r JOIN user u ON u.tenant_id = r.tenant_id
              WHERE r.tenant_id = ?1 AND r.id = ?2 AND u.id = ?3 AND r.org_id IS NULL
             ON CONFLICT (tenant_id, role_id, user_id) WHERE org_id IS NULL DO NOTHING",
            tenant.0,
            role.0,
            user.0,
            now_ms,
        )
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;
        let held = sqlx::query_scalar!(
            r#"SELECT EXISTS(SELECT 1 FROM role_assignment
                              WHERE tenant_id = ?1 AND role_id = ?2 AND user_id = ?3
                                AND org_id IS NULL)
                      AS "held!: bool""#,
            tenant.0,
            role.0,
            user.0,
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(map_err)?;
        tx.commit().await.map_err(map_err)?;
        Ok(held)
    }

    async fn unassign(
        &self,
        tenant: TenantId,
        role: RoleId,
        user: UserId,
    ) -> Result<bool, StorageError> {
        let done = sqlx::query!(
            "DELETE FROM role_assignment
              WHERE tenant_id = ?1 AND role_id = ?2 AND user_id = ?3 AND org_id IS NULL",
            tenant.0,
            role.0,
            user.0,
        )
        .execute(&self.writer)
        .await
        .map_err(map_err)?;
        Ok(done.rows_affected() > 0)
    }

    async fn roles_for_user(
        &self,
        tenant: TenantId,
        user: UserId,
    ) -> Result<Vec<Role>, StorageError> {
        sqlx::query_as!(
            RoleRow,
            r#"SELECT r.id AS "id!: uuid::Uuid", r.tenant_id AS "tenant_id!: uuid::Uuid",
                      r.org_id AS "org_id?: uuid::Uuid", r.name AS "name!",
                      r.description AS "description!", r.permissions AS "permissions!",
                      r.created_at AS "created_at!", r.updated_at AS "updated_at!"
                 FROM role_assignment a
                 JOIN role r ON r.tenant_id = a.tenant_id AND r.id = a.role_id
                WHERE a.tenant_id = ?1 AND a.user_id = ?2 AND a.org_id IS NULL
                ORDER BY r.name, r.id"#,
            tenant.0,
            user.0,
        )
        .fetch_all(&self.reader)
        .await
        .map_err(map_err)?
        .into_iter()
        .map(Role::try_from)
        .collect()
    }

    async fn users_with_role(
        &self,
        tenant: TenantId,
        role: RoleId,
        page: PageRequest,
    ) -> Result<Page<User>, StorageError> {
        let limit = page.clamped_limit();
        let fetch = i64::from(limit) + 1;
        let rows = sqlx::query_as!(
            UserRow,
            r#"SELECT u.id AS "id!: uuid::Uuid", u.tenant_id AS "tenant_id!: uuid::Uuid",
                      u.email AS "email!", u.email_verified AS "email_verified!: bool",
                      u.username AS "username?", u.claims AS "claims!", u.status AS "status!",
                      u.created_at AS "created_at!", u.updated_at AS "updated_at!",
                      u.last_login_at AS "last_login_at?"
                 FROM role_assignment a
                 JOIN user u ON u.tenant_id = a.tenant_id AND u.id = a.user_id
                WHERE a.tenant_id = ?1 AND a.role_id = ?2 AND a.org_id IS NULL
                  AND (?3 IS NULL OR u.id > ?3)
                ORDER BY u.id
                LIMIT ?4"#,
            tenant.0,
            role.0,
            page.after,
            fetch,
        )
        .fetch_all(&self.reader)
        .await
        .map_err(map_err)?;
        let items = rows
            .into_iter()
            .map(User::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(into_page(items, limit, |u| u.id.0))
    }

    async fn holders_of_permission(
        &self,
        tenant: TenantId,
        permission: &str,
    ) -> Result<u64, StorageError> {
        let count = sqlx::query_scalar!(
            r#"SELECT count(DISTINCT u.id) AS "count!: i64"
                 FROM user u
                 JOIN role_assignment a ON a.tenant_id = u.tenant_id AND a.user_id = u.id
                                        AND a.org_id IS NULL
                 JOIN role r ON r.tenant_id = a.tenant_id AND r.id = a.role_id
                WHERE u.tenant_id = ?1 AND u.status = 'active'
                  AND EXISTS (SELECT 1 FROM json_each(r.permissions) p WHERE p.value = ?2)"#,
            tenant.0,
            permission,
        )
        .fetch_one(&self.reader)
        .await
        .map_err(map_err)?;
        u64::try_from(count).map_err(|_| StorageError::Corrupt(format!("negative count {count}")))
    }

    async fn list_org_roles(
        &self,
        tenant: TenantId,
        org: OrgId,
    ) -> Result<Vec<Role>, StorageError> {
        sqlx::query_as!(
            RoleRow,
            r#"SELECT id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      org_id AS "org_id?: uuid::Uuid", name AS "name!",
                      description AS "description!", permissions AS "permissions!",
                      created_at AS "created_at!", updated_at AS "updated_at!"
                 FROM role WHERE tenant_id = ?1 AND org_id = ?2
                ORDER BY name, id"#,
            tenant.0,
            org.0,
        )
        .fetch_all(&self.reader)
        .await
        .map_err(map_err)?
        .into_iter()
        .map(Role::try_from)
        .collect()
    }

    async fn assign_in_org(
        &self,
        tenant: TenantId,
        role: RoleId,
        user: UserId,
        org: OrgId,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let mut tx = self.writer.begin().await.map_err(map_err)?;
        let held = assign_in_org_on(&mut tx, tenant, role, user, org, now).await?;
        tx.commit().await.map_err(map_err)?;
        Ok(held)
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
              WHERE tenant_id = ?1 AND role_id = ?2 AND user_id = ?3 AND org_id = ?4",
            tenant.0,
            role.0,
            user.0,
            org.0,
        )
        .execute(&self.writer)
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
        // Assignments in an org exist only for members (membership foreign key), and at most one
        // per role (partial unique index), so no deduplication is needed.
        sqlx::query_as!(
            RoleRow,
            r#"SELECT r.id AS "id!: uuid::Uuid", r.tenant_id AS "tenant_id!: uuid::Uuid",
                      r.org_id AS "org_id?: uuid::Uuid", r.name AS "name!",
                      r.description AS "description!", r.permissions AS "permissions!",
                      r.created_at AS "created_at!", r.updated_at AS "updated_at!"
                 FROM role_assignment a
                 JOIN role r ON r.tenant_id = a.tenant_id AND r.id = a.role_id
                WHERE a.tenant_id = ?1 AND a.user_id = ?2 AND a.org_id = ?3
                ORDER BY r.name, r.id"#,
            tenant.0,
            user.0,
            org.0,
        )
        .fetch_all(&self.reader)
        .await
        .map_err(map_err)?
        .into_iter()
        .map(Role::try_from)
        .collect()
    }

    async fn org_assignments(
        &self,
        tenant: TenantId,
        org: OrgId,
        user: UserId,
    ) -> Result<Vec<RoleAssignment>, StorageError> {
        let rows = sqlx::query!(
            r#"SELECT role_id AS "role_id!: uuid::Uuid", user_id AS "user_id!: uuid::Uuid",
                      org_id AS "org_id!: uuid::Uuid"
                 FROM role_assignment
                WHERE tenant_id = ?1 AND org_id = ?2 AND user_id = ?3
                ORDER BY role_id"#,
            tenant.0,
            org.0,
            user.0,
        )
        .fetch_all(&self.reader)
        .await
        .map_err(map_err)?;
        Ok(rows
            .into_iter()
            .map(|r| RoleAssignment {
                role_id: RoleId(r.role_id),
                user_id: UserId(r.user_id),
                org_id: Some(OrgId(r.org_id)),
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
            r#"SELECT count(DISTINCT u.id) AS "count!: i64"
                 FROM user u
                 JOIN role_assignment a ON a.tenant_id = u.tenant_id AND a.user_id = u.id
                                        AND a.org_id = ?2
                 JOIN role r ON r.tenant_id = a.tenant_id AND r.id = a.role_id
                WHERE u.tenant_id = ?1 AND u.status = 'active'
                  AND EXISTS (SELECT 1 FROM json_each(r.permissions) p WHERE p.value = ?3)"#,
            tenant.0,
            org.0,
            permission,
        )
        .fetch_one(&self.reader)
        .await
        .map_err(map_err)?;
        u64::try_from(count).map_err(|_| StorageError::Corrupt(format!("negative count {count}")))
    }
}
