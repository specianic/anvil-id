//! `OrgRepo` on Postgres: organizations, memberships, invitations and verified domains
//! (ORG-02, ORG-04).
//!
//! Tenant isolation is enforced by the schema: memberships, invitations, domains, org-owned roles
//! and org connections reference the org through composite `(tenant_id, org_id)` foreign keys
//! with `ON DELETE CASCADE`, and in-org role assignments reference the membership. Races are
//! decided by the database (READ COMMITTED):
//!
//! - accepting an invitation locks its row (`SELECT … FOR UPDATE`) and consumes it with one
//!   conditional `UPDATE`; a concurrent accept waits for the lock, then sees the token closed;
//! - verifying a domain is one conditional `UPDATE`; the partial unique index over verified
//!   claims lets exactly one org of a tenant hold a domain verified (`unique_violation` →
//!   `Conflict`);
//! - adding a member is `INSERT … ON CONFLICT DO NOTHING`.
//!
//! The intents that end a membership (`remove_member`, `delete`) revoke the org-bound token
//! families (reason `admin`) in the same transaction.

use anvil_core::model::{
    ActorKind, AuditActor, BrandingScope, Connection, InvitationAccept, MfaPolicy, NewMembership,
    NewOrgDomain, NewOrgInvitation, NewOrganization, NewPasswordCredential, NewUser, OrgDomain,
    OrgDomainId, OrgDomainStatus, OrgDomainUpdate, OrgId, OrgInvitation, OrgInvitationId,
    OrgMembership, OrgSettings, Organization, OrganizationUpdate, Page, PageRequest, RevokeReason,
    RoleId, SecretHash, TenantId, UserId,
};
use anvil_core::ports::{AddMemberOutcome, OrgRepo, StorageError};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::connections::ConnectionRow;
use crate::convert::{enum_from, fetch_limit, from_json, hash, into_page, map_err, to_json};
use crate::roles::assign_role_in_org;
use crate::users::{insert_password, insert_user};

#[derive(Debug, Clone)]
pub(crate) struct PgOrgs {
    pub(crate) pool: PgPool,
}

/// Whether `err` is a foreign key violation (SQLSTATE 23503).
pub(crate) fn is_fk_violation(err: &sqlx::Error) -> bool {
    matches!(err, sqlx::Error::Database(db) if db.is_foreign_key_violation())
}

/// Maps a foreign key violation to `Conflict` with `message` (the ports report a reference to a
/// row that does not exist in the tenant as a conflict, like `create_link`); anything else goes
/// through [`map_err`].
pub(crate) fn fk_conflict(err: sqlx::Error, message: &str) -> StorageError {
    if is_fk_violation(&err) {
        return StorageError::Conflict(message.to_owned());
    }
    map_err(err)
}

// ---- rows ----

struct OrgRow {
    id: Uuid,
    tenant_id: Uuid,
    slug: String,
    display_name: String,
    mfa_policy: Option<String>,
    settings: serde_json::Value,
    metadata: serde_json::Value,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

impl OrgRow {
    fn into_model(self) -> Result<Organization, StorageError> {
        Ok(Organization {
            id: OrgId(self.id),
            tenant_id: TenantId(self.tenant_id),
            slug: self.slug,
            display_name: self.display_name,
            mfa_policy: self
                .mfa_policy
                .as_deref()
                .map(|m| enum_from("organization.mfa_policy", m, MfaPolicy::parse))
                .transpose()?,
            settings: from_json::<OrgSettings>("organization.settings", self.settings)?,
            metadata: self.metadata,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

struct MembershipRow {
    tenant_id: Uuid,
    org_id: Uuid,
    user_id: Uuid,
    created_at: OffsetDateTime,
}

impl MembershipRow {
    fn into_model(self) -> OrgMembership {
        OrgMembership {
            tenant_id: TenantId(self.tenant_id),
            org_id: OrgId(self.org_id),
            user_id: UserId(self.user_id),
            created_at: self.created_at,
        }
    }
}

struct InvitationRow {
    id: Uuid,
    tenant_id: Uuid,
    org_id: Uuid,
    email: String,
    role_ids: serde_json::Value,
    token_hash: Vec<u8>,
    invited_by_kind: String,
    invited_by_id: Option<String>,
    created_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    accepted_at: Option<OffsetDateTime>,
    accepted_user_id: Option<Uuid>,
    revoked_at: Option<OffsetDateTime>,
}

impl InvitationRow {
    fn into_model(self) -> Result<OrgInvitation, StorageError> {
        Ok(OrgInvitation {
            id: OrgInvitationId(self.id),
            tenant_id: TenantId(self.tenant_id),
            org_id: OrgId(self.org_id),
            email: self.email,
            role_ids: from_json::<Vec<RoleId>>("org_invitation.role_ids", self.role_ids)?,
            token_hash: hash("org_invitation.token_hash", &self.token_hash)?,
            invited_by: AuditActor {
                kind: enum_from(
                    "org_invitation.invited_by_kind",
                    &self.invited_by_kind,
                    ActorKind::parse,
                )?,
                id: self.invited_by_id,
            },
            created_at: self.created_at,
            expires_at: self.expires_at,
            accepted_at: self.accepted_at,
            accepted_user_id: self.accepted_user_id.map(UserId),
            revoked_at: self.revoked_at,
        })
    }

    /// Not accepted, not revoked and not expired at `now`.
    fn is_open(&self, now: OffsetDateTime) -> bool {
        self.accepted_at.is_none() && self.revoked_at.is_none() && self.expires_at > now
    }
}

struct DomainRow {
    id: Uuid,
    tenant_id: Uuid,
    org_id: Uuid,
    domain: String,
    token: String,
    status: String,
    connection_id: Option<Uuid>,
    routing: bool,
    allow_local_password: bool,
    verified_at: Option<OffsetDateTime>,
    last_checked_at: Option<OffsetDateTime>,
    failing_since: Option<OffsetDateTime>,
    created_at: OffsetDateTime,
}

impl DomainRow {
    fn into_model(self) -> Result<OrgDomain, StorageError> {
        Ok(OrgDomain {
            id: OrgDomainId(self.id),
            tenant_id: TenantId(self.tenant_id),
            org_id: OrgId(self.org_id),
            domain: self.domain,
            token: self.token,
            status: enum_from("org_domain.status", &self.status, OrgDomainStatus::parse)?,
            connection_id: self.connection_id.map(anvil_core::model::ConnectionId),
            routing: self.routing,
            allow_local_password: self.allow_local_password,
            verified_at: self.verified_at,
            last_checked_at: self.last_checked_at,
            failing_since: self.failing_since,
            created_at: self.created_at,
        })
    }
}

// ---- shared steps (on the caller's transaction) ----

/// Inserts the membership and assigns each of its roles in the org, on the caller's transaction.
/// `Added` on success. `AlreadyMember` if the membership exists (nothing else written).
/// `NotFound` if the org or the user does not exist in `tenant` or a role cannot be assigned in
/// the org; the membership row may then already be written, so the caller must roll back.
pub(crate) async fn insert_membership(
    conn: &mut sqlx::PgConnection,
    tenant: TenantId,
    m: &NewMembership,
) -> Result<AddMemberOutcome, StorageError> {
    let inserted = sqlx::query_scalar!(
        r#"INSERT INTO org_membership (tenant_id, org_id, user_id, created_at)
           SELECT $1, $2, $3, $4
            WHERE EXISTS (SELECT 1 FROM organization WHERE tenant_id = $1 AND id = $2)
              AND EXISTS (SELECT 1 FROM "user" WHERE tenant_id = $1 AND id = $3)
           ON CONFLICT (tenant_id, org_id, user_id) DO NOTHING
        RETURNING user_id"#,
        tenant.0,
        m.org_id.0,
        m.user_id.0,
        m.created_at,
    )
    .fetch_optional(&mut *conn)
    .await;
    let inserted = match inserted {
        Ok(row) => row.is_some(),
        // The org or the user was deleted between the checks and the insert.
        Err(e) if is_fk_violation(&e) => return Ok(AddMemberOutcome::NotFound),
        Err(e) => return Err(map_err(e)),
    };
    if !inserted {
        let member = is_member_on(&mut *conn, tenant, m.org_id, m.user_id).await?;
        return Ok(if member {
            AddMemberOutcome::AlreadyMember
        } else {
            AddMemberOutcome::NotFound
        });
    }
    for role in &m.role_ids {
        if !assign_role_in_org(&mut *conn, tenant, *role, m.user_id, m.org_id, m.created_at).await?
        {
            return Ok(AddMemberOutcome::NotFound);
        }
    }
    Ok(AddMemberOutcome::Added)
}

async fn is_member_on<'e, E>(
    exec: E,
    tenant: TenantId,
    org: OrgId,
    user: UserId,
) -> Result<bool, StorageError>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_scalar!(
        r#"SELECT EXISTS (SELECT 1 FROM org_membership
                           WHERE tenant_id = $1 AND org_id = $2 AND user_id = $3) AS "exists!""#,
        tenant.0,
        org.0,
        user.0,
    )
    .fetch_one(exec)
    .await
    .map_err(map_err)
}

/// Revokes the org-bound token families of `org` (of one user if `user` is set) that are still
/// active, with reason `admin`.
async fn revoke_org_families(
    conn: &mut sqlx::PgConnection,
    tenant: TenantId,
    org: OrgId,
    user: Option<UserId>,
    now: OffsetDateTime,
) -> Result<(), StorageError> {
    sqlx::query!(
        "UPDATE token_family SET revoked_at = $4, revoked_reason = $5
          WHERE tenant_id = $1 AND org_id = $2 AND ($3::uuid IS NULL OR user_id = $3)
            AND revoked_at IS NULL",
        tenant.0,
        org.0,
        user.map(|u| u.0),
        now,
        RevokeReason::Admin.as_str(),
    )
    .execute(&mut *conn)
    .await
    .map_err(map_err)?;
    Ok(())
}

/// Locks the invitation with `token_hash` in `tenant` for the rest of the transaction.
async fn lock_invitation(
    conn: &mut sqlx::PgConnection,
    tenant: TenantId,
    token_hash: &SecretHash,
) -> Result<Option<InvitationRow>, StorageError> {
    sqlx::query_as!(
        InvitationRow,
        "SELECT id, tenant_id, org_id, email, role_ids, token_hash, invited_by_kind,
                invited_by_id, created_at, expires_at, accepted_at, accepted_user_id, revoked_at
           FROM org_invitation
          WHERE tenant_id = $1 AND token_hash = $2
            FOR UPDATE",
        tenant.0,
        token_hash.as_bytes().as_slice(),
    )
    .fetch_optional(&mut *conn)
    .await
    .map_err(map_err)
}

/// Consumes the (locked, open) invitation for `user` and adds the membership with each of the
/// invitation's roles that can still be assigned in the org. `None` if the token was closed in
/// the meantime or the user became a member: the caller rolls back.
async fn consume_invitation(
    conn: &mut sqlx::PgConnection,
    tenant: TenantId,
    inv: &InvitationRow,
    user: UserId,
    now: OffsetDateTime,
) -> Result<Option<InvitationAccept>, StorageError> {
    let consumed = sqlx::query_scalar!(
        "UPDATE org_invitation SET accepted_at = $3, accepted_user_id = $4
          WHERE tenant_id = $1 AND id = $2
            AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > $3
      RETURNING id",
        tenant.0,
        inv.id,
        now,
        user.0,
    )
    .fetch_optional(&mut *conn)
    .await
    .map_err(map_err)?;
    if consumed.is_none() {
        return Ok(Some(InvitationAccept::Invalid));
    }
    let membership = NewMembership {
        org_id: OrgId(inv.org_id),
        user_id: user,
        role_ids: Vec::new(),
        created_at: now,
    };
    match insert_membership(conn, tenant, &membership).await? {
        AddMemberOutcome::Added => {}
        AddMemberOutcome::AlreadyMember => return Ok(None),
        AddMemberOutcome::NotFound => return Ok(Some(InvitationAccept::Invalid)),
    }
    // Roles deleted (or no longer assignable) since the invitation was sent are skipped.
    let role_ids: Vec<RoleId> = from_json("org_invitation.role_ids", inv.role_ids.clone())?;
    for role in role_ids {
        assign_role_in_org(&mut *conn, tenant, role, user, membership.org_id, now).await?;
    }
    Ok(Some(InvitationAccept::Accepted(OrgMembership {
        tenant_id: tenant,
        org_id: membership.org_id,
        user_id: user,
        created_at: now,
    })))
}

/// The org's routing claim of `domain`: verified, routing on, and routed to an enabled
/// connection of the same org.
async fn routed_domain_row(
    pool: &PgPool,
    tenant: TenantId,
    domain: &str,
) -> Result<Option<(OrgDomain, Connection)>, StorageError> {
    let row = sqlx::query!(
        r#"SELECT d.id, d.tenant_id, d.org_id, d.domain, d.token, d.status,
                  d.connection_id, d.routing, d.allow_local_password, d.verified_at,
                  d.last_checked_at, d.failing_since, d.created_at,
                  c.id AS c_id, c.tenant_id AS c_tenant_id, c.slug AS c_slug,
                  c.display_name AS c_display_name, c.kind AS c_kind, c.enabled AS c_enabled,
                  c.config AS c_config, c.secret_enc AS c_secret_enc,
                  c.trust_email_verified AS c_trust_email_verified,
                  c.created_at AS c_created_at, c.updated_at AS c_updated_at,
                  c.org_id AS c_org_id
             FROM org_domain d
             JOIN connection c
               ON c.tenant_id = d.tenant_id AND c.org_id = d.org_id AND c.id = d.connection_id
            WHERE d.tenant_id = $1 AND d.domain = $2 AND d.verified_at IS NOT NULL
              AND d.routing AND c.enabled"#,
        tenant.0,
        domain,
    )
    .fetch_optional(pool)
    .await
    .map_err(map_err)?;
    let Some(r) = row else {
        return Ok(None);
    };
    let domain = DomainRow {
        id: r.id,
        tenant_id: r.tenant_id,
        org_id: r.org_id,
        domain: r.domain,
        token: r.token,
        status: r.status,
        connection_id: r.connection_id,
        routing: r.routing,
        allow_local_password: r.allow_local_password,
        verified_at: r.verified_at,
        last_checked_at: r.last_checked_at,
        failing_since: r.failing_since,
        created_at: r.created_at,
    }
    .into_model()?;
    let connection = ConnectionRow {
        id: r.c_id,
        tenant_id: r.c_tenant_id,
        slug: r.c_slug,
        display_name: r.c_display_name,
        kind: r.c_kind,
        enabled: r.c_enabled,
        config: r.c_config,
        secret_enc: r.c_secret_enc,
        trust_email_verified: r.c_trust_email_verified,
        created_at: r.c_created_at,
        updated_at: r.c_updated_at,
        org_id: r.c_org_id,
    }
    .into_model()?;
    Ok(Some((domain, connection)))
}

#[async_trait::async_trait]
impl OrgRepo for PgOrgs {
    // ---- organizations ----

    async fn create(
        &self,
        tenant: TenantId,
        org: &NewOrganization,
    ) -> Result<Organization, StorageError> {
        let settings = to_json("organization.settings", &org.settings)?;
        sqlx::query!(
            "INSERT INTO organization
                 (id, tenant_id, slug, display_name, mfa_policy, settings, metadata, created_at,
                  updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)",
            org.id.0,
            tenant.0,
            org.slug,
            org.display_name,
            org.mfa_policy.map(|m| m.as_str()),
            settings,
            org.metadata,
            org.created_at,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| fk_conflict(e, "the tenant does not exist"))?;
        Ok(Organization {
            id: org.id,
            tenant_id: tenant,
            slug: org.slug.clone(),
            display_name: org.display_name.clone(),
            mfa_policy: org.mfa_policy,
            settings: org.settings.clone(),
            metadata: org.metadata.clone(),
            created_at: org.created_at,
            updated_at: org.created_at,
        })
    }

    async fn get(&self, tenant: TenantId, id: OrgId) -> Result<Option<Organization>, StorageError> {
        sqlx::query_as!(
            OrgRow,
            "SELECT id, tenant_id, slug, display_name, mfa_policy, settings, metadata, created_at,
                    updated_at
               FROM organization
              WHERE tenant_id = $1 AND id = $2",
            tenant.0,
            id.0,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?
        .map(OrgRow::into_model)
        .transpose()
    }

    async fn get_by_slug(
        &self,
        tenant: TenantId,
        slug: &str,
    ) -> Result<Option<Organization>, StorageError> {
        sqlx::query_as!(
            OrgRow,
            "SELECT id, tenant_id, slug, display_name, mfa_policy, settings, metadata, created_at,
                    updated_at
               FROM organization
              WHERE tenant_id = $1 AND slug = $2",
            tenant.0,
            slug,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?
        .map(OrgRow::into_model)
        .transpose()
    }

    async fn list(
        &self,
        tenant: TenantId,
        page: PageRequest,
    ) -> Result<Page<Organization>, StorageError> {
        let limit = page.clamped_limit();
        let rows = sqlx::query_as!(
            OrgRow,
            "SELECT id, tenant_id, slug, display_name, mfa_policy, settings, metadata, created_at,
                    updated_at
               FROM organization
              WHERE tenant_id = $1 AND ($2::uuid IS NULL OR id > $2)
              ORDER BY id
              LIMIT $3",
            tenant.0,
            page.after,
            fetch_limit(limit),
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?;
        let items = rows
            .into_iter()
            .map(OrgRow::into_model)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(into_page(items, limit, |o| o.id.0))
    }

    async fn update(
        &self,
        tenant: TenantId,
        id: OrgId,
        update: &OrganizationUpdate,
        now: OffsetDateTime,
    ) -> Result<Option<Organization>, StorageError> {
        let settings = update
            .settings
            .as_ref()
            .map(|s| to_json("organization.settings", s))
            .transpose()?;
        let (set_mfa, mfa) = match update.mfa_policy {
            Some(m) => (true, m.map(|m| m.as_str())),
            None => (false, None),
        };
        // One statement: a duplicate slug leaves the row unchanged.
        sqlx::query_as!(
            OrgRow,
            "UPDATE organization
                SET slug = COALESCE($3, slug),
                    display_name = COALESCE($4, display_name),
                    mfa_policy = CASE WHEN $5 THEN $6 ELSE mfa_policy END,
                    settings = COALESCE($7, settings),
                    metadata = COALESCE($8, metadata),
                    updated_at = $9
              WHERE tenant_id = $1 AND id = $2
          RETURNING id, tenant_id, slug, display_name, mfa_policy, settings, metadata,
                    created_at, updated_at",
            tenant.0,
            id.0,
            update.slug,
            update.display_name,
            set_mfa,
            mfa,
            settings,
            update.metadata,
            now,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?
        .map(OrgRow::into_model)
        .transpose()
    }

    async fn delete(
        &self,
        tenant: TenantId,
        id: OrgId,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        // One transaction. Deleting the org cascades (composite foreign keys) to memberships and
        // through them to every in-org assignment, to org-owned roles and their assignments, to
        // org connections and their identity links, to domains and to invitations. The org's
        // families are revoked and its branding deleted in the same transaction.
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        let done = sqlx::query!(
            "DELETE FROM organization WHERE tenant_id = $1 AND id = $2",
            tenant.0,
            id.0,
        )
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;
        if done.rows_affected() == 0 {
            return Ok(false);
        }
        revoke_org_families(&mut tx, tenant, id, None, now).await?;
        // The org's branding goes with it (its logo becomes unreferenced and is removed by the
        // next `purge_expired`).
        let scope_key = BrandingScope::Org(id).scope_key();
        sqlx::query!(
            "DELETE FROM branding WHERE tenant_id = $1 AND scope_key = $2",
            tenant.0,
            scope_key,
        )
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;
        tx.commit().await.map_err(map_err)?;
        Ok(true)
    }

    // ---- members ----

    async fn add_member(
        &self,
        tenant: TenantId,
        membership: &NewMembership,
    ) -> Result<AddMemberOutcome, StorageError> {
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        let outcome = insert_membership(&mut tx, tenant, membership).await?;
        if outcome == AddMemberOutcome::Added {
            tx.commit().await.map_err(map_err)?;
        }
        // Otherwise dropping `tx` rolls back whatever was written.
        Ok(outcome)
    }

    async fn remove_member(
        &self,
        tenant: TenantId,
        org: OrgId,
        user: UserId,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        // One transaction: the in-org assignments go with the membership (cascading foreign
        // key), then the user's families bound to this org are revoked.
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        let done = sqlx::query!(
            "DELETE FROM org_membership WHERE tenant_id = $1 AND org_id = $2 AND user_id = $3",
            tenant.0,
            org.0,
            user.0,
        )
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;
        if done.rows_affected() == 0 {
            return Ok(false);
        }
        revoke_org_families(&mut tx, tenant, org, Some(user), now).await?;
        tx.commit().await.map_err(map_err)?;
        Ok(true)
    }

    async fn is_member(
        &self,
        tenant: TenantId,
        org: OrgId,
        user: UserId,
    ) -> Result<bool, StorageError> {
        is_member_on(&self.pool, tenant, org, user).await
    }

    async fn list_members(
        &self,
        tenant: TenantId,
        org: OrgId,
        page: PageRequest,
    ) -> Result<Page<OrgMembership>, StorageError> {
        let limit = page.clamped_limit();
        let rows = sqlx::query_as!(
            MembershipRow,
            "SELECT tenant_id, org_id, user_id, created_at
               FROM org_membership
              WHERE tenant_id = $1 AND org_id = $2 AND ($3::uuid IS NULL OR user_id > $3)
              ORDER BY user_id
              LIMIT $4",
            tenant.0,
            org.0,
            page.after,
            fetch_limit(limit),
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?;
        let items = rows.into_iter().map(MembershipRow::into_model).collect();
        Ok(into_page(items, limit, |m| m.user_id.0))
    }

    async fn memberships_of_user(
        &self,
        tenant: TenantId,
        user: UserId,
    ) -> Result<Vec<Organization>, StorageError> {
        sqlx::query_as!(
            OrgRow,
            "SELECT o.id, o.tenant_id, o.slug, o.display_name, o.mfa_policy, o.settings,
                    o.metadata, o.created_at, o.updated_at
               FROM org_membership m
               JOIN organization o ON o.tenant_id = m.tenant_id AND o.id = m.org_id
              WHERE m.tenant_id = $1 AND m.user_id = $2
              ORDER BY o.slug COLLATE \"C\"",
            tenant.0,
            user.0,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?
        .into_iter()
        .map(OrgRow::into_model)
        .collect()
    }

    // ---- invitations ----

    async fn create_invitation(
        &self,
        tenant: TenantId,
        invitation: &NewOrgInvitation,
    ) -> Result<OrgInvitation, StorageError> {
        let role_ids = to_json("org_invitation.role_ids", &invitation.role_ids)?;
        sqlx::query!(
            "INSERT INTO org_invitation
                 (id, tenant_id, org_id, email, role_ids, token_hash, invited_by_kind,
                  invited_by_id, created_at, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
            invitation.id.0,
            tenant.0,
            invitation.org_id.0,
            invitation.email,
            role_ids,
            invitation.token_hash.as_bytes().as_slice(),
            invitation.invited_by.kind.as_str(),
            invitation.invited_by.id,
            invitation.created_at,
            invitation.expires_at,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| fk_conflict(e, "the organization does not exist in this tenant"))?;
        Ok(OrgInvitation {
            id: invitation.id,
            tenant_id: tenant,
            org_id: invitation.org_id,
            email: invitation.email.clone(),
            role_ids: invitation.role_ids.clone(),
            token_hash: invitation.token_hash,
            invited_by: invitation.invited_by.clone(),
            created_at: invitation.created_at,
            expires_at: invitation.expires_at,
            accepted_at: None,
            accepted_user_id: None,
            revoked_at: None,
        })
    }

    async fn list_invitations(
        &self,
        tenant: TenantId,
        org: OrgId,
        include_closed: bool,
    ) -> Result<Vec<OrgInvitation>, StorageError> {
        sqlx::query_as!(
            InvitationRow,
            "SELECT id, tenant_id, org_id, email, role_ids, token_hash, invited_by_kind,
                    invited_by_id, created_at, expires_at, accepted_at, accepted_user_id,
                    revoked_at
               FROM org_invitation
              WHERE tenant_id = $1 AND org_id = $2
                AND ($3 OR (accepted_at IS NULL AND revoked_at IS NULL))
              ORDER BY created_at DESC, id DESC",
            tenant.0,
            org.0,
            include_closed,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?
        .into_iter()
        .map(InvitationRow::into_model)
        .collect()
    }

    async fn revoke_invitation(
        &self,
        tenant: TenantId,
        org: OrgId,
        id: OrgInvitationId,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let done = sqlx::query!(
            "UPDATE org_invitation SET revoked_at = $4
              WHERE tenant_id = $1 AND org_id = $2 AND id = $3
                AND accepted_at IS NULL AND revoked_at IS NULL",
            tenant.0,
            org.0,
            id.0,
            now,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(done.rows_affected() > 0)
    }

    async fn invitation_by_hash(
        &self,
        tenant: TenantId,
        token_hash: &SecretHash,
    ) -> Result<Option<OrgInvitation>, StorageError> {
        sqlx::query_as!(
            InvitationRow,
            "SELECT id, tenant_id, org_id, email, role_ids, token_hash, invited_by_kind,
                    invited_by_id, created_at, expires_at, accepted_at, accepted_user_id,
                    revoked_at
               FROM org_invitation
              WHERE tenant_id = $1 AND token_hash = $2",
            tenant.0,
            token_hash.as_bytes().as_slice(),
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?
        .map(InvitationRow::into_model)
        .transpose()
    }

    async fn accept_invitation(
        &self,
        tenant: TenantId,
        token_hash: &SecretHash,
        user: UserId,
        user_verified_email: &str,
        now: OffsetDateTime,
    ) -> Result<InvitationAccept, StorageError> {
        // One transaction holding the invitation's row lock: a concurrent accept of the same
        // token waits here, then reads it accepted. Every early return drops `tx` (rollback).
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        let Some(inv) = lock_invitation(&mut tx, tenant, token_hash).await? else {
            return Ok(InvitationAccept::Invalid);
        };
        if !inv.is_open(now) {
            return Ok(InvitationAccept::Invalid);
        }
        let user_exists = sqlx::query_scalar!(
            r#"SELECT EXISTS (SELECT 1 FROM "user" WHERE tenant_id = $1 AND id = $2) AS "exists!""#,
            tenant.0,
            user.0,
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(map_err)?;
        if !user_exists {
            return Ok(InvitationAccept::Invalid);
        }
        if user_verified_email != inv.email {
            return Ok(InvitationAccept::EmailMismatch);
        }
        if is_member_on(&mut *tx, tenant, OrgId(inv.org_id), user).await? {
            return Ok(InvitationAccept::AlreadyMember);
        }
        match consume_invitation(&mut tx, tenant, &inv, user, now).await? {
            Some(InvitationAccept::Accepted(m)) => {
                tx.commit().await.map_err(map_err)?;
                Ok(InvitationAccept::Accepted(m))
            }
            Some(other) => Ok(other),
            None => Ok(InvitationAccept::AlreadyMember),
        }
    }

    async fn accept_invitation_with_new_user(
        &self,
        tenant: TenantId,
        token_hash: &SecretHash,
        user: &NewUser,
        password: &NewPasswordCredential,
        now: OffsetDateTime,
    ) -> Result<InvitationAccept, StorageError> {
        // Same lock as `accept_invitation`; the user insert's `Conflict` rolls everything back
        // and leaves the token open.
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        let Some(inv) = lock_invitation(&mut tx, tenant, token_hash).await? else {
            return Ok(InvitationAccept::Invalid);
        };
        if !inv.is_open(now) {
            return Ok(InvitationAccept::Invalid);
        }
        if user.email != inv.email {
            return Ok(InvitationAccept::EmailMismatch);
        }
        insert_user(&mut *tx, tenant, user).await?;
        insert_password(&mut *tx, tenant, user.id, password).await?;
        match consume_invitation(&mut tx, tenant, &inv, user.id, now).await? {
            Some(InvitationAccept::Accepted(m)) => {
                tx.commit().await.map_err(map_err)?;
                Ok(InvitationAccept::Accepted(m))
            }
            Some(other) => Ok(other),
            // A freshly inserted user cannot already be a member.
            None => Err(StorageError::Conflict(
                "the new user is already a member".to_owned(),
            )),
        }
    }

    // ---- domains ----

    async fn create_domain(
        &self,
        tenant: TenantId,
        domain: &NewOrgDomain,
    ) -> Result<OrgDomain, StorageError> {
        // The composite foreign keys refuse an unknown org and a routing connection that is not
        // a connection of the same org (a tenant connection has org_id NULL and never matches).
        sqlx::query!(
            "INSERT INTO org_domain
                 (id, tenant_id, org_id, domain, token, status, connection_id, routing,
                  allow_local_password, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
            domain.id.0,
            tenant.0,
            domain.org_id.0,
            domain.domain,
            domain.token,
            OrgDomainStatus::Pending.as_str(),
            domain.connection_id.map(|c| c.0),
            domain.routing,
            domain.allow_local_password,
            domain.created_at,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| {
            fk_conflict(
                e,
                "the organization or the routing connection does not exist in this organization",
            )
        })?;
        Ok(OrgDomain {
            id: domain.id,
            tenant_id: tenant,
            org_id: domain.org_id,
            domain: domain.domain.clone(),
            token: domain.token.clone(),
            status: OrgDomainStatus::Pending,
            connection_id: domain.connection_id,
            routing: domain.routing,
            allow_local_password: domain.allow_local_password,
            verified_at: None,
            last_checked_at: None,
            failing_since: None,
            created_at: domain.created_at,
        })
    }

    async fn list_domains(
        &self,
        tenant: TenantId,
        org: OrgId,
    ) -> Result<Vec<OrgDomain>, StorageError> {
        sqlx::query_as!(
            DomainRow,
            "SELECT id, tenant_id, org_id, domain, token, status, connection_id, routing,
                    allow_local_password, verified_at, last_checked_at, failing_since, created_at
               FROM org_domain
              WHERE tenant_id = $1 AND org_id = $2
              ORDER BY domain COLLATE \"C\"",
            tenant.0,
            org.0,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?
        .into_iter()
        .map(DomainRow::into_model)
        .collect()
    }

    async fn get_domain(
        &self,
        tenant: TenantId,
        id: OrgDomainId,
    ) -> Result<Option<OrgDomain>, StorageError> {
        sqlx::query_as!(
            DomainRow,
            "SELECT id, tenant_id, org_id, domain, token, status, connection_id, routing,
                    allow_local_password, verified_at, last_checked_at, failing_since, created_at
               FROM org_domain
              WHERE tenant_id = $1 AND id = $2",
            tenant.0,
            id.0,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?
        .map(DomainRow::into_model)
        .transpose()
    }

    async fn update_domain(
        &self,
        tenant: TenantId,
        id: OrgDomainId,
        update: &OrgDomainUpdate,
        _now: OffsetDateTime,
    ) -> Result<Option<OrgDomain>, StorageError> {
        let (set_conn, conn) = match update.connection_id {
            Some(c) => (true, c.map(|c| c.0)),
            None => (false, None),
        };
        // One statement; a routing connection outside the domain's org fails the composite
        // foreign key and changes nothing.
        let row = sqlx::query_as!(
            DomainRow,
            "UPDATE org_domain
                SET connection_id = CASE WHEN $3 THEN $4 ELSE connection_id END,
                    routing = COALESCE($5, routing),
                    allow_local_password = COALESCE($6, allow_local_password)
              WHERE tenant_id = $1 AND id = $2
          RETURNING id, tenant_id, org_id, domain, token, status, connection_id, routing,
                    allow_local_password, verified_at, last_checked_at, failing_since,
                    created_at",
            tenant.0,
            id.0,
            set_conn,
            conn,
            update.routing,
            update.allow_local_password,
        )
        .fetch_optional(&self.pool)
        .await;
        match row {
            Ok(row) => row.map(DomainRow::into_model).transpose(),
            Err(e) if is_fk_violation(&e) => Ok(None),
            Err(e) => Err(map_err(e)),
        }
    }

    async fn delete_domain(&self, tenant: TenantId, id: OrgDomainId) -> Result<bool, StorageError> {
        let done = sqlx::query!(
            "DELETE FROM org_domain WHERE tenant_id = $1 AND id = $2",
            tenant.0,
            id.0,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(done.rows_affected() > 0)
    }

    async fn mark_verified(
        &self,
        tenant: TenantId,
        id: OrgDomainId,
        now: OffsetDateTime,
    ) -> Result<Option<OrgDomain>, StorageError> {
        // One statement; the partial unique index over verified claims decides between orgs (a
        // concurrent verifier waits for the first one's commit, then hits the unique violation).
        let row = sqlx::query_as!(
            DomainRow,
            "UPDATE org_domain
                SET status = $3, verified_at = $4, last_checked_at = $4, failing_since = NULL
              WHERE tenant_id = $1 AND id = $2 AND verified_at IS NULL
          RETURNING id, tenant_id, org_id, domain, token, status, connection_id, routing,
                    allow_local_password, verified_at, last_checked_at, failing_since,
                    created_at",
            tenant.0,
            id.0,
            OrgDomainStatus::Verified.as_str(),
            now,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?;
        match row {
            Some(row) => row.into_model().map(Some),
            // Unknown, or already verified (returned unchanged).
            None => self.get_domain(tenant, id).await,
        }
    }

    async fn record_check(
        &self,
        tenant: TenantId,
        id: OrgDomainId,
        ok: bool,
        now: OffsetDateTime,
    ) -> Result<Option<OrgDomain>, StorageError> {
        sqlx::query_as!(
            DomainRow,
            "UPDATE org_domain
                SET last_checked_at = $4,
                    failing_since = CASE WHEN $3 THEN NULL ELSE COALESCE(failing_since, $4) END
              WHERE tenant_id = $1 AND id = $2
          RETURNING id, tenant_id, org_id, domain, token, status, connection_id, routing,
                    allow_local_password, verified_at, last_checked_at, failing_since,
                    created_at",
            tenant.0,
            id.0,
            ok,
            now,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?
        .map(DomainRow::into_model)
        .transpose()
    }

    async fn unverify(
        &self,
        tenant: TenantId,
        id: OrgDomainId,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let done = sqlx::query!(
            "UPDATE org_domain
                SET status = $3, verified_at = NULL, failing_since = NULL, last_checked_at = $4
              WHERE tenant_id = $1 AND id = $2 AND verified_at IS NOT NULL",
            tenant.0,
            id.0,
            OrgDomainStatus::Pending.as_str(),
            now,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(done.rows_affected() > 0)
    }

    async fn routed_domain(
        &self,
        tenant: TenantId,
        domain: &str,
    ) -> Result<Option<(OrgDomain, Connection)>, StorageError> {
        routed_domain_row(&self.pool, tenant, domain).await
    }

    async fn routing_connections(&self, tenant: TenantId) -> Result<Vec<Connection>, StorageError> {
        sqlx::query_as!(
            ConnectionRow,
            "SELECT c.id, c.tenant_id, c.slug, c.display_name, c.kind, c.enabled, c.config,
                    c.secret_enc, c.trust_email_verified, c.created_at, c.updated_at, c.org_id
               FROM connection c
              WHERE c.tenant_id = $1 AND c.enabled
                AND EXISTS (SELECT 1 FROM org_domain d
                             WHERE d.tenant_id = c.tenant_id AND d.connection_id = c.id
                               AND d.org_id = c.org_id AND d.verified_at IS NOT NULL
                               AND d.routing)
              ORDER BY c.id",
            tenant.0,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?
        .into_iter()
        .map(ConnectionRow::into_model)
        .collect()
    }

    async fn verified_domains_of_org(
        &self,
        tenant: TenantId,
        org: OrgId,
    ) -> Result<Vec<String>, StorageError> {
        sqlx::query_scalar!(
            "SELECT domain
               FROM org_domain
              WHERE tenant_id = $1 AND org_id = $2 AND verified_at IS NOT NULL
              ORDER BY domain COLLATE \"C\"",
            tenant.0,
            org.0,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)
    }

    async fn due_for_recheck(
        &self,
        checked_before: OffsetDateTime,
        limit: u32,
    ) -> Result<Vec<OrgDomain>, StorageError> {
        sqlx::query_as!(
            DomainRow,
            "SELECT id, tenant_id, org_id, domain, token, status, connection_id, routing,
                    allow_local_password, verified_at, last_checked_at, failing_since, created_at
               FROM org_domain
              WHERE verified_at IS NOT NULL
                AND (last_checked_at IS NULL OR last_checked_at < $1)
              ORDER BY last_checked_at ASC NULLS FIRST, id
              LIMIT $2",
            checked_before,
            i64::from(limit),
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?
        .into_iter()
        .map(DomainRow::into_model)
        .collect()
    }
}
