//! `OrgRepo` on SQLite: organizations, memberships, invitations and domain claims.
//!
//! Every row references its org through the composite `(tenant_id, org_id)` foreign key with ON
//! DELETE CASCADE, so deleting an org removes its memberships (and through them every role
//! assignment in the org), its org-owned roles, its connections with their identity links, its
//! domains and its invitations in the same statement. Token families have no foreign key to the
//! org: the intents that end a membership revoke the affected families in their transaction.
//!
//! Multi-write intents (`add_member`, `remove_member`, `delete`, both invitation accepts) run as
//! one transaction on the single writer connection, which also serialises concurrent accepts and
//! verifications: the conditional UPDATE or the partial unique index decides the single winner.

use anvil_core::model::{
    ActorKind, AuditActor, Connection, InvitationAccept, NewMembership, NewOrgDomain,
    NewOrgInvitation, NewOrganization, NewPasswordCredential, NewUser, OrgDomain, OrgDomainId,
    OrgDomainStatus, OrgDomainUpdate, OrgId, OrgInvitation, OrgInvitationId, OrgMembership,
    Organization, OrganizationUpdate, Page, PageRequest, RevokeReason, SecretHash, TenantId,
    UserId,
};
use anvil_core::model::{BrandingScope, MfaPolicy};
use anvil_core::ports::{AddMemberOutcome, OrgRepo, StorageError};
use sqlx::{SqliteConnection, SqlitePool};
use time::OffsetDateTime;

use crate::connections::ConnectionRow;
use crate::convert::{
    blob_to_hash, from_json, into_page, map_err, ms_to_odt, odt_to_ms, opt_ms_to_odt, parse_enum,
    to_json,
};
use crate::roles::assign_in_org_on;
use crate::users::{insert_password, insert_user};

#[derive(Debug, Clone)]
pub(crate) struct SqliteOrgs {
    pub(crate) writer: SqlitePool,
    pub(crate) reader: SqlitePool,
}

/// Maps a driver error like [`map_err`], and a foreign key violation (a reference to a row that
/// does not exist in the tenant) to `Conflict` with `what` as the message.
pub(crate) fn map_fk_err(what: &'static str) -> impl Fn(sqlx::Error) -> StorageError {
    move |e| match &e {
        sqlx::Error::Database(db) if db.is_foreign_key_violation() => {
            StorageError::Conflict(what.to_owned())
        }
        _ => map_err(e),
    }
}

// ---- rows -----------------------------------------------------------------------------------

struct OrgRow {
    id: uuid::Uuid,
    tenant_id: uuid::Uuid,
    slug: String,
    display_name: String,
    mfa_policy: Option<String>,
    settings: String,
    metadata: String,
    created_at: i64,
    updated_at: i64,
}

impl TryFrom<OrgRow> for Organization {
    type Error = StorageError;

    fn try_from(r: OrgRow) -> Result<Self, StorageError> {
        Ok(Organization {
            id: OrgId(r.id),
            tenant_id: TenantId(r.tenant_id),
            slug: r.slug,
            display_name: r.display_name,
            mfa_policy: r
                .mfa_policy
                .as_deref()
                .map(|p| parse_enum(p, MfaPolicy::parse, "organization.mfa_policy"))
                .transpose()?,
            settings: from_json(&r.settings, "organization.settings")?,
            metadata: from_json(&r.metadata, "organization.metadata")?,
            created_at: ms_to_odt(r.created_at)?,
            updated_at: ms_to_odt(r.updated_at)?,
        })
    }
}

struct MemberRow {
    tenant_id: uuid::Uuid,
    org_id: uuid::Uuid,
    user_id: uuid::Uuid,
    created_at: i64,
}

impl TryFrom<MemberRow> for OrgMembership {
    type Error = StorageError;

    fn try_from(r: MemberRow) -> Result<Self, StorageError> {
        Ok(OrgMembership {
            tenant_id: TenantId(r.tenant_id),
            org_id: OrgId(r.org_id),
            user_id: UserId(r.user_id),
            created_at: ms_to_odt(r.created_at)?,
        })
    }
}

struct InvitationRow {
    id: uuid::Uuid,
    tenant_id: uuid::Uuid,
    org_id: uuid::Uuid,
    email: String,
    roles: String,
    token_hash: Vec<u8>,
    invited_by_kind: String,
    invited_by_id: Option<String>,
    created_at: i64,
    expires_at: i64,
    accepted_at: Option<i64>,
    accepted_user_id: Option<uuid::Uuid>,
    revoked_at: Option<i64>,
}

impl TryFrom<InvitationRow> for OrgInvitation {
    type Error = StorageError;

    fn try_from(r: InvitationRow) -> Result<Self, StorageError> {
        Ok(OrgInvitation {
            id: OrgInvitationId(r.id),
            tenant_id: TenantId(r.tenant_id),
            org_id: OrgId(r.org_id),
            email: r.email,
            role_ids: from_json(&r.roles, "org_invitation.roles")?,
            token_hash: blob_to_hash(&r.token_hash, "org_invitation.token_hash")?,
            invited_by: AuditActor {
                kind: parse_enum(
                    &r.invited_by_kind,
                    ActorKind::parse,
                    "org_invitation.invited_by_kind",
                )?,
                id: r.invited_by_id,
            },
            created_at: ms_to_odt(r.created_at)?,
            expires_at: ms_to_odt(r.expires_at)?,
            accepted_at: opt_ms_to_odt(r.accepted_at)?,
            accepted_user_id: r.accepted_user_id.map(UserId),
            revoked_at: opt_ms_to_odt(r.revoked_at)?,
        })
    }
}

struct DomainRow {
    id: uuid::Uuid,
    tenant_id: uuid::Uuid,
    org_id: uuid::Uuid,
    domain: String,
    token: String,
    status: String,
    connection_id: Option<uuid::Uuid>,
    routing: bool,
    allow_local_password: bool,
    verified_at: Option<i64>,
    last_checked_at: Option<i64>,
    failing_since: Option<i64>,
    created_at: i64,
}

impl TryFrom<DomainRow> for OrgDomain {
    type Error = StorageError;

    fn try_from(r: DomainRow) -> Result<Self, StorageError> {
        Ok(OrgDomain {
            id: OrgDomainId(r.id),
            tenant_id: TenantId(r.tenant_id),
            org_id: OrgId(r.org_id),
            domain: r.domain,
            token: r.token,
            status: parse_enum(&r.status, OrgDomainStatus::parse, "org_domain.status")?,
            connection_id: r.connection_id.map(anvil_core::model::ConnectionId),
            routing: r.routing,
            allow_local_password: r.allow_local_password,
            verified_at: opt_ms_to_odt(r.verified_at)?,
            last_checked_at: opt_ms_to_odt(r.last_checked_at)?,
            failing_since: opt_ms_to_odt(r.failing_since)?,
            created_at: ms_to_odt(r.created_at)?,
        })
    }
}

/// A routed domain claim joined with its connection (`routed_domain`).
struct RoutedRow {
    d_id: uuid::Uuid,
    d_tenant_id: uuid::Uuid,
    d_org_id: uuid::Uuid,
    d_domain: String,
    d_token: String,
    d_status: String,
    d_connection_id: Option<uuid::Uuid>,
    d_routing: bool,
    d_allow_local_password: bool,
    d_verified_at: Option<i64>,
    d_last_checked_at: Option<i64>,
    d_failing_since: Option<i64>,
    d_created_at: i64,
    c_id: uuid::Uuid,
    c_tenant_id: uuid::Uuid,
    c_slug: String,
    c_display_name: String,
    c_enabled: bool,
    c_config: String,
    c_secret_enc: Option<Vec<u8>>,
    c_trust_email_verified: bool,
    c_created_at: i64,
    c_updated_at: i64,
    c_org_id: Option<uuid::Uuid>,
}

impl TryFrom<RoutedRow> for (OrgDomain, Connection) {
    type Error = StorageError;

    fn try_from(r: RoutedRow) -> Result<Self, StorageError> {
        let domain = OrgDomain::try_from(DomainRow {
            id: r.d_id,
            tenant_id: r.d_tenant_id,
            org_id: r.d_org_id,
            domain: r.d_domain,
            token: r.d_token,
            status: r.d_status,
            connection_id: r.d_connection_id,
            routing: r.d_routing,
            allow_local_password: r.d_allow_local_password,
            verified_at: r.d_verified_at,
            last_checked_at: r.d_last_checked_at,
            failing_since: r.d_failing_since,
            created_at: r.d_created_at,
        })?;
        let connection = Connection::try_from(ConnectionRow {
            id: r.c_id,
            tenant_id: r.c_tenant_id,
            slug: r.c_slug,
            display_name: r.c_display_name,
            enabled: r.c_enabled,
            config: r.c_config,
            secret_enc: r.c_secret_enc,
            trust_email_verified: r.c_trust_email_verified,
            created_at: r.c_created_at,
            updated_at: r.c_updated_at,
            org_id: r.c_org_id,
        })?;
        Ok((domain, connection))
    }
}

// ---- shared intent steps --------------------------------------------------------------------

/// Adds the membership and assigns each of its roles in the org, on `conn` (inside the caller's
/// transaction). `Added` means rows were written; with `AlreadyMember` or `NotFound` the caller
/// must roll back (a `NotFound` after the membership insert leaves a partial membership in the
/// open transaction).
pub(crate) async fn insert_membership_on(
    conn: &mut SqliteConnection,
    tenant: TenantId,
    membership: &NewMembership,
) -> Result<AddMemberOutcome, StorageError> {
    let created_at = odt_to_ms(membership.created_at);
    // The SELECT only yields a row if both the org and the user exist in `tenant`. `WHERE` before
    // `ON CONFLICT` is required: SQLite would otherwise parse the upsert's `ON` as a join
    // constraint of the SELECT.
    let done = sqlx::query!(
        "INSERT INTO org_membership (tenant_id, org_id, user_id, created_at)
         SELECT o.tenant_id, o.id, u.id, ?4
           FROM organization o JOIN user u ON u.tenant_id = o.tenant_id
          WHERE o.tenant_id = ?1 AND o.id = ?2 AND u.id = ?3
         ON CONFLICT (tenant_id, org_id, user_id) DO NOTHING",
        tenant.0,
        membership.org_id.0,
        membership.user_id.0,
        created_at,
    )
    .execute(&mut *conn)
    .await
    .map_err(map_err)?;
    if done.rows_affected() == 0 {
        return Ok(
            if is_member_on(conn, tenant, membership.org_id, membership.user_id).await? {
                AddMemberOutcome::AlreadyMember
            } else {
                AddMemberOutcome::NotFound
            },
        );
    }
    for role in &membership.role_ids {
        let held = assign_in_org_on(
            conn,
            tenant,
            *role,
            membership.user_id,
            membership.org_id,
            membership.created_at,
        )
        .await?;
        if !held {
            return Ok(AddMemberOutcome::NotFound);
        }
    }
    Ok(AddMemberOutcome::Added)
}

async fn is_member_on(
    conn: &mut SqliteConnection,
    tenant: TenantId,
    org: OrgId,
    user: UserId,
) -> Result<bool, StorageError> {
    sqlx::query_scalar!(
        r#"SELECT EXISTS(SELECT 1 FROM org_membership
                          WHERE tenant_id = ?1 AND org_id = ?2 AND user_id = ?3)
                  AS "member!: bool""#,
        tenant.0,
        org.0,
        user.0,
    )
    .fetch_one(conn)
    .await
    .map_err(map_err)
}

/// Revokes the token families bound to `org` (only `user`'s if given) that are still active,
/// with reason `Admin`, on `conn`.
async fn revoke_org_families_on(
    conn: &mut SqliteConnection,
    tenant: TenantId,
    org: OrgId,
    user: Option<UserId>,
    now: OffsetDateTime,
) -> Result<(), StorageError> {
    let reason = RevokeReason::Admin.as_str();
    let now_ms = odt_to_ms(now);
    let user = user.map(|u| u.0);
    sqlx::query!(
        "UPDATE token_family SET revoked_at = ?4, revoked_reason = ?5
          WHERE tenant_id = ?1 AND org_id = ?2 AND (?3 IS NULL OR user_id = ?3)
            AND revoked_at IS NULL",
        tenant.0,
        org.0,
        user,
        now_ms,
        reason,
    )
    .execute(conn)
    .await
    .map_err(map_err)?;
    Ok(())
}

async fn invitation_on(
    conn: &mut SqliteConnection,
    tenant: TenantId,
    token_hash: &SecretHash,
) -> Result<Option<OrgInvitation>, StorageError> {
    let hash = token_hash.as_bytes().as_slice();
    sqlx::query_as!(
        InvitationRow,
        r#"SELECT id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                  org_id AS "org_id!: uuid::Uuid", email AS "email!", roles AS "roles!",
                  token_hash AS "token_hash!", invited_by_kind AS "invited_by_kind!",
                  invited_by_id AS "invited_by_id?", created_at AS "created_at!",
                  expires_at AS "expires_at!", accepted_at AS "accepted_at?",
                  accepted_user_id AS "accepted_user_id?: uuid::Uuid",
                  revoked_at AS "revoked_at?"
             FROM org_invitation WHERE tenant_id = ?1 AND token_hash = ?2"#,
        tenant.0,
        hash,
    )
    .fetch_optional(conn)
    .await
    .map_err(map_err)?
    .map(OrgInvitation::try_from)
    .transpose()
}

fn is_open(invitation: &OrgInvitation, now: OffsetDateTime) -> bool {
    invitation.accepted_at.is_none()
        && invitation.revoked_at.is_none()
        && invitation.expires_at > now
}

/// The consuming step of an accept: one conditional UPDATE. `false` if the token was no longer
/// open (another accept, a revocation or the expiry won).
async fn consume_invitation_on(
    conn: &mut SqliteConnection,
    tenant: TenantId,
    id: OrgInvitationId,
    user: UserId,
    now: OffsetDateTime,
) -> Result<bool, StorageError> {
    let now_ms = odt_to_ms(now);
    let done = sqlx::query!(
        "UPDATE org_invitation SET accepted_at = ?4, accepted_user_id = ?3
          WHERE tenant_id = ?1 AND id = ?2
            AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > ?4",
        tenant.0,
        id.0,
        user.0,
        now_ms,
    )
    .execute(conn)
    .await
    .map_err(map_err)?;
    Ok(done.rows_affected() == 1)
}

/// Adds the accepting user as a member with each of the invitation's roles that still exist and
/// can be assigned in the org (deleted roles are skipped), on `conn`.
async fn join_from_invitation_on(
    conn: &mut SqliteConnection,
    invitation: &OrgInvitation,
    user: UserId,
    now: OffsetDateTime,
) -> Result<Option<OrgMembership>, StorageError> {
    let tenant = invitation.tenant_id;
    let outcome = insert_membership_on(
        conn,
        tenant,
        &NewMembership {
            org_id: invitation.org_id,
            user_id: user,
            role_ids: Vec::new(),
            created_at: now,
        },
    )
    .await?;
    if outcome != AddMemberOutcome::Added {
        return Ok(None);
    }
    for role in &invitation.role_ids {
        assign_in_org_on(conn, tenant, *role, user, invitation.org_id, now).await?;
    }
    Ok(Some(OrgMembership {
        tenant_id: tenant,
        org_id: invitation.org_id,
        user_id: user,
        created_at: now,
    }))
}

async fn domain_on(
    conn: &mut SqliteConnection,
    tenant: TenantId,
    id: OrgDomainId,
) -> Result<Option<OrgDomain>, StorageError> {
    sqlx::query_as!(
        DomainRow,
        r#"SELECT id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                  org_id AS "org_id!: uuid::Uuid", domain AS "domain!", token AS "token!",
                  status AS "status!", connection_id AS "connection_id?: uuid::Uuid",
                  routing AS "routing!: bool",
                  allow_local_password AS "allow_local_password!: bool",
                  verified_at AS "verified_at?", last_checked_at AS "last_checked_at?",
                  failing_since AS "failing_since?", created_at AS "created_at!"
             FROM org_domain WHERE tenant_id = ?1 AND id = ?2"#,
        tenant.0,
        id.0,
    )
    .fetch_optional(conn)
    .await
    .map_err(map_err)?
    .map(OrgDomain::try_from)
    .transpose()
}

#[async_trait::async_trait]
impl OrgRepo for SqliteOrgs {
    // ---- organizations ----

    async fn create(
        &self,
        tenant: TenantId,
        org: &NewOrganization,
    ) -> Result<Organization, StorageError> {
        let mfa_policy = org.mfa_policy.map(|p| p.as_str());
        let settings = to_json(&org.settings, "organization.settings")?;
        let metadata = to_json(&org.metadata, "organization.metadata")?;
        let created_at = odt_to_ms(org.created_at);
        sqlx::query!(
            "INSERT INTO organization
                 (id, tenant_id, slug, display_name, mfa_policy, settings, metadata, created_at,
                  updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)",
            org.id.0,
            tenant.0,
            org.slug,
            org.display_name,
            mfa_policy,
            settings,
            metadata,
            created_at,
        )
        .execute(&self.writer)
        .await
        .map_err(map_fk_err("organization references an unknown tenant"))?;
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
            r#"SELECT id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      slug AS "slug!", display_name AS "display_name!",
                      mfa_policy AS "mfa_policy?", settings AS "settings!",
                      metadata AS "metadata!", created_at AS "created_at!",
                      updated_at AS "updated_at!"
                 FROM organization WHERE tenant_id = ?1 AND id = ?2"#,
            tenant.0,
            id.0,
        )
        .fetch_optional(&self.reader)
        .await
        .map_err(map_err)?
        .map(Organization::try_from)
        .transpose()
    }

    async fn get_by_slug(
        &self,
        tenant: TenantId,
        slug: &str,
    ) -> Result<Option<Organization>, StorageError> {
        sqlx::query_as!(
            OrgRow,
            r#"SELECT id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      slug AS "slug!", display_name AS "display_name!",
                      mfa_policy AS "mfa_policy?", settings AS "settings!",
                      metadata AS "metadata!", created_at AS "created_at!",
                      updated_at AS "updated_at!"
                 FROM organization WHERE tenant_id = ?1 AND slug = ?2"#,
            tenant.0,
            slug,
        )
        .fetch_optional(&self.reader)
        .await
        .map_err(map_err)?
        .map(Organization::try_from)
        .transpose()
    }

    async fn list(
        &self,
        tenant: TenantId,
        page: PageRequest,
    ) -> Result<Page<Organization>, StorageError> {
        let limit = page.clamped_limit();
        let fetch = i64::from(limit) + 1;
        let rows = sqlx::query_as!(
            OrgRow,
            r#"SELECT id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      slug AS "slug!", display_name AS "display_name!",
                      mfa_policy AS "mfa_policy?", settings AS "settings!",
                      metadata AS "metadata!", created_at AS "created_at!",
                      updated_at AS "updated_at!"
                 FROM organization
                WHERE tenant_id = ?1 AND (?2 IS NULL OR id > ?2)
                ORDER BY id
                LIMIT ?3"#,
            tenant.0,
            page.after,
            fetch,
        )
        .fetch_all(&self.reader)
        .await
        .map_err(map_err)?;
        let items = rows
            .into_iter()
            .map(Organization::try_from)
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
        let set_mfa = update.mfa_policy.is_some();
        let mfa_policy = update.mfa_policy.flatten().map(|p| p.as_str());
        let settings = update
            .settings
            .as_ref()
            .map(|s| to_json(s, "organization.settings"))
            .transpose()?;
        let metadata = update
            .metadata
            .as_ref()
            .map(|m| to_json(m, "organization.metadata"))
            .transpose()?;
        let now_ms = odt_to_ms(now);
        sqlx::query_as!(
            OrgRow,
            r#"UPDATE organization
                  SET slug = COALESCE(?3, slug),
                      display_name = COALESCE(?4, display_name),
                      mfa_policy = CASE WHEN ?5 THEN ?6 ELSE mfa_policy END,
                      settings = COALESCE(?7, settings),
                      metadata = COALESCE(?8, metadata),
                      updated_at = ?9
                WHERE tenant_id = ?1 AND id = ?2
            RETURNING id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      slug AS "slug!", display_name AS "display_name!",
                      mfa_policy AS "mfa_policy?", settings AS "settings!",
                      metadata AS "metadata!", created_at AS "created_at!",
                      updated_at AS "updated_at!""#,
            tenant.0,
            id.0,
            update.slug,
            update.display_name,
            set_mfa,
            mfa_policy,
            settings,
            metadata,
            now_ms,
        )
        .fetch_optional(&self.writer)
        .await
        .map_err(map_err)?
        .map(Organization::try_from)
        .transpose()
    }

    async fn delete(
        &self,
        tenant: TenantId,
        id: OrgId,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let mut tx = self.writer.begin().await.map_err(map_err)?;
        // Memberships (and with them every assignment in the org), org-owned roles (and their
        // assignments), connections (and their identity links), domains and invitations go by
        // ON DELETE CASCADE in this statement.
        let done = sqlx::query!(
            "DELETE FROM organization WHERE tenant_id = ?1 AND id = ?2",
            tenant.0,
            id.0,
        )
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;
        if done.rows_affected() == 0 {
            tx.rollback().await.map_err(map_err)?;
            return Ok(false);
        }
        revoke_org_families_on(&mut tx, tenant, id, None, now).await?;
        // The org's branding goes with it (its logo becomes unreferenced and is removed by the
        // next `purge_expired`).
        let scope_key = BrandingScope::Org(id).scope_key();
        sqlx::query!(
            "DELETE FROM branding WHERE tenant_id = ?1 AND scope_key = ?2",
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
        let mut tx = self.writer.begin().await.map_err(map_err)?;
        let outcome = insert_membership_on(&mut tx, tenant, membership).await?;
        if outcome == AddMemberOutcome::Added {
            tx.commit().await.map_err(map_err)?;
        } else {
            tx.rollback().await.map_err(map_err)?;
        }
        Ok(outcome)
    }

    async fn remove_member(
        &self,
        tenant: TenantId,
        org: OrgId,
        user: UserId,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let mut tx = self.writer.begin().await.map_err(map_err)?;
        // The user's assignments in the org go by ON DELETE CASCADE (membership foreign key).
        let done = sqlx::query!(
            "DELETE FROM org_membership WHERE tenant_id = ?1 AND org_id = ?2 AND user_id = ?3",
            tenant.0,
            org.0,
            user.0,
        )
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;
        if done.rows_affected() == 0 {
            tx.rollback().await.map_err(map_err)?;
            return Ok(false);
        }
        revoke_org_families_on(&mut tx, tenant, org, Some(user), now).await?;
        tx.commit().await.map_err(map_err)?;
        Ok(true)
    }

    async fn is_member(
        &self,
        tenant: TenantId,
        org: OrgId,
        user: UserId,
    ) -> Result<bool, StorageError> {
        let mut conn = self.reader.acquire().await.map_err(map_err)?;
        is_member_on(&mut conn, tenant, org, user).await
    }

    async fn list_members(
        &self,
        tenant: TenantId,
        org: OrgId,
        page: PageRequest,
    ) -> Result<Page<OrgMembership>, StorageError> {
        let limit = page.clamped_limit();
        let fetch = i64::from(limit) + 1;
        let rows = sqlx::query_as!(
            MemberRow,
            r#"SELECT tenant_id AS "tenant_id!: uuid::Uuid", org_id AS "org_id!: uuid::Uuid",
                      user_id AS "user_id!: uuid::Uuid", created_at AS "created_at!"
                 FROM org_membership
                WHERE tenant_id = ?1 AND org_id = ?2 AND (?3 IS NULL OR user_id > ?3)
                ORDER BY user_id
                LIMIT ?4"#,
            tenant.0,
            org.0,
            page.after,
            fetch,
        )
        .fetch_all(&self.reader)
        .await
        .map_err(map_err)?;
        let items = rows
            .into_iter()
            .map(OrgMembership::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(into_page(items, limit, |m| m.user_id.0))
    }

    async fn memberships_of_user(
        &self,
        tenant: TenantId,
        user: UserId,
    ) -> Result<Vec<Organization>, StorageError> {
        sqlx::query_as!(
            OrgRow,
            r#"SELECT o.id AS "id!: uuid::Uuid", o.tenant_id AS "tenant_id!: uuid::Uuid",
                      o.slug AS "slug!", o.display_name AS "display_name!",
                      o.mfa_policy AS "mfa_policy?", o.settings AS "settings!",
                      o.metadata AS "metadata!", o.created_at AS "created_at!",
                      o.updated_at AS "updated_at!"
                 FROM org_membership m
                 JOIN organization o ON o.tenant_id = m.tenant_id AND o.id = m.org_id
                WHERE m.tenant_id = ?1 AND m.user_id = ?2
                ORDER BY o.slug"#,
            tenant.0,
            user.0,
        )
        .fetch_all(&self.reader)
        .await
        .map_err(map_err)?
        .into_iter()
        .map(Organization::try_from)
        .collect()
    }

    // ---- invitations ----

    async fn create_invitation(
        &self,
        tenant: TenantId,
        invitation: &NewOrgInvitation,
    ) -> Result<OrgInvitation, StorageError> {
        let roles = to_json(&invitation.role_ids, "org_invitation.roles")?;
        let hash = invitation.token_hash.as_bytes().as_slice();
        let kind = invitation.invited_by.kind.as_str();
        let created_at = odt_to_ms(invitation.created_at);
        let expires_at = odt_to_ms(invitation.expires_at);
        sqlx::query!(
            "INSERT INTO org_invitation
                 (id, tenant_id, org_id, email, roles, token_hash, invited_by_kind,
                  invited_by_id, created_at, expires_at, accepted_at, accepted_user_id,
                  revoked_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, NULL, NULL, NULL)",
            invitation.id.0,
            tenant.0,
            invitation.org_id.0,
            invitation.email,
            roles,
            hash,
            kind,
            invitation.invited_by.id,
            created_at,
            expires_at,
        )
        .execute(&self.writer)
        .await
        .map_err(map_fk_err(
            "invitation references an org outside the tenant",
        ))?;
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
            r#"SELECT id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      org_id AS "org_id!: uuid::Uuid", email AS "email!", roles AS "roles!",
                      token_hash AS "token_hash!", invited_by_kind AS "invited_by_kind!",
                      invited_by_id AS "invited_by_id?", created_at AS "created_at!",
                      expires_at AS "expires_at!", accepted_at AS "accepted_at?",
                      accepted_user_id AS "accepted_user_id?: uuid::Uuid",
                      revoked_at AS "revoked_at?"
                 FROM org_invitation
                WHERE tenant_id = ?1 AND org_id = ?2
                  AND (?3 OR (accepted_at IS NULL AND revoked_at IS NULL))
                ORDER BY created_at DESC, id DESC"#,
            tenant.0,
            org.0,
            include_closed,
        )
        .fetch_all(&self.reader)
        .await
        .map_err(map_err)?
        .into_iter()
        .map(OrgInvitation::try_from)
        .collect()
    }

    async fn revoke_invitation(
        &self,
        tenant: TenantId,
        org: OrgId,
        id: OrgInvitationId,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let now_ms = odt_to_ms(now);
        let done = sqlx::query!(
            "UPDATE org_invitation SET revoked_at = ?4
              WHERE tenant_id = ?1 AND org_id = ?2 AND id = ?3
                AND accepted_at IS NULL AND revoked_at IS NULL",
            tenant.0,
            org.0,
            id.0,
            now_ms,
        )
        .execute(&self.writer)
        .await
        .map_err(map_err)?;
        Ok(done.rows_affected() > 0)
    }

    async fn invitation_by_hash(
        &self,
        tenant: TenantId,
        token_hash: &SecretHash,
    ) -> Result<Option<OrgInvitation>, StorageError> {
        let mut conn = self.reader.acquire().await.map_err(map_err)?;
        invitation_on(&mut conn, tenant, token_hash).await
    }

    async fn accept_invitation(
        &self,
        tenant: TenantId,
        token_hash: &SecretHash,
        user: UserId,
        user_verified_email: &str,
        now: OffsetDateTime,
    ) -> Result<InvitationAccept, StorageError> {
        let mut tx = self.writer.begin().await.map_err(map_err)?;
        // Every read below runs on the single writer inside the transaction, so no other write
        // can interleave between the checks and the consuming UPDATE.
        let invitation = match invitation_on(&mut tx, tenant, token_hash).await? {
            Some(i) if is_open(&i, now) => i,
            _ => {
                tx.rollback().await.map_err(map_err)?;
                return Ok(InvitationAccept::Invalid);
            }
        };
        let user_exists = sqlx::query_scalar!(
            r#"SELECT EXISTS(SELECT 1 FROM user WHERE tenant_id = ?1 AND id = ?2)
                      AS "exists!: bool""#,
            tenant.0,
            user.0,
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(map_err)?;
        let outcome = if !user_exists {
            Some(InvitationAccept::Invalid)
        } else if invitation.email != user_verified_email {
            Some(InvitationAccept::EmailMismatch)
        } else if is_member_on(&mut tx, tenant, invitation.org_id, user).await? {
            Some(InvitationAccept::AlreadyMember)
        } else {
            None
        };
        if let Some(outcome) = outcome {
            tx.rollback().await.map_err(map_err)?;
            return Ok(outcome);
        }
        if !consume_invitation_on(&mut tx, tenant, invitation.id, user, now).await? {
            tx.rollback().await.map_err(map_err)?;
            return Ok(InvitationAccept::Invalid);
        }
        match join_from_invitation_on(&mut tx, &invitation, user, now).await? {
            Some(membership) => {
                tx.commit().await.map_err(map_err)?;
                Ok(InvitationAccept::Accepted(membership))
            }
            None => {
                tx.rollback().await.map_err(map_err)?;
                Ok(InvitationAccept::AlreadyMember)
            }
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
        let mut tx = self.writer.begin().await.map_err(map_err)?;
        let invitation = match invitation_on(&mut tx, tenant, token_hash).await? {
            Some(i) if is_open(&i, now) => i,
            _ => {
                tx.rollback().await.map_err(map_err)?;
                return Ok(InvitationAccept::Invalid);
            }
        };
        if invitation.email != user.email {
            tx.rollback().await.map_err(map_err)?;
            return Ok(InvitationAccept::EmailMismatch);
        }
        // Any error drops `tx` uncommitted: no user, password, membership or consumed token.
        insert_user(&mut tx, tenant, user).await?;
        insert_password(&mut tx, tenant, user.id, password).await?;
        if !consume_invitation_on(&mut tx, tenant, invitation.id, user.id, now).await? {
            tx.rollback().await.map_err(map_err)?;
            return Ok(InvitationAccept::Invalid);
        }
        match join_from_invitation_on(&mut tx, &invitation, user.id, now).await? {
            Some(membership) => {
                tx.commit().await.map_err(map_err)?;
                Ok(InvitationAccept::Accepted(membership))
            }
            None => {
                tx.rollback().await.map_err(map_err)?;
                Err(StorageError::Conflict(
                    "the new user could not join the organization".to_owned(),
                ))
            }
        }
    }

    // ---- domains ----

    async fn create_domain(
        &self,
        tenant: TenantId,
        domain: &NewOrgDomain,
    ) -> Result<OrgDomain, StorageError> {
        let connection = domain.connection_id.map(|c| c.0);
        let created_at = odt_to_ms(domain.created_at);
        let status = OrgDomainStatus::Pending.as_str();
        // The SELECT yields a row only for an org of `tenant` and, when a routing connection is
        // given, only if it is a connection of that same org.
        let done = sqlx::query!(
            "INSERT INTO org_domain
                 (id, tenant_id, org_id, domain, token, status, connection_id, routing,
                  allow_local_password, verified_at, last_checked_at, failing_since, created_at)
             SELECT ?1, o.tenant_id, o.id, ?4, ?5, ?10, ?6, ?7, ?8, NULL, NULL, NULL, ?9
               FROM organization o
              WHERE o.tenant_id = ?2 AND o.id = ?3
                AND (?6 IS NULL OR EXISTS (SELECT 1 FROM connection c
                                            WHERE c.tenant_id = ?2 AND c.id = ?6
                                              AND c.org_id = ?3))",
            domain.id.0,
            tenant.0,
            domain.org_id.0,
            domain.domain,
            domain.token,
            connection,
            domain.routing,
            domain.allow_local_password,
            created_at,
            status,
        )
        .execute(&self.writer)
        .await
        .map_err(map_err)?;
        if done.rows_affected() == 0 {
            return Err(StorageError::Conflict(
                "domain claim references an unknown org or a connection outside the org".to_owned(),
            ));
        }
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
            r#"SELECT id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      org_id AS "org_id!: uuid::Uuid", domain AS "domain!", token AS "token!",
                      status AS "status!", connection_id AS "connection_id?: uuid::Uuid",
                      routing AS "routing!: bool",
                      allow_local_password AS "allow_local_password!: bool",
                      verified_at AS "verified_at?", last_checked_at AS "last_checked_at?",
                      failing_since AS "failing_since?", created_at AS "created_at!"
                 FROM org_domain WHERE tenant_id = ?1 AND org_id = ?2
                ORDER BY domain, id"#,
            tenant.0,
            org.0,
        )
        .fetch_all(&self.reader)
        .await
        .map_err(map_err)?
        .into_iter()
        .map(OrgDomain::try_from)
        .collect()
    }

    async fn get_domain(
        &self,
        tenant: TenantId,
        id: OrgDomainId,
    ) -> Result<Option<OrgDomain>, StorageError> {
        let mut conn = self.reader.acquire().await.map_err(map_err)?;
        domain_on(&mut conn, tenant, id).await
    }

    async fn update_domain(
        &self,
        tenant: TenantId,
        id: OrgDomainId,
        update: &OrgDomainUpdate,
        _now: OffsetDateTime,
    ) -> Result<Option<OrgDomain>, StorageError> {
        let set_connection = update.connection_id.is_some();
        let connection = update.connection_id.flatten().map(|c| c.0);
        // A new routing connection must be a connection of the claim's own org; otherwise the
        // WHERE matches nothing and nothing changes.
        sqlx::query_as!(
            DomainRow,
            r#"UPDATE org_domain
                  SET connection_id = CASE WHEN ?3 THEN ?4 ELSE connection_id END,
                      routing = COALESCE(?5, routing),
                      allow_local_password = COALESCE(?6, allow_local_password)
                WHERE tenant_id = ?1 AND id = ?2
                  AND (NOT ?3 OR ?4 IS NULL
                       OR EXISTS (SELECT 1 FROM connection c
                                   WHERE c.tenant_id = ?1 AND c.id = ?4
                                     AND c.org_id = org_domain.org_id))
            RETURNING id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      org_id AS "org_id!: uuid::Uuid", domain AS "domain!", token AS "token!",
                      status AS "status!", connection_id AS "connection_id?: uuid::Uuid",
                      routing AS "routing!: bool",
                      allow_local_password AS "allow_local_password!: bool",
                      verified_at AS "verified_at?", last_checked_at AS "last_checked_at?",
                      failing_since AS "failing_since?", created_at AS "created_at!""#,
            tenant.0,
            id.0,
            set_connection,
            connection,
            update.routing,
            update.allow_local_password,
        )
        .fetch_optional(&self.writer)
        .await
        .map_err(map_err)?
        .map(OrgDomain::try_from)
        .transpose()
    }

    async fn delete_domain(&self, tenant: TenantId, id: OrgDomainId) -> Result<bool, StorageError> {
        let done = sqlx::query!(
            "DELETE FROM org_domain WHERE tenant_id = ?1 AND id = ?2",
            tenant.0,
            id.0,
        )
        .execute(&self.writer)
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
        let now_ms = odt_to_ms(now);
        let verified = OrgDomainStatus::Verified.as_str();
        let mut tx = self.writer.begin().await.map_err(map_err)?;
        // The partial unique index (tenant_id, domain) WHERE verified_at IS NOT NULL decides
        // between orgs: a second org's UPDATE violates it and maps to Conflict.
        let row = sqlx::query_as!(
            DomainRow,
            r#"UPDATE org_domain
                  SET status = ?4, verified_at = ?3, last_checked_at = ?3, failing_since = NULL
                WHERE tenant_id = ?1 AND id = ?2 AND verified_at IS NULL
            RETURNING id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      org_id AS "org_id!: uuid::Uuid", domain AS "domain!", token AS "token!",
                      status AS "status!", connection_id AS "connection_id?: uuid::Uuid",
                      routing AS "routing!: bool",
                      allow_local_password AS "allow_local_password!: bool",
                      verified_at AS "verified_at?", last_checked_at AS "last_checked_at?",
                      failing_since AS "failing_since?", created_at AS "created_at!""#,
            tenant.0,
            id.0,
            now_ms,
            verified,
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_err)?;
        let result = match row {
            Some(row) => Some(OrgDomain::try_from(row)?),
            // Unknown, or already verified (returned unchanged).
            None => domain_on(&mut tx, tenant, id).await?,
        };
        tx.commit().await.map_err(map_err)?;
        Ok(result)
    }

    async fn record_check(
        &self,
        tenant: TenantId,
        id: OrgDomainId,
        ok: bool,
        now: OffsetDateTime,
    ) -> Result<Option<OrgDomain>, StorageError> {
        let now_ms = odt_to_ms(now);
        // A failure starts (or keeps) the streak of a verified claim; a pending claim has none.
        sqlx::query_as!(
            DomainRow,
            r#"UPDATE org_domain
                  SET last_checked_at = ?4,
                      failing_since = CASE WHEN ?3 OR verified_at IS NULL THEN NULL
                                           ELSE COALESCE(failing_since, ?4) END
                WHERE tenant_id = ?1 AND id = ?2
            RETURNING id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      org_id AS "org_id!: uuid::Uuid", domain AS "domain!", token AS "token!",
                      status AS "status!", connection_id AS "connection_id?: uuid::Uuid",
                      routing AS "routing!: bool",
                      allow_local_password AS "allow_local_password!: bool",
                      verified_at AS "verified_at?", last_checked_at AS "last_checked_at?",
                      failing_since AS "failing_since?", created_at AS "created_at!""#,
            tenant.0,
            id.0,
            ok,
            now_ms,
        )
        .fetch_optional(&self.writer)
        .await
        .map_err(map_err)?
        .map(OrgDomain::try_from)
        .transpose()
    }

    async fn unverify(
        &self,
        tenant: TenantId,
        id: OrgDomainId,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let now_ms = odt_to_ms(now);
        let pending = OrgDomainStatus::Pending.as_str();
        let done = sqlx::query!(
            "UPDATE org_domain
                SET status = ?4, verified_at = NULL, failing_since = NULL, last_checked_at = ?3
              WHERE tenant_id = ?1 AND id = ?2 AND verified_at IS NOT NULL",
            tenant.0,
            id.0,
            now_ms,
            pending,
        )
        .execute(&self.writer)
        .await
        .map_err(map_err)?;
        Ok(done.rows_affected() > 0)
    }

    async fn routed_domain(
        &self,
        tenant: TenantId,
        domain: &str,
    ) -> Result<Option<(OrgDomain, Connection)>, StorageError> {
        sqlx::query_as!(
            RoutedRow,
            r#"SELECT d.id AS "d_id!: uuid::Uuid", d.tenant_id AS "d_tenant_id!: uuid::Uuid",
                      d.org_id AS "d_org_id!: uuid::Uuid", d.domain AS "d_domain!",
                      d.token AS "d_token!", d.status AS "d_status!",
                      d.connection_id AS "d_connection_id?: uuid::Uuid",
                      d.routing AS "d_routing!: bool",
                      d.allow_local_password AS "d_allow_local_password!: bool",
                      d.verified_at AS "d_verified_at?",
                      d.last_checked_at AS "d_last_checked_at?",
                      d.failing_since AS "d_failing_since?", d.created_at AS "d_created_at!",
                      c.id AS "c_id!: uuid::Uuid", c.tenant_id AS "c_tenant_id!: uuid::Uuid",
                      c.slug AS "c_slug!", c.display_name AS "c_display_name!",
                      c.enabled AS "c_enabled!: bool", c.config AS "c_config!",
                      c.secret_enc AS "c_secret_enc?",
                      c.trust_email_verified AS "c_trust_email_verified!: bool",
                      c.created_at AS "c_created_at!", c.updated_at AS "c_updated_at!",
                      c.org_id AS "c_org_id?: uuid::Uuid"
                 FROM org_domain d
                 JOIN connection c ON c.tenant_id = d.tenant_id AND c.id = d.connection_id
                                  AND c.org_id = d.org_id
                WHERE d.tenant_id = ?1 AND d.domain = ?2 AND d.verified_at IS NOT NULL
                  AND d.routing = 1 AND c.enabled = 1"#,
            tenant.0,
            domain,
        )
        .fetch_optional(&self.reader)
        .await
        .map_err(map_err)?
        .map(<(OrgDomain, Connection)>::try_from)
        .transpose()
    }

    async fn tenant_has_routing(&self, tenant: TenantId) -> Result<bool, StorageError> {
        sqlx::query_scalar!(
            r#"SELECT EXISTS(SELECT 1 FROM org_domain d
                               JOIN connection c ON c.tenant_id = d.tenant_id
                                                AND c.id = d.connection_id
                                                AND c.org_id = d.org_id
                              WHERE d.tenant_id = ?1 AND d.verified_at IS NOT NULL
                                AND d.routing = 1 AND c.enabled = 1)
                      AS "routing!: bool""#,
            tenant.0,
        )
        .fetch_one(&self.reader)
        .await
        .map_err(map_err)
    }

    async fn verified_domains_of_org(
        &self,
        tenant: TenantId,
        org: OrgId,
    ) -> Result<Vec<String>, StorageError> {
        sqlx::query_scalar!(
            r#"SELECT domain AS "domain!" FROM org_domain
                WHERE tenant_id = ?1 AND org_id = ?2 AND verified_at IS NOT NULL
                ORDER BY domain"#,
            tenant.0,
            org.0,
        )
        .fetch_all(&self.reader)
        .await
        .map_err(map_err)
    }

    async fn due_for_recheck(
        &self,
        checked_before: OffsetDateTime,
        limit: u32,
    ) -> Result<Vec<OrgDomain>, StorageError> {
        let before = odt_to_ms(checked_before);
        let limit = i64::from(limit);
        // NULL sorts first in ascending order: never-checked claims come first.
        sqlx::query_as!(
            DomainRow,
            r#"SELECT id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      org_id AS "org_id!: uuid::Uuid", domain AS "domain!", token AS "token!",
                      status AS "status!", connection_id AS "connection_id?: uuid::Uuid",
                      routing AS "routing!: bool",
                      allow_local_password AS "allow_local_password!: bool",
                      verified_at AS "verified_at?", last_checked_at AS "last_checked_at?",
                      failing_since AS "failing_since?", created_at AS "created_at!"
                 FROM org_domain
                WHERE verified_at IS NOT NULL
                  AND (last_checked_at IS NULL OR last_checked_at < ?1)
                ORDER BY last_checked_at, id
                LIMIT ?2"#,
            before,
            limit,
        )
        .fetch_all(&self.reader)
        .await
        .map_err(map_err)?
        .into_iter()
        .map(OrgDomain::try_from)
        .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anvil_core::model::RoleId;

    #[test]
    fn invitation_open_only_before_expiry_and_untouched() {
        let now = OffsetDateTime::UNIX_EPOCH + time::Duration::days(1);
        let open = OrgInvitation {
            id: OrgInvitationId::new_v7(),
            tenant_id: TenantId::new_v7(),
            org_id: OrgId::new_v7(),
            email: "a@example.test".into(),
            role_ids: vec![RoleId::new_v7()],
            token_hash: SecretHash([1; 32]),
            invited_by: AuditActor::system(),
            created_at: now,
            expires_at: now + time::Duration::days(7),
            accepted_at: None,
            accepted_user_id: None,
            revoked_at: None,
        };
        assert!(is_open(&open, now));
        assert!(
            !is_open(&open, open.expires_at),
            "expires_at <= now is closed"
        );
        let revoked = OrgInvitation {
            revoked_at: Some(now),
            ..open.clone()
        };
        assert!(!is_open(&revoked, now));
        let accepted = OrgInvitation {
            accepted_at: Some(now),
            accepted_user_id: Some(UserId::new_v7()),
            ..open
        };
        assert!(!is_open(&accepted, now));
    }
}
