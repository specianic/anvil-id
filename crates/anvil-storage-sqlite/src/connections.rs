//! `ConnectionRepo` on SQLite: upstream connections and identity links.
//!
//! `config` is the tagged `ConnectionConfig` JSON; the client secret only ever lives KEK-sealed in
//! `secret_enc`. Identity links reference user and connection through composite
//! `(tenant_id, …)` foreign keys, so a link can never cross tenants. An org connection
//! (`org_id` set) references its org through the composite `(tenant_id, org_id)` foreign key and
//! goes with it.

use anvil_core::model::{
    Connection, ConnectionConfig, ConnectionId, ConnectionUpdate, IdentityLink, IdentityLinkId,
    NewConnection, NewEmail, NewIdentityLink, NewMembership, NewSelfServiceToken, NewUser, OrgId,
    TenantId, User, UserId,
};
use anvil_core::ports::{AddMemberOutcome, ConnectionRepo, DeleteLinkOutcome, StorageError};

use sqlx::{SqliteConnection, SqlitePool};
use time::OffsetDateTime;

use crate::convert::{from_json, map_err, ms_to_odt, odt_to_ms, opt_ms_to_odt, to_json};
use crate::organizations::{insert_membership_on, map_fk_err};
use crate::outbox::insert_email;
use crate::users::{insert_self_service_token, insert_user};

#[derive(Debug, Clone)]
pub(crate) struct SqliteConnections {
    pub(crate) writer: SqlitePool,
    pub(crate) reader: SqlitePool,
}

pub(crate) struct ConnectionRow {
    pub(crate) id: uuid::Uuid,
    pub(crate) tenant_id: uuid::Uuid,
    pub(crate) slug: String,
    pub(crate) display_name: String,
    pub(crate) enabled: bool,
    pub(crate) config: String,
    pub(crate) secret_enc: Option<Vec<u8>>,
    pub(crate) trust_email_verified: bool,
    pub(crate) created_at: i64,
    pub(crate) updated_at: i64,
    pub(crate) org_id: Option<uuid::Uuid>,
}

impl TryFrom<ConnectionRow> for Connection {
    type Error = StorageError;

    fn try_from(r: ConnectionRow) -> Result<Self, StorageError> {
        Ok(Connection {
            id: ConnectionId(r.id),
            tenant_id: TenantId(r.tenant_id),
            slug: r.slug,
            display_name: r.display_name,
            enabled: r.enabled,
            config: from_json::<ConnectionConfig>(&r.config, "connection.config")?,
            secret_enc: r.secret_enc,
            trust_email_verified: r.trust_email_verified,
            created_at: ms_to_odt(r.created_at)?,
            updated_at: ms_to_odt(r.updated_at)?,
            org_id: r.org_id.map(OrgId),
        })
    }
}

struct LinkRow {
    id: uuid::Uuid,
    tenant_id: uuid::Uuid,
    user_id: uuid::Uuid,
    connection_id: uuid::Uuid,
    subject: String,
    email_at_link: Option<String>,
    metadata: String,
    created_at: i64,
    last_used_at: Option<i64>,
}

impl TryFrom<LinkRow> for IdentityLink {
    type Error = StorageError;

    fn try_from(r: LinkRow) -> Result<Self, StorageError> {
        Ok(IdentityLink {
            id: IdentityLinkId(r.id),
            tenant_id: TenantId(r.tenant_id),
            user_id: UserId(r.user_id),
            connection_id: ConnectionId(r.connection_id),
            subject: r.subject,
            email_at_link: r.email_at_link,
            metadata: from_json(&r.metadata, "identity_link.metadata")?,
            created_at: ms_to_odt(r.created_at)?,
            last_used_at: opt_ms_to_odt(r.last_used_at)?,
        })
    }
}

/// Inserts an identity link on `conn`. A missing user or connection (or one of another tenant)
/// violates the composite foreign keys and is reported as `Conflict`, like a duplicate.
async fn insert_link(
    conn: &mut SqliteConnection,
    tenant: TenantId,
    link: &NewIdentityLink,
) -> Result<IdentityLink, StorageError> {
    let metadata = to_json(&link.metadata, "identity_link.metadata")?;
    let created_at = odt_to_ms(link.created_at);
    sqlx::query!(
        "INSERT INTO identity_link
             (id, tenant_id, user_id, connection_id, subject, email_at_link, metadata,
              created_at, last_used_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL)",
        link.id.0,
        tenant.0,
        link.user_id.0,
        link.connection_id.0,
        link.subject,
        link.email_at_link,
        metadata,
        created_at,
    )
    .execute(conn)
    .await
    .map_err(|e| match &e {
        sqlx::Error::Database(db) if db.is_foreign_key_violation() => StorageError::Conflict(
            "identity link references a user or connection outside the tenant".to_owned(),
        ),
        _ => map_err(e),
    })?;
    Ok(IdentityLink {
        id: link.id,
        tenant_id: tenant,
        user_id: link.user_id,
        connection_id: link.connection_id,
        subject: link.subject.clone(),
        email_at_link: link.email_at_link.clone(),
        metadata: link.metadata.clone(),
        created_at: link.created_at,
        last_used_at: None,
    })
}

#[async_trait::async_trait]
impl ConnectionRepo for SqliteConnections {
    async fn create(
        &self,
        tenant: TenantId,
        connection: &NewConnection,
    ) -> Result<Connection, StorageError> {
        let kind = connection.config.kind().as_str();
        let org_id = connection.org_id.map(|o| o.0);
        let config = to_json(&connection.config, "connection.config")?;
        let created_at = odt_to_ms(connection.created_at);
        sqlx::query!(
            "INSERT INTO connection
                 (id, tenant_id, slug, display_name, kind, enabled, config, secret_enc,
                  trust_email_verified, created_at, updated_at, org_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10, ?11)",
            connection.id.0,
            tenant.0,
            connection.slug,
            connection.display_name,
            kind,
            connection.enabled,
            config,
            connection.secret_enc,
            connection.trust_email_verified,
            created_at,
            org_id,
        )
        .execute(&self.writer)
        .await
        .map_err(map_fk_err(
            "connection references an org outside the tenant",
        ))?;
        Ok(Connection {
            id: connection.id,
            tenant_id: tenant,
            slug: connection.slug.clone(),
            display_name: connection.display_name.clone(),
            enabled: connection.enabled,
            config: connection.config.clone(),
            secret_enc: connection.secret_enc.clone(),
            trust_email_verified: connection.trust_email_verified,
            created_at: connection.created_at,
            updated_at: connection.created_at,
            org_id: connection.org_id,
        })
    }

    async fn get(
        &self,
        tenant: TenantId,
        id: ConnectionId,
    ) -> Result<Option<Connection>, StorageError> {
        sqlx::query_as!(
            ConnectionRow,
            r#"SELECT id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      slug AS "slug!", display_name AS "display_name!",
                      enabled AS "enabled!: bool", config AS "config!",
                      secret_enc AS "secret_enc?",
                      trust_email_verified AS "trust_email_verified!: bool",
                      created_at AS "created_at!", updated_at AS "updated_at!",
                      org_id AS "org_id?: uuid::Uuid"
                 FROM connection WHERE tenant_id = ?1 AND id = ?2"#,
            tenant.0,
            id.0,
        )
        .fetch_optional(&self.reader)
        .await
        .map_err(map_err)?
        .map(Connection::try_from)
        .transpose()
    }

    async fn get_by_slug(
        &self,
        tenant: TenantId,
        slug: &str,
    ) -> Result<Option<Connection>, StorageError> {
        sqlx::query_as!(
            ConnectionRow,
            r#"SELECT id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      slug AS "slug!", display_name AS "display_name!",
                      enabled AS "enabled!: bool", config AS "config!",
                      secret_enc AS "secret_enc?",
                      trust_email_verified AS "trust_email_verified!: bool",
                      created_at AS "created_at!", updated_at AS "updated_at!",
                      org_id AS "org_id?: uuid::Uuid"
                 FROM connection WHERE tenant_id = ?1 AND slug = ?2"#,
            tenant.0,
            slug,
        )
        .fetch_optional(&self.reader)
        .await
        .map_err(map_err)?
        .map(Connection::try_from)
        .transpose()
    }

    async fn list(&self, tenant: TenantId) -> Result<Vec<Connection>, StorageError> {
        sqlx::query_as!(
            ConnectionRow,
            r#"SELECT id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      slug AS "slug!", display_name AS "display_name!",
                      enabled AS "enabled!: bool", config AS "config!",
                      secret_enc AS "secret_enc?",
                      trust_email_verified AS "trust_email_verified!: bool",
                      created_at AS "created_at!", updated_at AS "updated_at!",
                      org_id AS "org_id?: uuid::Uuid"
                 FROM connection WHERE tenant_id = ?1 ORDER BY slug"#,
            tenant.0,
        )
        .fetch_all(&self.reader)
        .await
        .map_err(map_err)?
        .into_iter()
        .map(Connection::try_from)
        .collect()
    }

    async fn update(
        &self,
        tenant: TenantId,
        id: ConnectionId,
        update: &ConnectionUpdate,
        now: OffsetDateTime,
    ) -> Result<Option<Connection>, StorageError> {
        let kind = update.config.as_ref().map(|c| c.kind().as_str());
        let config = update
            .config
            .as_ref()
            .map(|c| to_json(c, "connection.config"))
            .transpose()?;
        let now_ms = odt_to_ms(now);
        sqlx::query_as!(
            ConnectionRow,
            r#"UPDATE connection
                  SET display_name = COALESCE(?3, display_name),
                      enabled = COALESCE(?4, enabled),
                      kind = COALESCE(?5, kind),
                      config = COALESCE(?6, config),
                      trust_email_verified = COALESCE(?7, trust_email_verified),
                      updated_at = ?8
                WHERE tenant_id = ?1 AND id = ?2
            RETURNING id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      slug AS "slug!", display_name AS "display_name!",
                      enabled AS "enabled!: bool", config AS "config!",
                      secret_enc AS "secret_enc?",
                      trust_email_verified AS "trust_email_verified!: bool",
                      created_at AS "created_at!", updated_at AS "updated_at!",
                      org_id AS "org_id?: uuid::Uuid""#,
            tenant.0,
            id.0,
            update.display_name,
            update.enabled,
            kind,
            config,
            update.trust_email_verified,
            now_ms,
        )
        .fetch_optional(&self.writer)
        .await
        .map_err(map_err)?
        .map(Connection::try_from)
        .transpose()
    }

    async fn set_secret(
        &self,
        tenant: TenantId,
        id: ConnectionId,
        secret_enc: Option<&[u8]>,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let now_ms = odt_to_ms(now);
        let done = sqlx::query!(
            "UPDATE connection SET secret_enc = ?3, updated_at = ?4
              WHERE tenant_id = ?1 AND id = ?2",
            tenant.0,
            id.0,
            secret_enc,
            now_ms,
        )
        .execute(&self.writer)
        .await
        .map_err(map_err)?;
        Ok(done.rows_affected() > 0)
    }

    async fn delete(&self, tenant: TenantId, id: ConnectionId) -> Result<bool, StorageError> {
        // Identity links go by ON DELETE CASCADE in the same statement.
        let done = sqlx::query!(
            "DELETE FROM connection WHERE tenant_id = ?1 AND id = ?2",
            tenant.0,
            id.0,
        )
        .execute(&self.writer)
        .await
        .map_err(map_err)?;
        Ok(done.rows_affected() > 0)
    }

    async fn list_for_org(
        &self,
        tenant: TenantId,
        org: OrgId,
    ) -> Result<Vec<Connection>, StorageError> {
        sqlx::query_as!(
            ConnectionRow,
            r#"SELECT id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      slug AS "slug!", display_name AS "display_name!",
                      enabled AS "enabled!: bool", config AS "config!",
                      secret_enc AS "secret_enc?",
                      trust_email_verified AS "trust_email_verified!: bool",
                      created_at AS "created_at!", updated_at AS "updated_at!",
                      org_id AS "org_id?: uuid::Uuid"
                 FROM connection WHERE tenant_id = ?1 AND org_id = ?2 ORDER BY slug"#,
            tenant.0,
            org.0,
        )
        .fetch_all(&self.reader)
        .await
        .map_err(map_err)?
        .into_iter()
        .map(Connection::try_from)
        .collect()
    }

    async fn has_links(
        &self,
        tenant: TenantId,
        connection: ConnectionId,
    ) -> Result<bool, StorageError> {
        sqlx::query_scalar!(
            r#"SELECT EXISTS(SELECT 1 FROM identity_link
                              WHERE tenant_id = ?1 AND connection_id = ?2)
                      AS "linked!: bool""#,
            tenant.0,
            connection.0,
        )
        .fetch_one(&self.reader)
        .await
        .map_err(map_err)
    }

    async fn find_link(
        &self,
        tenant: TenantId,
        connection_id: ConnectionId,
        subject: &str,
    ) -> Result<Option<IdentityLink>, StorageError> {
        sqlx::query_as!(
            LinkRow,
            r#"SELECT id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      user_id AS "user_id!: uuid::Uuid",
                      connection_id AS "connection_id!: uuid::Uuid", subject AS "subject!",
                      email_at_link AS "email_at_link?", metadata AS "metadata!",
                      created_at AS "created_at!", last_used_at AS "last_used_at?"
                 FROM identity_link
                WHERE tenant_id = ?1 AND connection_id = ?2 AND subject = ?3"#,
            tenant.0,
            connection_id.0,
            subject,
        )
        .fetch_optional(&self.reader)
        .await
        .map_err(map_err)?
        .map(IdentityLink::try_from)
        .transpose()
    }

    async fn create_link(
        &self,
        tenant: TenantId,
        link: &NewIdentityLink,
    ) -> Result<IdentityLink, StorageError> {
        let mut conn = self.writer.acquire().await.map_err(map_err)?;
        insert_link(&mut conn, tenant, link).await
    }

    async fn links_for_user(
        &self,
        tenant: TenantId,
        user: UserId,
    ) -> Result<Vec<IdentityLink>, StorageError> {
        sqlx::query_as!(
            LinkRow,
            r#"SELECT id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      user_id AS "user_id!: uuid::Uuid",
                      connection_id AS "connection_id!: uuid::Uuid", subject AS "subject!",
                      email_at_link AS "email_at_link?", metadata AS "metadata!",
                      created_at AS "created_at!", last_used_at AS "last_used_at?"
                 FROM identity_link
                WHERE tenant_id = ?1 AND user_id = ?2
                ORDER BY created_at, id"#,
            tenant.0,
            user.0,
        )
        .fetch_all(&self.reader)
        .await
        .map_err(map_err)?
        .into_iter()
        .map(IdentityLink::try_from)
        .collect()
    }

    async fn touch_link(
        &self,
        tenant: TenantId,
        id: IdentityLinkId,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let now_ms = odt_to_ms(now);
        let done = sqlx::query!(
            "UPDATE identity_link SET last_used_at = ?3 WHERE tenant_id = ?1 AND id = ?2",
            tenant.0,
            id.0,
            now_ms,
        )
        .execute(&self.writer)
        .await
        .map_err(map_err)?;
        Ok(done.rows_affected() > 0)
    }

    async fn delete_link(
        &self,
        tenant: TenantId,
        user: UserId,
        id: IdentityLinkId,
        email_sign_in: bool,
    ) -> Result<DeleteLinkOutcome, StorageError> {
        // One writer transaction: SQLite writes are serialised through the single writer, so a
        // concurrent unlink of the user's other link runs entirely before or after this one and
        // the guard below sees its result.
        let mut tx = self.writer.begin().await.map_err(map_err)?;
        // The guard: the user keeps a password, a passkey, another link, or a verified email the
        // tenant lets them sign in with. TOTP is a second factor, never a sign-in method.
        let done = sqlx::query!(
            "DELETE FROM identity_link
              WHERE tenant_id = ?1 AND user_id = ?2 AND id = ?3
                AND (EXISTS (SELECT 1 FROM credential c
                              WHERE c.tenant_id = ?1 AND c.user_id = ?2
                                AND c.kind IN ('password', 'webauthn'))
                     OR EXISTS (SELECT 1 FROM identity_link o
                                 WHERE o.tenant_id = ?1 AND o.user_id = ?2 AND o.id <> ?3)
                     OR (?4 AND EXISTS (SELECT 1 FROM user u
                                         WHERE u.tenant_id = ?1 AND u.id = ?2
                                           AND u.email_verified = 1)))",
            tenant.0,
            user.0,
            id.0,
            email_sign_in,
        )
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;
        if done.rows_affected() > 0 {
            tx.commit().await.map_err(map_err)?;
            return Ok(DeleteLinkOutcome::Deleted);
        }
        let exists = sqlx::query_scalar!(
            r#"SELECT 1 AS "one!: i64" FROM identity_link
                WHERE tenant_id = ?1 AND user_id = ?2 AND id = ?3"#,
            tenant.0,
            user.0,
            id.0,
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_err)?
        .is_some();
        tx.commit().await.map_err(map_err)?;
        Ok(if exists {
            DeleteLinkOutcome::LastSignInMethod
        } else {
            DeleteLinkOutcome::NotFound
        })
    }

    async fn create_user_with_link(
        &self,
        tenant: TenantId,
        user: &NewUser,
        link: &NewIdentityLink,
        token: Option<&NewSelfServiceToken>,
        email: Option<&NewEmail>,
        membership: Option<&NewMembership>,
    ) -> Result<User, StorageError> {
        let mut tx = self.writer.begin().await.map_err(map_err)?;
        // Any error drops `tx` uncommitted: none of the user, link, token, email or membership
        // is stored.
        let created = insert_user(&mut tx, tenant, user).await?;
        insert_link(&mut tx, tenant, link).await?;
        if let Some(membership) = membership {
            if membership.user_id != user.id {
                return Err(StorageError::Conflict(
                    "membership is not for the user being created".to_owned(),
                ));
            }
            if insert_membership_on(&mut tx, tenant, membership).await? != AddMemberOutcome::Added {
                return Err(StorageError::Conflict(
                    "membership references an unknown org or a role that cannot be assigned in it"
                        .to_owned(),
                ));
            }
        }
        if let Some(token) = token {
            insert_self_service_token(&mut tx, tenant, token).await?;
        }
        if let Some(email) = email {
            insert_email(&mut tx, tenant, email).await?;
        }
        tx.commit().await.map_err(map_err)?;
        Ok(created)
    }
}
