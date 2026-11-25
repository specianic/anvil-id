//! `ConnectionRepo` on Postgres: upstream connections and identity links.
//!
//! `config` is the tagged `ConnectionConfig` JSON (jsonb); `kind` is derived from it on write
//! and cross-checked on read. The sealed client secret (`secret_enc`) is stored exactly as given;
//! storage never sees the plaintext. Identity links reference their user and connection through
//! composite `(tenant_id, …)` foreign keys, so a link can never cross tenants.

use anvil_core::model::{
    Connection, ConnectionConfig, ConnectionId, ConnectionKind, ConnectionUpdate, IdentityLink,
    IdentityLinkId, NewConnection, NewEmail, NewIdentityLink, NewSelfServiceToken, NewUser,
    TenantId, User, UserId,
};
use anvil_core::ports::{ConnectionRepo, DeleteLinkOutcome, StorageError};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::convert::{enum_from, from_json, map_err, to_json};
use crate::outbox::enqueue_email;
use crate::users::{insert_self_service_token, insert_user, user_from_new};

#[derive(Debug, Clone)]
pub(crate) struct PgConnections {
    pub(crate) pool: PgPool,
}

struct ConnectionRow {
    id: Uuid,
    tenant_id: Uuid,
    slug: String,
    display_name: String,
    kind: String,
    enabled: bool,
    config: serde_json::Value,
    secret_enc: Option<Vec<u8>>,
    trust_email_verified: bool,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

impl ConnectionRow {
    fn into_model(self) -> Result<Connection, StorageError> {
        let kind = enum_from("connection.kind", &self.kind, ConnectionKind::parse)?;
        let config: ConnectionConfig = from_json("connection.config", self.config)?;
        if config.kind() != kind {
            return Err(StorageError::Corrupt(format!(
                "connection.kind: {} does not match config {}",
                kind.as_str(),
                config.kind().as_str()
            )));
        }
        Ok(Connection {
            id: ConnectionId(self.id),
            tenant_id: TenantId(self.tenant_id),
            slug: self.slug,
            display_name: self.display_name,
            enabled: self.enabled,
            config,
            secret_enc: self.secret_enc,
            trust_email_verified: self.trust_email_verified,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

struct LinkRow {
    id: Uuid,
    tenant_id: Uuid,
    user_id: Uuid,
    connection_id: Uuid,
    subject: String,
    email_at_link: Option<String>,
    metadata: serde_json::Value,
    created_at: OffsetDateTime,
    last_used_at: Option<OffsetDateTime>,
}

impl LinkRow {
    fn into_model(self) -> Result<IdentityLink, StorageError> {
        Ok(IdentityLink {
            id: IdentityLinkId(self.id),
            tenant_id: TenantId(self.tenant_id),
            user_id: UserId(self.user_id),
            connection_id: ConnectionId(self.connection_id),
            subject: self.subject,
            email_at_link: self.email_at_link,
            metadata: from_json("identity_link.metadata", self.metadata)?,
            created_at: self.created_at,
            last_used_at: self.last_used_at,
        })
    }
}

fn link_from_new(tenant: TenantId, l: &NewIdentityLink) -> IdentityLink {
    IdentityLink {
        id: l.id,
        tenant_id: tenant,
        user_id: l.user_id,
        connection_id: l.connection_id,
        subject: l.subject.clone(),
        email_at_link: l.email_at_link.clone(),
        metadata: l.metadata.clone(),
        created_at: l.created_at,
        last_used_at: None,
    }
}

/// Inserts a link on any executor. `Conflict` on a duplicate id or (tenant, connection,
/// subject), and when the user or connection does not exist in `tenant` (the composite foreign
/// keys reject it; reported as a conflict per the port contract).
async fn insert_link<'e, E>(
    exec: E,
    tenant: TenantId,
    l: &NewIdentityLink,
) -> Result<(), StorageError>
where
    E: sqlx::PgExecutor<'e>,
{
    let metadata = to_json("identity_link.metadata", &l.metadata)?;
    sqlx::query!(
        "INSERT INTO identity_link
             (id, tenant_id, user_id, connection_id, subject, email_at_link, metadata,
              created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        l.id.0,
        tenant.0,
        l.user_id.0,
        l.connection_id.0,
        l.subject,
        l.email_at_link,
        metadata,
        l.created_at,
    )
    .execute(exec)
    .await
    .map_err(|e| {
        if let sqlx::Error::Database(db) = &e
            && db.is_foreign_key_violation()
        {
            return StorageError::Conflict(
                "the user or connection does not exist in this tenant".to_owned(),
            );
        }
        map_err(e)
    })?;
    Ok(())
}

#[async_trait::async_trait]
impl ConnectionRepo for PgConnections {
    async fn create(
        &self,
        tenant: TenantId,
        c: &NewConnection,
    ) -> Result<Connection, StorageError> {
        let config = to_json("connection.config", &c.config)?;
        sqlx::query!(
            "INSERT INTO connection
                 (id, tenant_id, slug, display_name, kind, enabled, config, secret_enc,
                  trust_email_verified, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10)",
            c.id.0,
            tenant.0,
            c.slug,
            c.display_name,
            c.config.kind().as_str(),
            c.enabled,
            config,
            c.secret_enc.as_deref(),
            c.trust_email_verified,
            c.created_at,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(Connection {
            id: c.id,
            tenant_id: tenant,
            slug: c.slug.clone(),
            display_name: c.display_name.clone(),
            enabled: c.enabled,
            config: c.config.clone(),
            secret_enc: c.secret_enc.clone(),
            trust_email_verified: c.trust_email_verified,
            created_at: c.created_at,
            updated_at: c.created_at,
        })
    }

    async fn get(
        &self,
        tenant: TenantId,
        id: ConnectionId,
    ) -> Result<Option<Connection>, StorageError> {
        sqlx::query_as!(
            ConnectionRow,
            "SELECT id, tenant_id, slug, display_name, kind, enabled, config, secret_enc,
                    trust_email_verified, created_at, updated_at
               FROM connection
              WHERE tenant_id = $1 AND id = $2",
            tenant.0,
            id.0,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?
        .map(ConnectionRow::into_model)
        .transpose()
    }

    async fn get_by_slug(
        &self,
        tenant: TenantId,
        slug: &str,
    ) -> Result<Option<Connection>, StorageError> {
        sqlx::query_as!(
            ConnectionRow,
            "SELECT id, tenant_id, slug, display_name, kind, enabled, config, secret_enc,
                    trust_email_verified, created_at, updated_at
               FROM connection
              WHERE tenant_id = $1 AND slug = $2",
            tenant.0,
            slug,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?
        .map(ConnectionRow::into_model)
        .transpose()
    }

    async fn list(&self, tenant: TenantId) -> Result<Vec<Connection>, StorageError> {
        sqlx::query_as!(
            ConnectionRow,
            "SELECT id, tenant_id, slug, display_name, kind, enabled, config, secret_enc,
                    trust_email_verified, created_at, updated_at
               FROM connection
              WHERE tenant_id = $1
              ORDER BY slug COLLATE \"C\"",
            tenant.0,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?
        .into_iter()
        .map(ConnectionRow::into_model)
        .collect()
    }

    async fn update(
        &self,
        tenant: TenantId,
        id: ConnectionId,
        update: &ConnectionUpdate,
        now: OffsetDateTime,
    ) -> Result<Option<Connection>, StorageError> {
        let config = update
            .config
            .as_ref()
            .map(|c| to_json("connection.config", c))
            .transpose()?;
        let kind = update.config.as_ref().map(|c| c.kind().as_str());
        // One statement: kind and config always change together.
        sqlx::query_as!(
            ConnectionRow,
            "UPDATE connection
                SET display_name = COALESCE($3, display_name),
                    enabled = COALESCE($4, enabled),
                    config = COALESCE($5, config),
                    kind = COALESCE($6, kind),
                    trust_email_verified = COALESCE($7, trust_email_verified),
                    updated_at = $8
              WHERE tenant_id = $1 AND id = $2
          RETURNING id, tenant_id, slug, display_name, kind, enabled, config, secret_enc,
                    trust_email_verified, created_at, updated_at",
            tenant.0,
            id.0,
            update.display_name,
            update.enabled,
            config,
            kind,
            update.trust_email_verified,
            now,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?
        .map(ConnectionRow::into_model)
        .transpose()
    }

    async fn set_secret(
        &self,
        tenant: TenantId,
        id: ConnectionId,
        secret_enc: Option<&[u8]>,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let done = sqlx::query!(
            "UPDATE connection SET secret_enc = $3, updated_at = $4
              WHERE tenant_id = $1 AND id = $2",
            tenant.0,
            id.0,
            secret_enc,
            now,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(done.rows_affected() > 0)
    }

    async fn delete(&self, tenant: TenantId, id: ConnectionId) -> Result<bool, StorageError> {
        // Identity links go by ON DELETE CASCADE in the same statement.
        let done = sqlx::query!(
            "DELETE FROM connection WHERE tenant_id = $1 AND id = $2",
            tenant.0,
            id.0,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(done.rows_affected() > 0)
    }

    async fn find_link(
        &self,
        tenant: TenantId,
        connection_id: ConnectionId,
        subject: &str,
    ) -> Result<Option<IdentityLink>, StorageError> {
        sqlx::query_as!(
            LinkRow,
            "SELECT id, tenant_id, user_id, connection_id, subject, email_at_link, metadata,
                    created_at, last_used_at
               FROM identity_link
              WHERE tenant_id = $1 AND connection_id = $2 AND subject = $3",
            tenant.0,
            connection_id.0,
            subject,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?
        .map(LinkRow::into_model)
        .transpose()
    }

    async fn create_link(
        &self,
        tenant: TenantId,
        link: &NewIdentityLink,
    ) -> Result<IdentityLink, StorageError> {
        insert_link(&self.pool, tenant, link).await?;
        Ok(link_from_new(tenant, link))
    }

    async fn links_for_user(
        &self,
        tenant: TenantId,
        user: UserId,
    ) -> Result<Vec<IdentityLink>, StorageError> {
        sqlx::query_as!(
            LinkRow,
            "SELECT id, tenant_id, user_id, connection_id, subject, email_at_link, metadata,
                    created_at, last_used_at
               FROM identity_link
              WHERE tenant_id = $1 AND user_id = $2
              ORDER BY created_at, id",
            tenant.0,
            user.0,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?
        .into_iter()
        .map(LinkRow::into_model)
        .collect()
    }

    async fn touch_link(
        &self,
        tenant: TenantId,
        id: IdentityLinkId,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let done = sqlx::query!(
            "UPDATE identity_link SET last_used_at = $3 WHERE tenant_id = $1 AND id = $2",
            tenant.0,
            id.0,
            now,
        )
        .execute(&self.pool)
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
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        // Serialise unlinks of the same user: a second call waits on this row lock until the
        // first commits. READ COMMITTED takes a fresh snapshot per statement, so its guarded
        // DELETE below then sees the first call's delete.
        let locked = sqlx::query_scalar!(
            r#"SELECT 1 AS "one!" FROM "user" WHERE tenant_id = $1 AND id = $2 FOR UPDATE"#,
            tenant.0,
            user.0,
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_err)?;
        if locked.is_none() {
            return Ok(DeleteLinkOutcome::NotFound);
        }
        // The guard: the user keeps a password, a passkey, another link, or a verified email the
        // tenant lets them sign in with. TOTP is a second factor, never a sign-in method.
        let done = sqlx::query!(
            r#"DELETE FROM identity_link
                WHERE tenant_id = $1 AND user_id = $2 AND id = $3
                  AND (EXISTS (SELECT 1 FROM credential c
                                WHERE c.tenant_id = $1 AND c.user_id = $2
                                  AND c.kind IN ('password', 'webauthn'))
                       OR EXISTS (SELECT 1 FROM identity_link o
                                   WHERE o.tenant_id = $1 AND o.user_id = $2 AND o.id <> $3)
                       OR ($4 AND EXISTS (SELECT 1 FROM "user" u
                                           WHERE u.tenant_id = $1 AND u.id = $2
                                             AND u.email_verified)))"#,
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
            r#"SELECT 1 AS "one!" FROM identity_link
                WHERE tenant_id = $1 AND user_id = $2 AND id = $3"#,
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
    ) -> Result<User, StorageError> {
        if link.user_id != user.id {
            return Err(StorageError::Conflict(
                "identity link user_id does not match the new user".to_owned(),
            ));
        }
        // One transaction; any error drops `tx` and rolls every insert back.
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        insert_user(&mut *tx, tenant, user).await?;
        insert_link(&mut *tx, tenant, link).await?;
        if let Some(t) = token {
            insert_self_service_token(&mut *tx, tenant, t).await?;
        }
        if let Some(e) = email {
            enqueue_email(&mut *tx, tenant, e).await?;
        }
        tx.commit().await.map_err(map_err)?;
        Ok(user_from_new(tenant, user))
    }
}
