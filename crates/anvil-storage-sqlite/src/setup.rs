//! `SetupRepo` on SQLite (installation-wide).

use anvil_core::model::{
    InstallPlan, NewClient, NewPasswordCredential, NewSetupToken, NewUser, SYSTEM_TENANT_SLUG,
    SecretHash, TenantId,
};
use anvil_core::ports::{InstallOutcome, SetupOutcome, SetupRepo, StorageError};
use sqlx::{SqliteConnection, SqlitePool};
use time::OffsetDateTime;

use crate::clients::insert_client;
use crate::convert::{map_err, odt_to_ms};
use crate::keys::insert_key;
use crate::roles::{assign_admin_role, insert_admin_role};
use crate::tenants::insert_tenant;
use crate::users::{insert_password, insert_user};

#[derive(Debug, Clone)]
pub(crate) struct SqliteSetup {
    pub(crate) writer: SqlitePool,
    pub(crate) reader: SqlitePool,
}

async fn insert_setup_token(
    conn: &mut SqliteConnection,
    token: &NewSetupToken,
) -> Result<(), StorageError> {
    let hash = token.token_hash.as_bytes().as_slice();
    let created_at = odt_to_ms(token.created_at);
    let expires_at = odt_to_ms(token.expires_at);
    sqlx::query!(
        "INSERT INTO admin_setup_token (token_hash, created_at, expires_at, consumed_at)
         VALUES (?1, ?2, ?3, NULL)",
        hash,
        created_at,
        expires_at,
    )
    .execute(conn)
    .await
    .map_err(map_err)?;
    Ok(())
}

async fn system_tenant_exists(conn: &mut SqliteConnection) -> Result<bool, StorageError> {
    let row = sqlx::query!(
        r#"SELECT EXISTS(SELECT 1 FROM tenant WHERE slug = ?1) AS "exists!: bool""#,
        SYSTEM_TENANT_SLUG,
    )
    .fetch_one(conn)
    .await
    .map_err(map_err)?;
    Ok(row.exists)
}

/// Writes the whole plan on `conn` (inside the caller's transaction), including the system
/// tenant's administrator role.
async fn write_plan(conn: &mut SqliteConnection, plan: &InstallPlan) -> Result<(), StorageError> {
    for tenant in &plan.tenants {
        insert_tenant(conn, tenant).await?;
        if tenant.slug == SYSTEM_TENANT_SLUG {
            insert_admin_role(conn, tenant.id, tenant.created_at).await?;
        }
    }
    for (tenant, key) in &plan.keys {
        insert_key(conn, *tenant, key).await?;
    }
    insert_setup_token(conn, &plan.setup_token).await
}

#[async_trait::async_trait]
impl SetupRepo for SqliteSetup {
    async fn is_installed(&self) -> Result<bool, StorageError> {
        let mut conn = self.reader.acquire().await.map_err(map_err)?;
        system_tenant_exists(&mut conn).await
    }

    async fn install(&self, plan: &InstallPlan) -> Result<InstallOutcome, StorageError> {
        // The transaction holds the single writer connection, so concurrent installers are
        // serialised: the check below and the inserts cannot interleave with another installer.
        let mut tx = self.writer.begin().await.map_err(map_err)?;
        if system_tenant_exists(&mut tx).await? {
            tx.rollback().await.map_err(map_err)?;
            return Ok(InstallOutcome::AlreadyInstalled);
        }
        match write_plan(&mut tx, plan).await {
            Ok(()) => {
                tx.commit().await.map_err(map_err)?;
                Ok(InstallOutcome::Installed)
            }
            Err(StorageError::Conflict(msg)) => {
                tx.rollback().await.map_err(map_err)?;
                // A conflict on the system slug means another installation won; any other
                // conflict is a genuine error of the plan.
                let mut conn = self.writer.acquire().await.map_err(map_err)?;
                if system_tenant_exists(&mut conn).await? {
                    Ok(InstallOutcome::AlreadyInstalled)
                } else {
                    Err(StorageError::Conflict(msg))
                }
            }
            Err(e) => Err(e),
        }
    }

    async fn create_setup_token(&self, token: &NewSetupToken) -> Result<(), StorageError> {
        let mut conn = self.writer.acquire().await.map_err(map_err)?;
        insert_setup_token(&mut conn, token).await
    }

    async fn peek_setup_token(
        &self,
        hash: &SecretHash,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let hash = hash.as_bytes().as_slice();
        let now_ms = odt_to_ms(now);
        let row = sqlx::query!(
            r#"SELECT EXISTS(SELECT 1 FROM admin_setup_token
                              WHERE token_hash = ?1 AND consumed_at IS NULL AND expires_at > ?2)
                      AS "valid!: bool""#,
            hash,
            now_ms,
        )
        .fetch_one(&self.reader)
        .await
        .map_err(map_err)?;
        Ok(row.valid)
    }

    async fn complete_setup(
        &self,
        hash: &SecretHash,
        now: OffsetDateTime,
        admin_tenant: TenantId,
        admin: &NewUser,
        password: &NewPasswordCredential,
        client_tenant: TenantId,
        client: &NewClient,
    ) -> Result<SetupOutcome, StorageError> {
        let hash = hash.as_bytes().as_slice();
        let now_ms = odt_to_ms(now);
        let mut tx = self.writer.begin().await.map_err(map_err)?;
        let consumed = sqlx::query!(
            "UPDATE admin_setup_token SET consumed_at = ?2
              WHERE token_hash = ?1 AND consumed_at IS NULL AND expires_at > ?2",
            hash,
            now_ms,
        )
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;
        if consumed.rows_affected() == 0 {
            tx.rollback().await.map_err(map_err)?;
            return Ok(SetupOutcome::InvalidToken);
        }
        // Any error below drops `tx` uncommitted, which rolls back the token consumption too.
        let user = insert_user(&mut tx, admin_tenant, admin).await?;
        insert_password(&mut tx, admin_tenant, admin.id, password).await?;
        assign_admin_role(&mut tx, admin_tenant, admin.id, now).await?;
        let client = insert_client(&mut tx, client_tenant, client).await?;
        tx.commit().await.map_err(map_err)?;
        Ok(SetupOutcome::Completed { user, client })
    }
}
