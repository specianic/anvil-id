//! `SetupRepo` on Postgres (installation-wide).

use anvil_core::model::{
    InstallPlan, NewClient, NewPasswordCredential, NewSetupToken, NewUser, SYSTEM_TENANT_SLUG,
    SecretHash, TenantId,
};
use anvil_core::ports::{InstallOutcome, SetupOutcome, SetupRepo, StorageError};
use sqlx::PgPool;
use time::OffsetDateTime;

use crate::clients::{client_from_new, insert_client};
use crate::convert::map_err;
use crate::keys::insert_key;
use crate::roles::{assign_admin_role, insert_admin_role};
use crate::tenants::insert_tenant;
use crate::users::{insert_password, insert_user, user_from_new};

#[derive(Debug, Clone)]
pub(crate) struct PgSetup {
    pub(crate) pool: PgPool,
}

async fn insert_setup_token<'e, E>(exec: E, token: &NewSetupToken) -> Result<(), StorageError>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query!(
        "INSERT INTO admin_setup_token (token_hash, created_at, expires_at) VALUES ($1, $2, $3)",
        token.token_hash.as_bytes().as_slice(),
        token.created_at,
        token.expires_at,
    )
    .execute(exec)
    .await
    .map_err(map_err)?;
    Ok(())
}

impl PgSetup {
    async fn write_plan(&self, plan: &InstallPlan) -> Result<(), StorageError> {
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        for tenant in &plan.tenants {
            insert_tenant(&mut *tx, tenant).await?;
            if tenant.slug == SYSTEM_TENANT_SLUG {
                insert_admin_role(&mut tx, tenant.id, tenant.created_at).await?;
            }
        }
        for (tenant, key) in &plan.keys {
            insert_key(&mut *tx, *tenant, key).await?;
        }
        insert_setup_token(&mut *tx, &plan.setup_token).await?;
        tx.commit().await.map_err(map_err)
    }
}

#[async_trait::async_trait]
impl SetupRepo for PgSetup {
    async fn is_installed(&self) -> Result<bool, StorageError> {
        let row = sqlx::query!(
            "SELECT EXISTS (SELECT 1 FROM tenant WHERE slug = $1) AS \"installed!\"",
            SYSTEM_TENANT_SLUG,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(row.installed)
    }

    async fn install(&self, plan: &InstallPlan) -> Result<InstallOutcome, StorageError> {
        // No check-then-insert: the unique slug index decides. A concurrent installer's insert of
        // the system tenant blocks on ours and fails with a unique violation once we commit; the
        // dropped transaction rolls back everything it wrote.
        match self.write_plan(plan).await {
            Ok(()) => Ok(InstallOutcome::Installed),
            Err(StorageError::Conflict(msg)) => {
                if self.is_installed().await? {
                    Ok(InstallOutcome::AlreadyInstalled)
                } else {
                    Err(StorageError::Conflict(msg))
                }
            }
            Err(e) => Err(e),
        }
    }

    async fn create_setup_token(&self, token: &NewSetupToken) -> Result<(), StorageError> {
        insert_setup_token(&self.pool, token).await
    }

    async fn peek_setup_token(
        &self,
        hash: &SecretHash,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let row = sqlx::query!(
            "SELECT EXISTS (SELECT 1 FROM admin_setup_token
                             WHERE token_hash = $1 AND used_at IS NULL AND expires_at > $2)
                    AS \"valid!\"",
            hash.as_bytes().as_slice(),
            now,
        )
        .fetch_one(&self.pool)
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
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        // Concurrent completions serialise on the token row lock; under READ COMMITTED the losers
        // re-check `used_at IS NULL` against the committed row and update nothing.
        let consumed = sqlx::query!(
            "UPDATE admin_setup_token SET used_at = $1
              WHERE token_hash = $2 AND used_at IS NULL AND expires_at > $1
          RETURNING token_hash",
            now,
            hash.as_bytes().as_slice(),
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_err)?;
        if consumed.is_none() {
            // Dropping the transaction rolls it back; nothing was written.
            return Ok(SetupOutcome::InvalidToken);
        }
        // Any error below drops `tx`, rolling back the token consumption too.
        insert_user(&mut *tx, admin_tenant, admin).await?;
        insert_password(&mut *tx, admin_tenant, admin.id, password).await?;
        assign_admin_role(&mut tx, admin_tenant, admin.id, now).await?;
        insert_client(&mut *tx, client_tenant, client).await?;
        tx.commit().await.map_err(map_err)?;
        Ok(SetupOutcome::Completed {
            user: user_from_new(admin_tenant, admin),
            client: client_from_new(client_tenant, client),
        })
    }
}
