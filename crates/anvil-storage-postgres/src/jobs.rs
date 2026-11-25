//! `JobRepo` on Postgres: installation-wide background job leases.

use anvil_core::ports::{JobRepo, StorageError};
use sqlx::PgPool;
use time::OffsetDateTime;

use crate::convert::map_err;

#[derive(Debug, Clone)]
pub(crate) struct PgJobs {
    pub(crate) pool: PgPool,
}

#[async_trait::async_trait]
impl JobRepo for PgJobs {
    async fn try_lease(
        &self,
        name: &str,
        owner: &str,
        until: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        // One statement: concurrent first takers serialise on the primary key (the losers see the
        // winner's committed row in ON CONFLICT and its unexpired lease fails the WHERE).
        let row = sqlx::query_scalar!(
            "INSERT INTO job_lease (name, owner, leased_until)
             VALUES ($1, $2, $3)
             ON CONFLICT (name) DO UPDATE
                SET owner = EXCLUDED.owner, leased_until = EXCLUDED.leased_until
              WHERE job_lease.leased_until <= $4 OR job_lease.owner = EXCLUDED.owner
          RETURNING owner",
            name,
            owner,
            until,
            now,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(row.is_some())
    }

    async fn release(&self, name: &str, owner: &str) -> Result<bool, StorageError> {
        let done = sqlx::query!(
            "DELETE FROM job_lease WHERE name = $1 AND owner = $2",
            name,
            owner,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(done.rows_affected() > 0)
    }
}
