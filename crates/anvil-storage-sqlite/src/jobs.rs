//! `JobRepo` on SQLite: installation-wide background job leases.

use anvil_core::ports::{JobRepo, StorageError};
use sqlx::SqlitePool;
use time::OffsetDateTime;

use crate::convert::{map_err, odt_to_ms};

#[derive(Debug, Clone)]
pub(crate) struct SqliteJobs {
    pub(crate) writer: SqlitePool,
}

#[async_trait::async_trait]
impl JobRepo for SqliteJobs {
    async fn try_lease(
        &self,
        name: &str,
        owner: &str,
        until: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let until = odt_to_ms(until);
        let now = odt_to_ms(now);
        // One statement: insert a free lease, or take over an expired one / renew our own. While
        // another owner holds an unexpired lease the DO UPDATE's WHERE fails and no row changes.
        let done = sqlx::query!(
            "INSERT INTO job_lease (name, owner, leased_until) VALUES (?1, ?2, ?3)
             ON CONFLICT (name)
             DO UPDATE SET owner = excluded.owner, leased_until = excluded.leased_until
                     WHERE job_lease.leased_until <= ?4 OR job_lease.owner = excluded.owner",
            name,
            owner,
            until,
            now,
        )
        .execute(&self.writer)
        .await
        .map_err(map_err)?;
        Ok(done.rows_affected() == 1)
    }

    async fn release(&self, name: &str, owner: &str) -> Result<bool, StorageError> {
        let done = sqlx::query!(
            "DELETE FROM job_lease WHERE name = ?1 AND owner = ?2",
            name,
            owner,
        )
        .execute(&self.writer)
        .await
        .map_err(map_err)?;
        Ok(done.rows_affected() > 0)
    }
}
