//! PostgreSQL implementation of the `anvil_core::ports` storage traits (via sqlx).
//!
//! Native column types: `uuid` ids, `bytea` hashes, `timestamptz` timestamps, `jsonb` settings.
//! All repositories share one connection pool.

mod convert;
// TRANSITIONAL (plan 02-02): tenants.rs and grants.rs stay on disk as reference for plan 02-06
// but are not compiled; every repository is `pending::Pending` until 02-06 lands.
mod pending;

use anvil_core::ports::{
    ClientRepo, FlowRepo, GrantRepo, KeyRepo, OutboxRepo, SessionRepo, SetupRepo, Storage,
    StorageError, TenantRepo, UserRepo,
};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

use crate::convert::map_err;
use crate::pending::Pending;

/// Postgres storage backend.
#[derive(Debug, Clone)]
pub struct PostgresStorage {
    pool: PgPool,
}

impl PostgresStorage {
    /// Connects a pool of at most `max_connections` connections to `url`.
    pub async fn connect(url: &str, max_connections: u32) -> Result<Self, StorageError> {
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .connect(url)
            .await
            .map_err(map_err)?;
        Ok(Self { pool })
    }

    /// Runs embedded migrations.
    pub async fn migrate(&self) -> Result<(), StorageError> {
        sqlx::migrate!()
            .run(&self.pool)
            .await
            .map_err(|e| StorageError::Backend(Box::new(e)))
    }
}

#[async_trait::async_trait]
impl Storage for PostgresStorage {
    fn tenants(&self) -> &dyn TenantRepo {
        &Pending
    }
    fn users(&self) -> &dyn UserRepo {
        &Pending
    }
    fn clients(&self) -> &dyn ClientRepo {
        &Pending
    }
    fn keys(&self) -> &dyn KeyRepo {
        &Pending
    }
    fn sessions(&self) -> &dyn SessionRepo {
        &Pending
    }
    fn flows(&self) -> &dyn FlowRepo {
        &Pending
    }
    fn grants(&self) -> &dyn GrantRepo {
        &Pending
    }
    fn setup(&self) -> &dyn SetupRepo {
        &Pending
    }
    fn outbox(&self) -> &dyn OutboxRepo {
        &Pending
    }

    async fn purge_expired(&self, _now: time::OffsetDateTime) -> Result<u64, StorageError> {
        Err(StorageError::Unsupported(
            "postgres: Storage::purge_expired lands in plan 02-06",
        ))
    }
}
