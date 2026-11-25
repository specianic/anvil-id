//! PostgreSQL implementation of the `anvil_core::ports` storage traits (via sqlx).
//!
//! Native column types: `uuid` ids, `bytea` hashes, `timestamptz` timestamps, `jsonb` settings.
//! All repositories share one connection pool.

mod convert;
mod grants;
mod tenants;

use anvil_core::ports::{GrantRepo, Storage, StorageError, TenantRepo};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

use crate::convert::map_err;
use crate::grants::PgGrants;
use crate::tenants::PgTenants;

/// Postgres storage backend.
#[derive(Debug, Clone)]
pub struct PostgresStorage {
    pool: PgPool,
    tenants: PgTenants,
    grants: PgGrants,
}

impl PostgresStorage {
    /// Connects a pool of at most `max_connections` connections to `url`.
    pub async fn connect(url: &str, max_connections: u32) -> Result<Self, StorageError> {
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .connect(url)
            .await
            .map_err(map_err)?;
        Ok(Self {
            tenants: PgTenants { pool: pool.clone() },
            grants: PgGrants { pool: pool.clone() },
            pool,
        })
    }

    /// Runs embedded migrations.
    pub async fn migrate(&self) -> Result<(), StorageError> {
        sqlx::migrate!()
            .run(&self.pool)
            .await
            .map_err(|e| StorageError::Backend(Box::new(e)))
    }
}

impl Storage for PostgresStorage {
    fn tenants(&self) -> &dyn TenantRepo {
        &self.tenants
    }

    fn grants(&self) -> &dyn GrantRepo {
        &self.grants
    }
}
