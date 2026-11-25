//! PostgreSQL implementation of the `anvil_core::ports` storage traits (via sqlx).
//!
//! Native column types: `uuid` ids, `bytea` hashes, `timestamptz` timestamps, `jsonb` documents,
//! `text[]` lists. All repositories share one connection pool. Multi-row intent methods run in
//! one transaction (READ COMMITTED); races are decided by row-level conditional
//! `UPDATE … RETURNING` / `INSERT … ON CONFLICT`, never by check-then-act.

mod clients;
mod convert;
mod keys;
mod outbox;
// TRANSITIONAL (plan 02-06 task 1): users, sessions, flows and grants are still `Pending`.
mod pending;
mod setup;
mod tenants;
mod users;

use anvil_core::ports::{
    ClientRepo, FlowRepo, GrantRepo, KeyRepo, OutboxRepo, SessionRepo, SetupRepo, Storage,
    StorageError, TenantRepo, UserRepo,
};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

use crate::clients::PgClients;
use crate::convert::map_err;
use crate::keys::PgKeys;
use crate::outbox::PgOutbox;
use crate::pending::Pending;
use crate::setup::PgSetup;
use crate::tenants::PgTenants;

/// Postgres storage backend.
#[derive(Debug, Clone)]
pub struct PostgresStorage {
    pool: PgPool,
    tenants: PgTenants,
    clients: PgClients,
    keys: PgKeys,
    setup: PgSetup,
    outbox: PgOutbox,
}

impl PostgresStorage {
    /// Connects a pool of at most `max_connections` connections to `url`.
    pub async fn connect(url: &str, max_connections: u32) -> Result<Self, StorageError> {
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .connect(url)
            .await
            .map_err(map_err)?;
        Ok(Self::from_pool(pool))
    }

    fn from_pool(pool: PgPool) -> Self {
        Self {
            tenants: PgTenants { pool: pool.clone() },
            clients: PgClients { pool: pool.clone() },
            keys: PgKeys { pool: pool.clone() },
            setup: PgSetup { pool: pool.clone() },
            outbox: PgOutbox { pool: pool.clone() },
            pool,
        }
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
        &self.tenants
    }
    fn users(&self) -> &dyn UserRepo {
        &Pending
    }
    fn clients(&self) -> &dyn ClientRepo {
        &self.clients
    }
    fn keys(&self) -> &dyn KeyRepo {
        &self.keys
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
        &self.setup
    }
    fn outbox(&self) -> &dyn OutboxRepo {
        &self.outbox
    }

    async fn purge_expired(&self, _now: time::OffsetDateTime) -> Result<u64, StorageError> {
        Err(StorageError::Unsupported(
            "postgres: Storage::purge_expired lands in plan 02-06 task 2",
        ))
    }
}
