//! PostgreSQL implementation of the `anvil_core::ports` storage traits (via sqlx).
//!
//! Native column types: `uuid` ids, `bytea` hashes, `timestamptz` timestamps, `jsonb` documents,
//! `text[]` lists. All repositories share one connection pool. Multi-row intent methods run in
//! one transaction (READ COMMITTED); races are decided by row-level conditional
//! `UPDATE … RETURNING` / `INSERT … ON CONFLICT`, never by check-then-act.

mod clients;
mod convert;
mod flows;
mod grants;
mod keys;
mod outbox;
mod sessions;
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
use crate::flows::PgFlows;
use crate::grants::PgGrants;
use crate::keys::PgKeys;
use crate::outbox::PgOutbox;
use crate::sessions::PgSessions;
use crate::setup::PgSetup;
use crate::tenants::PgTenants;
use crate::users::PgUsers;

/// Rows deleted per `purge_expired` statement, so a large backlog never holds long locks.
const PURGE_BATCH: i64 = 1000;

/// Postgres storage backend.
#[derive(Debug, Clone)]
pub struct PostgresStorage {
    pool: PgPool,
    tenants: PgTenants,
    users: PgUsers,
    clients: PgClients,
    keys: PgKeys,
    sessions: PgSessions,
    flows: PgFlows,
    grants: PgGrants,
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
            users: PgUsers { pool: pool.clone() },
            clients: PgClients { pool: pool.clone() },
            keys: PgKeys { pool: pool.clone() },
            sessions: PgSessions { pool: pool.clone() },
            flows: PgFlows { pool: pool.clone() },
            grants: PgGrants { pool: pool.clone() },
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
        &self.users
    }
    fn clients(&self) -> &dyn ClientRepo {
        &self.clients
    }
    fn keys(&self) -> &dyn KeyRepo {
        &self.keys
    }
    fn sessions(&self) -> &dyn SessionRepo {
        &self.sessions
    }
    fn flows(&self) -> &dyn FlowRepo {
        &self.flows
    }
    fn grants(&self) -> &dyn GrantRepo {
        &self.grants
    }
    fn setup(&self) -> &dyn SetupRepo {
        &self.setup
    }
    fn outbox(&self) -> &dyn OutboxRepo {
        &self.outbox
    }

    async fn purge_expired(&self, now: time::OffsetDateTime) -> Result<u64, StorageError> {
        // Batched `DELETE … WHERE ctid IN (SELECT ctid … LIMIT n)` per table until a batch comes
        // back short. Consumed codes and refresh tokens stay until they expire (reuse detection).
        macro_rules! purge {
            ($sql:literal) => {{
                let mut deleted = 0u64;
                loop {
                    let done = sqlx::query!($sql, now, PURGE_BATCH)
                        .execute(&self.pool)
                        .await
                        .map_err(map_err)?;
                    deleted += done.rows_affected();
                    if done.rows_affected() < PURGE_BATCH as u64 {
                        break deleted;
                    }
                }
            }};
        }
        let mut total = 0u64;
        total += purge!(
            "DELETE FROM authorization_code WHERE ctid IN
               (SELECT ctid FROM authorization_code WHERE expires_at <= $1 LIMIT $2)"
        );
        total += purge!(
            "DELETE FROM authorization_request WHERE ctid IN
               (SELECT ctid FROM authorization_request WHERE expires_at <= $1 LIMIT $2)"
        );
        total += purge!(
            "DELETE FROM flow WHERE ctid IN
               (SELECT ctid FROM flow WHERE expires_at <= $1 LIMIT $2)"
        );
        total += purge!(
            "DELETE FROM browser_session WHERE ctid IN
               (SELECT ctid FROM browser_session WHERE expires_at <= $1 LIMIT $2)"
        );
        total += purge!(
            "DELETE FROM refresh_token WHERE ctid IN
               (SELECT ctid FROM refresh_token WHERE expires_at <= $1 LIMIT $2)"
        );
        total += purge!(
            "DELETE FROM replay_guard WHERE ctid IN
               (SELECT ctid FROM replay_guard WHERE expires_at <= $1 LIMIT $2)"
        );
        total += purge!(
            "DELETE FROM self_service_token WHERE ctid IN
               (SELECT ctid FROM self_service_token WHERE expires_at <= $1 LIMIT $2)"
        );
        total += purge!(
            "DELETE FROM admin_setup_token WHERE ctid IN
               (SELECT ctid FROM admin_setup_token WHERE expires_at <= $1 LIMIT $2)"
        );
        total += purge!(
            "DELETE FROM email_outbox WHERE ctid IN
               (SELECT ctid FROM email_outbox
                 WHERE sent_at IS NOT NULL OR expires_at <= $1 LIMIT $2)"
        );
        Ok(total)
    }
}
