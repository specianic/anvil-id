//! SQLite implementation of the `anvil_core::ports` storage traits (via sqlx).
//!
//! File databases use WAL with a single writer connection and a separate read-only reader pool.
//! All writes (including the atomic `consume_code` UPDATE) go through the one writer, so SQLite
//! never sees concurrent writers.

mod clients;
mod convert;
mod keys;
mod outbox;
// TRANSITIONAL (plan 02-02): users, sessions, flows and grants are `pending::Pending` until the
// second half of plan 02-05 lands.
mod pending;
mod setup;
mod tenants;
mod users;

use std::str::FromStr;
use std::time::Duration;

use anvil_core::ports::{
    ClientRepo, FlowRepo, GrantRepo, KeyRepo, OutboxRepo, SessionRepo, SetupRepo, Storage,
    StorageError, TenantRepo, UserRepo,
};
use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};

use crate::clients::SqliteClients;
use crate::convert::map_err;
use crate::keys::SqliteKeys;
use crate::outbox::SqliteOutbox;
use crate::pending::Pending;
use crate::setup::SqliteSetup;
use crate::tenants::SqliteTenants;

/// Maximum number of reader connections for file databases.
const READER_CONNECTIONS: u32 = 8;

/// SQLite storage backend.
#[derive(Debug, Clone)]
pub struct SqliteStorage {
    writer: SqlitePool,
    tenants: SqliteTenants,
    clients: SqliteClients,
    keys: SqliteKeys,
    setup: SqliteSetup,
    outbox: SqliteOutbox,
}

fn is_memory_url(url: &str) -> bool {
    matches!(url, "sqlite::memory:" | ":memory:" | "sqlite://:memory:")
}

impl SqliteStorage {
    /// Opens (creating if missing) the DB. File URLs: WAL, synchronous=NORMAL, busy_timeout 5s,
    /// foreign_keys, writer pool of 1 + read-only reader pool. `sqlite::memory:` → one shared
    /// single-connection pool.
    pub async fn connect(url: &str) -> Result<Self, StorageError> {
        let base = SqliteConnectOptions::from_str(url)
            .map_err(map_err)?
            .busy_timeout(Duration::from_secs(5))
            .foreign_keys(true);

        let (writer, reader) = if is_memory_url(url) {
            // A shared-cache in-memory DB disappears with its last connection and reports
            // SQLITE_LOCKED (not covered by busy_timeout) across connections: use exactly one
            // connection that never closes, as both writer and reader.
            let pool = SqlitePoolOptions::new()
                .max_connections(1)
                .min_connections(1)
                .idle_timeout(None)
                .max_lifetime(None)
                .connect_with(base)
                .await
                .map_err(map_err)?;
            (pool.clone(), pool)
        } else {
            let base = base
                .journal_mode(SqliteJournalMode::Wal)
                .synchronous(SqliteSynchronous::Normal);
            // The writer connects first so the file (and WAL) exist before readers open it.
            let writer = SqlitePoolOptions::new()
                .max_connections(1)
                .connect_with(base.clone().create_if_missing(true))
                .await
                .map_err(map_err)?;
            let reader = SqlitePoolOptions::new()
                .max_connections(READER_CONNECTIONS)
                .connect_with(base.read_only(true))
                .await
                .map_err(map_err)?;
            (writer, reader)
        };

        Ok(Self {
            tenants: SqliteTenants {
                writer: writer.clone(),
                reader: reader.clone(),
            },
            clients: SqliteClients {
                writer: writer.clone(),
                reader: reader.clone(),
            },
            keys: SqliteKeys {
                writer: writer.clone(),
                reader: reader.clone(),
            },
            setup: SqliteSetup {
                writer: writer.clone(),
                reader,
            },
            outbox: SqliteOutbox {
                writer: writer.clone(),
            },
            writer,
        })
    }

    /// Runs embedded migrations on the writer.
    pub async fn migrate(&self) -> Result<(), StorageError> {
        sqlx::migrate!()
            .run(&self.writer)
            .await
            .map_err(|e| StorageError::Backend(Box::new(e)))
    }
}

#[async_trait::async_trait]
impl Storage for SqliteStorage {
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
            "sqlite: Storage::purge_expired lands in plan 02-05",
        ))
    }
}
