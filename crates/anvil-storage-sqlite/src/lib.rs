//! SQLite implementation of the `anvil_core::ports` storage traits (via sqlx).
//!
//! File databases use WAL with a single writer connection and a separate read-only reader pool.
//! All writes (including the atomic `consume_code` UPDATE) go through the one writer, so SQLite
//! never sees concurrent writers. Every multi-row intent method (`create_code`, `rotate_refresh`,
//! `UserRepo::create`, `complete_recovery`, `install`, `complete_setup`, ...) runs as one
//! transaction on that writer.

mod clients;
mod convert;
mod flows;
mod grants;
mod keys;
mod outbox;
mod pending;
mod sessions;
mod setup;
mod tenants;
mod users;

use std::str::FromStr;
use std::time::Duration;

use anvil_core::ports::{
    AuditRepo, ClientRepo, FlowRepo, GrantRepo, JobRepo, KeyRepo, MailSettingsRepo, OutboxRepo,
    SessionRepo, SetupRepo, Storage, StorageError, TenantRepo, UserRepo,
};
use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};

use crate::clients::SqliteClients;
use crate::convert::{map_err, odt_to_ms};
use crate::flows::SqliteFlows;
use crate::grants::SqliteGrants;
use crate::keys::SqliteKeys;
use crate::outbox::SqliteOutbox;
use crate::sessions::SqliteSessions;
use crate::setup::SqliteSetup;
use crate::tenants::SqliteTenants;
use crate::users::SqliteUsers;

/// Maximum number of reader connections for file databases.
const READER_CONNECTIONS: u32 = 8;

/// Rows deleted per statement by `purge_expired`, so a large purge never holds the writer long.
const PURGE_BATCH: i64 = 1000;

/// SQLite storage backend.
#[derive(Debug, Clone)]
pub struct SqliteStorage {
    writer: SqlitePool,
    tenants: SqliteTenants,
    users: SqliteUsers,
    clients: SqliteClients,
    keys: SqliteKeys,
    sessions: SqliteSessions,
    flows: SqliteFlows,
    grants: SqliteGrants,
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
            users: SqliteUsers {
                writer: writer.clone(),
                reader: reader.clone(),
            },
            sessions: SqliteSessions {
                writer: writer.clone(),
                reader: reader.clone(),
            },
            flows: SqliteFlows {
                writer: writer.clone(),
                reader: reader.clone(),
            },
            grants: SqliteGrants {
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
    // TRANSITIONAL: explicit Unsupported until the 0003 migration (see `pending`).
    fn audit(&self) -> &dyn AuditRepo {
        &pending::Pending
    }
    fn mail_settings(&self) -> &dyn MailSettingsRepo {
        &pending::Pending
    }
    fn jobs(&self) -> &dyn JobRepo {
        &pending::Pending
    }

    async fn purge_expired(&self, now: time::OffsetDateTime) -> Result<u64, StorageError> {
        let now = odt_to_ms(now);
        let w = &self.writer;
        // Each statement deletes at most PURGE_BATCH rows (rowid subquery) and is repeated until
        // a batch comes back short. Consumed codes and refresh tokens stay until they expire, so
        // reuse detection keeps working.
        macro_rules! purge {
            ($sql:literal) => {{
                let mut deleted = 0u64;
                loop {
                    let n = sqlx::query!($sql, now, PURGE_BATCH)
                        .execute(w)
                        .await
                        .map_err(map_err)?
                        .rows_affected();
                    deleted += n;
                    if n < PURGE_BATCH as u64 {
                        break deleted;
                    }
                }
            }};
        }
        let mut total = 0u64;
        total += purge!(
            "DELETE FROM authorization_code WHERE rowid IN
               (SELECT rowid FROM authorization_code WHERE expires_at <= ?1 LIMIT ?2)"
        );
        total += purge!(
            "DELETE FROM authorization_request WHERE rowid IN
               (SELECT rowid FROM authorization_request WHERE expires_at <= ?1 LIMIT ?2)"
        );
        total += purge!(
            "DELETE FROM flow WHERE rowid IN
               (SELECT rowid FROM flow WHERE expires_at <= ?1 LIMIT ?2)"
        );
        total += purge!(
            "DELETE FROM browser_session WHERE rowid IN
               (SELECT rowid FROM browser_session
                 WHERE expires_at <= ?1 OR idle_expires_at <= ?1 LIMIT ?2)"
        );
        total += purge!(
            "DELETE FROM refresh_token WHERE rowid IN
               (SELECT rowid FROM refresh_token WHERE expires_at <= ?1 LIMIT ?2)"
        );
        total += purge!(
            "DELETE FROM replay_guard WHERE rowid IN
               (SELECT rowid FROM replay_guard WHERE expires_at <= ?1 LIMIT ?2)"
        );
        total += purge!(
            "DELETE FROM self_service_token WHERE rowid IN
               (SELECT rowid FROM self_service_token WHERE expires_at <= ?1 LIMIT ?2)"
        );
        total += purge!(
            "DELETE FROM admin_setup_token WHERE rowid IN
               (SELECT rowid FROM admin_setup_token WHERE expires_at <= ?1 LIMIT ?2)"
        );
        total += purge!(
            "DELETE FROM email_outbox WHERE rowid IN
               (SELECT rowid FROM email_outbox
                 WHERE sent_at IS NOT NULL OR expires_at <= ?1 LIMIT ?2)"
        );
        // Families past their absolute lifetime can never issue tokens again; keep any that a
        // still-valid code references. Their (unusable) refresh tokens go by cascade.
        total += purge!(
            "DELETE FROM token_family WHERE rowid IN
               (SELECT rowid FROM token_family f
                 WHERE f.absolute_expires_at <= ?1
                   AND NOT EXISTS (SELECT 1 FROM authorization_code c
                                    WHERE c.token_family_id = f.id AND c.expires_at > ?1)
                 LIMIT ?2)"
        );
        Ok(total)
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::*;

    /// 0.1 was never released, but migration 0002 must still apply on a populated Phase 1
    /// database (tenant row kept with default settings, Phase 1 code table replaced).
    #[tokio::test]
    async fn migration_0002_applies_on_a_phase1_database() {
        let storage = SqliteStorage::connect("sqlite::memory:")
            .await
            .expect("connect");
        let mut phase1 = sqlx::migrate!();
        phase1.migrations = Cow::Owned(phase1.migrations[..1].to_vec());
        phase1.run(&storage.writer).await.expect("0001 applies");

        let tenant = uuid::Uuid::now_v7();
        // Unchecked queries: the Phase 1 schema is not the one the query macros check against.
        sqlx::query(
            "INSERT INTO tenant (id, slug, display_name, created_at) VALUES (?1, 'legacy', 'Legacy', 0)",
        )
        .bind(tenant)
        .execute(&storage.writer)
        .await
        .expect("seed phase 1 tenant");
        sqlx::query(
            "INSERT INTO authorization_code
                 (code_hash, tenant_id, client_id, redirect_uri, scope, code_challenge,
                  expires_at, created_at)
             VALUES (zeroblob(32), ?1, 'c', 'https://app.example.test/cb', 'openid', 'x', 1, 0)",
        )
        .bind(tenant)
        .execute(&storage.writer)
        .await
        .expect("seed phase 1 rows");

        storage
            .migrate()
            .await
            .expect("0002 applies on top of 0001");
        let migrated = storage
            .tenants()
            .get_by_slug("legacy")
            .await
            .expect("get_by_slug")
            .expect("the Phase 1 tenant survives");
        assert_eq!(migrated.id.0, tenant);
        assert_eq!(migrated.host, None);
        assert_eq!(migrated.settings, Default::default());
    }
}
