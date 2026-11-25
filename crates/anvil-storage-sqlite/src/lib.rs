//! SQLite implementation of the `anvil_core::ports` storage traits (via sqlx).
//!
//! File databases use WAL with a single writer connection and a separate read-only reader pool.
//! All writes (including the atomic `consume_code` UPDATE) go through the one writer, so SQLite
//! never sees concurrent writers. Every multi-row intent method (`create_code`, `rotate_refresh`,
//! `UserRepo::create`, `complete_recovery`, `install`, `complete_setup`, `create_totp`,
//! `revoke_consent`, `revoke_with_families`, `KeyRepo::promote`, ...) runs as one transaction on
//! that writer. Compare-and-swap methods (`update_passkey`, `advance_totp_step`,
//! `consume_recovery_code`, `swap_state`, `try_lease`) are single conditional statements.

mod audit;
mod clients;
mod consent;
mod convert;
mod credentials;
mod flows;
mod grants;
mod jobs;
mod keys;
mod mail_settings;
pub mod migrate;
mod outbox;
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

use crate::audit::SqliteAudit;
use crate::clients::SqliteClients;
use crate::convert::{map_err, odt_to_ms};
use crate::flows::SqliteFlows;
use crate::grants::SqliteGrants;
use crate::jobs::SqliteJobs;
use crate::keys::SqliteKeys;
use crate::mail_settings::SqliteMailSettings;
use crate::outbox::SqliteOutbox;
use crate::sessions::SqliteSessions;
use crate::setup::SqliteSetup;
use crate::tenants::SqliteTenants;
use crate::users::SqliteUsers;

pub use crate::migrate::{MigrateError, MigrateOptions, PendingMigration};

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
    audit: SqliteAudit,
    mail_settings: SqliteMailSettings,
    jobs: SqliteJobs,
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
            audit: SqliteAudit {
                writer: writer.clone(),
                reader: reader.clone(),
            },
            mail_settings: SqliteMailSettings {
                writer: writer.clone(),
                reader: reader.clone(),
            },
            jobs: SqliteJobs {
                writer: writer.clone(),
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
    fn audit(&self) -> &dyn AuditRepo {
        &self.audit
    }
    fn mail_settings(&self) -> &dyn MailSettingsRepo {
        &self.mail_settings
    }
    fn jobs(&self) -> &dyn JobRepo {
        &self.jobs
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
            "DELETE FROM access_token WHERE rowid IN
               (SELECT rowid FROM access_token WHERE expires_at <= ?1 LIMIT ?2)"
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

    /// 0004 rebuilds token_family with foreign keys off: on a populated 0.1 database (last 0.1
    /// migration = version 2) every code, refresh token and password survives 0003 + 0004, and
    /// foreign keys are enforced again on the migrating connection afterwards.
    #[tokio::test]
    async fn migrations_0003_0004_preserve_a_populated_0_1_database() {
        let storage = SqliteStorage::connect("sqlite::memory:")
            .await
            .expect("connect");
        let mut v01 = sqlx::migrate!();
        v01.migrations = Cow::Owned(v01.migrations[..2].to_vec());
        assert_eq!(v01.migrations.last().map(|m| m.version), Some(2));
        v01.run(&storage.writer).await.expect("0001 + 0002 apply");

        // Unchecked queries: the 0.1 schema is not the one the query macros check against.
        let seed = [
            "INSERT INTO tenant (id, slug, display_name, created_at)
             VALUES (x'0000000000000000000000000000000a', 'legacy', 'Legacy', 0)",
            "INSERT INTO user (id, tenant_id, email, email_verified, claims, status, created_at,
                               updated_at)
             VALUES (x'0000000000000000000000000000000b', x'0000000000000000000000000000000a',
                     'user@example.test', 1, '{}', 'active', 0, 0)",
            "INSERT INTO credential (tenant_id, user_id, kind, secret, created_at, updated_at)
             VALUES (x'0000000000000000000000000000000a', x'0000000000000000000000000000000b',
                     'password', '$argon2id$v=19$legacy', 1, 2)",
            "INSERT INTO flow (id, tenant_id, kind, state, csrf_hash, cookie_hash, created_at,
                               expires_at)
             VALUES (x'0000000000000000000000000000000f', x'0000000000000000000000000000000a',
                     'login', '{}', zeroblob(32), zeroblob(32), 0, 9999999999999)",
            "INSERT INTO token_family (id, tenant_id, client_id, user_id, scope, amr, created_at,
                                       absolute_expires_at, revoked_at, revoked_reason)
             VALUES (x'0000000000000000000000000000000c', x'0000000000000000000000000000000a',
                     'app', x'0000000000000000000000000000000b', 'openid', '[\"pwd\"]', 0,
                     9999999999999, NULL, NULL),
                    (x'0000000000000000000000000000000d', x'0000000000000000000000000000000a',
                     'app', x'0000000000000000000000000000000b', 'openid', '[]', 0,
                     9999999999999, 5, 'refresh_reuse')",
            "INSERT INTO authorization_code
                 (code_hash, tenant_id, client_id, user_id, session_id, redirect_uri, scope,
                  auth_time, acr, amr, token_family_id, expires_at, created_at)
             VALUES (x'0101010101010101010101010101010101010101010101010101010101010101',
                     x'0000000000000000000000000000000a', 'app', x'0000000000000000000000000000000b',
                     x'0000000000000000000000000000000e', 'https://app.example.test/cb', 'openid',
                     0, 'urn:anvilid:acr:pwd', '[\"pwd\"]', x'0000000000000000000000000000000c',
                     9999999999999, 0)",
            "INSERT INTO refresh_token (token_hash, tenant_id, family_id, scope, created_at,
                                        expires_at)
             VALUES (x'0202020202020202020202020202020202020202020202020202020202020202',
                     x'0000000000000000000000000000000a', x'0000000000000000000000000000000c',
                     'openid', 0, 9999999999999),
                    (x'0303030303030303030303030303030303030303030303030303030303030303',
                     x'0000000000000000000000000000000a', x'0000000000000000000000000000000d',
                     'openid', 0, 9999999999999)",
        ];
        for sql in seed {
            sqlx::query(sql)
                .execute(&storage.writer)
                .await
                .unwrap_or_else(|e| panic!("seed failed: {e}: {sql}"));
        }

        storage
            .migrate()
            .await
            .expect("0003 + 0004 apply on 0.1 data");

        let count = |sql: &'static str| {
            let w = storage.writer.clone();
            async move {
                sqlx::query_scalar::<_, i64>(sql)
                    .fetch_one(&w)
                    .await
                    .expect(sql)
            }
        };
        assert_eq!(count("SELECT count(*) FROM token_family").await, 2);
        assert_eq!(
            count("SELECT count(*) FROM token_family WHERE revoked_reason = 'refresh_reuse'").await,
            1
        );
        assert_eq!(count("SELECT count(*) FROM authorization_code").await, 1);
        assert_eq!(count("SELECT count(*) FROM refresh_token").await, 2);
        assert_eq!(count("SELECT count(*) FROM flow").await, 1);
        assert_eq!(
            count(
                "SELECT count(*) FROM credential
                  WHERE kind = 'password' AND secret = '$argon2id$v=19$legacy'
                    AND length(id) = 16 AND created_at = 1 AND updated_at = 2"
            )
            .await,
            1
        );
        // The new revoke reasons are accepted.
        sqlx::query(
            "UPDATE token_family SET revoked_at = 7, revoked_reason = 'consent_revoked'
              WHERE id = x'0000000000000000000000000000000c'",
        )
        .execute(&storage.writer)
        .await
        .expect("consent_revoked accepted");
        // Foreign keys are on again on the migrating connection, and the references from codes
        // and refresh tokens now point at the rebuilt table.
        assert_eq!(count("PRAGMA foreign_keys").await, 1);
        assert_eq!(
            count("SELECT count(*) FROM pragma_foreign_key_check").await,
            0
        );
        let dangling = sqlx::query(
            "INSERT INTO refresh_token (token_hash, tenant_id, family_id, scope, created_at,
                                        expires_at)
             VALUES (x'0404040404040404040404040404040404040404040404040404040404040404',
                     x'0000000000000000000000000000000a', x'000000000000000000000000000000ff',
                     'openid', 0, 1)",
        )
        .execute(&storage.writer)
        .await;
        assert!(dangling.is_err(), "foreign keys must be enforced again");
        sqlx::query("DELETE FROM token_family WHERE id = x'0000000000000000000000000000000c'")
            .execute(&storage.writer)
            .await
            .expect("delete family");
        assert_eq!(count("SELECT count(*) FROM authorization_code").await, 0);
        assert_eq!(count("SELECT count(*) FROM refresh_token").await, 1);
    }
}
