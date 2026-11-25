//! PostgreSQL implementation of the `anvil_core::ports` storage traits (via sqlx).
//!
//! Native column types: `uuid` ids, `bytea` hashes, `timestamptz` timestamps, `jsonb` documents,
//! `text[]` lists. All repositories share one connection pool. Multi-row intent methods run in
//! one transaction (READ COMMITTED); races are decided by row-level conditional
//! `UPDATE … RETURNING` / `INSERT … ON CONFLICT`, never by check-then-act.

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

use anvil_core::ports::{
    AuditRepo, ClientRepo, FlowRepo, GrantRepo, JobRepo, KeyRepo, MailSettingsRepo, OutboxRepo,
    SessionRepo, SetupRepo, Storage, StorageError, TenantRepo, UserRepo,
};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

use crate::audit::PgAudit;
use crate::clients::PgClients;
use crate::convert::map_err;
use crate::flows::PgFlows;
use crate::grants::PgGrants;
use crate::jobs::PgJobs;
use crate::keys::PgKeys;
use crate::mail_settings::PgMailSettings;
use crate::outbox::PgOutbox;
use crate::sessions::PgSessions;
use crate::setup::PgSetup;
use crate::tenants::PgTenants;
use crate::users::PgUsers;

pub use crate::migrate::{MigrateError, MigrateOptions, PendingMigration};

/// Rows deleted per `purge_expired` statement, so a large backlog never holds long locks.
pub(crate) const PURGE_BATCH: i64 = 1000;

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
    audit: PgAudit,
    mail_settings: PgMailSettings,
    jobs: PgJobs,
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
            audit: PgAudit { pool: pool.clone() },
            mail_settings: PgMailSettings { pool: pool.clone() },
            jobs: PgJobs { pool: pool.clone() },
            pool,
        }
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
            "DELETE FROM access_token WHERE ctid IN
               (SELECT ctid FROM access_token WHERE expires_at <= $1 LIMIT $2)"
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

#[cfg(test)]
mod tests {
    //! Migration upgrade path: a populated 0.1 database (0001 + 0002) migrates to 0.2 with
    //! every row intact. Needs Docker (testcontainers), like the contract suite.

    use std::borrow::Cow;

    use sqlx::{Connection, PgConnection};
    use testcontainers_modules::postgres::Postgres;
    use testcontainers_modules::testcontainers::{ImageExt, runners::AsyncRunner};
    use uuid::Uuid;

    /// The embedded migrator restricted to versions `<= max`.
    fn migrator_up_to(max: i64) -> sqlx::migrate::Migrator {
        let mut m = sqlx::migrate!();
        m.migrations = Cow::Owned(
            m.migrations
                .iter()
                .filter(|x| x.version <= max)
                .cloned()
                .collect(),
        );
        m
    }

    async fn connect(url: &str) -> PgConnection {
        let mut last = None;
        for _ in 0..50 {
            match PgConnection::connect(url).await {
                Ok(c) => return c,
                Err(e) => {
                    last = Some(e);
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                }
            }
        }
        panic!("connecting to the test Postgres failed: {last:?}");
    }

    async fn exec(conn: &mut PgConnection, sql: &str) -> Result<u64, sqlx::Error> {
        sqlx::raw_sql(sqlx::AssertSqlSafe(sql.to_owned()))
            .execute(&mut *conn)
            .await
            .map(|r| r.rows_affected())
    }

    #[tokio::test]
    async fn migration_0003_upgrades_a_populated_0_1_database() {
        let container = Postgres::default()
            .with_tag("18-alpine")
            .start()
            .await
            .expect("docker must be running for Postgres migration tests");
        let host = container.get_host().await.expect("host");
        let port = container.get_host_port_ipv4(5432).await.expect("port");
        // Default credentials of the throwaway testcontainers image, not a secret.
        let url = format!("postgres://postgres:postgres@{host}:{port}/postgres");
        let mut conn = connect(&url).await;

        migrator_up_to(2)
            .run(&mut conn)
            .await
            .expect("0001 + 0002 must apply");

        let tenant = Uuid::now_v7();
        let user = Uuid::now_v7();
        let family = Uuid::now_v7();
        let seed = format!(
            "INSERT INTO tenant (id, slug, display_name, created_at)
                  VALUES ('{tenant}', 'acme', 'Acme', now());
             INSERT INTO \"user\" (id, tenant_id, email, email_verified, status, created_at,
                                   updated_at)
                  VALUES ('{user}', '{tenant}', 'a@example.test', true, 'active', now(), now());
             INSERT INTO credential (tenant_id, user_id, kind, data, created_at, updated_at)
                  VALUES ('{tenant}', '{user}', 'password', '$argon2id$v=19$fake', now(), now());
             INSERT INTO client (id, tenant_id, client_id, name, client_type, application_type,
                                 auth_method, redirect_uris, grant_types, scopes, require_pkce,
                                 created_at, updated_at)
                  VALUES ('{c}', '{tenant}', 'web', 'Web', 'public', 'web', 'none',
                          ARRAY['https://rp.example.test/cb'], ARRAY['authorization_code'],
                          ARRAY['openid'], true, now(), now());
             INSERT INTO browser_session (id, tenant_id, user_id, token_hash, auth_time, acr,
                                          amr, created_at, last_seen_at, expires_at,
                                          idle_expires_at)
                  VALUES ('{s}', '{tenant}', '{user}', decode(repeat('ab', 32), 'hex'), now(),
                          'urn:anvilid:acr:pwd', ARRAY['pwd'], now(), now(),
                          now() + interval '1 day', now() + interval '1 hour');
             INSERT INTO token_family (id, tenant_id, client_id, user_id, scope, amr, created_at,
                                       absolute_expires_at, revoked_at, revoked_reason)
                  VALUES ('{family}', '{tenant}', 'web', '{user}', 'openid', ARRAY['pwd'], now(),
                          now() + interval '30 days', now(), 'admin');
             INSERT INTO refresh_token (token_hash, tenant_id, family_id, scope, created_at,
                                        expires_at)
                  VALUES (decode(repeat('cd', 32), 'hex'), '{tenant}', '{family}', 'openid',
                          now(), now() + interval '30 days');
             -- 0.1 had no user FK on codes: an expired code of a since-deleted user may exist.
             INSERT INTO authorization_code (code_hash, tenant_id, client_id, redirect_uri, scope,
                                             code_challenge, token_family_id, user_id, session_id,
                                             auth_time, acr, amr, expires_at, created_at)
                  VALUES (decode(repeat('ef', 32), 'hex'), '{tenant}', 'web',
                          'https://rp.example.test/cb', 'openid', NULL, '{family}', '{gone}',
                          '{s}', now(), 'urn:anvilid:acr:pwd', ARRAY['pwd'], now(), now());",
            c = Uuid::now_v7(),
            s = Uuid::now_v7(),
            gone = Uuid::now_v7(),
        );
        exec(&mut conn, &seed).await.expect("seeding 0.1 rows");

        migrator_up_to(i64::MAX)
            .run(&mut conn)
            .await
            .expect("0003 must apply on a populated 0.1 database");

        // Rows intact; the password credential got an id; new columns have their defaults.
        let (id, kind, data, label, backup): (Uuid, String, String, String, bool) = sqlx::query_as(
            "SELECT id, kind, data, label, backup_eligible FROM credential WHERE user_id = $1",
        )
        .bind(user)
        .fetch_one(&mut conn)
        .await
        .expect("the password credential survives");
        assert!(!id.is_nil());
        assert_eq!(
            (kind.as_str(), data.as_str(), label.as_str(), backup),
            ("password", "$argon2id$v=19$fake", "", false)
        );
        let (fmt, mode, alg, introspect): (String, String, Option<String>, bool) = sqlx::query_as(
            "SELECT token_format, consent_mode, id_token_signed_response_alg, can_introspect
                   FROM client WHERE client_id = 'web'",
        )
        .fetch_one(&mut conn)
        .await
        .expect("the client survives");
        assert_eq!(
            (fmt.as_str(), mode.as_str(), alg, introspect),
            ("jwt", "required", None, false)
        );
        let (ip, ua): (Option<String>, Option<String>) =
            sqlx::query_as("SELECT ip, user_agent FROM browser_session WHERE user_id = $1")
                .bind(user)
                .fetch_one(&mut conn)
                .await
                .expect("the session survives");
        assert_eq!((ip, ua), (None, None));
        let tokens: i64 =
            sqlx::query_scalar("SELECT count(*) FROM refresh_token WHERE family_id = $1")
                .bind(family)
                .fetch_one(&mut conn)
                .await
                .expect("count");
        assert_eq!(tokens, 1, "refresh tokens survive");

        // Swapped CHECK constraints accept the new values and still reject unknown ones.
        for reason in ["consent_revoked", "session_revoked", "token_revoked"] {
            exec(
                &mut conn,
                &format!(
                    "UPDATE token_family SET revoked_reason = '{reason}' WHERE id = '{family}'"
                ),
            )
            .await
            .unwrap_or_else(|e| panic!("reason {reason} must be accepted: {e}"));
        }
        assert!(
            exec(
                &mut conn,
                &format!("UPDATE token_family SET revoked_reason = 'bogus' WHERE id = '{family}'"),
            )
            .await
            .is_err(),
            "an unknown revoke reason must still be rejected"
        );
        for kind in ["settings", "consent"] {
            exec(
                &mut conn,
                &format!(
                    "INSERT INTO flow (id, tenant_id, kind, state, csrf_hash, cookie_hash,
                                       created_at, expires_at)
                          VALUES ('{}', '{tenant}', '{kind}', '{{}}', decode(repeat('01', 32),
                                  'hex'), decode(repeat('02', 32), 'hex'), now(), now())",
                    Uuid::now_v7()
                ),
            )
            .await
            .unwrap_or_else(|e| panic!("flow kind {kind} must be accepted: {e}"));
        }
        assert!(
            exec(
                &mut conn,
                &format!(
                    "INSERT INTO flow (id, tenant_id, kind, state, csrf_hash, cookie_hash,
                                       created_at, expires_at)
                          VALUES ('{}', '{tenant}', 'bogus', '{{}}', decode(repeat('01', 32),
                                  'hex'), decode(repeat('02', 32), 'hex'), now(), now())",
                    Uuid::now_v7()
                ),
            )
            .await
            .is_err(),
            "an unknown flow kind must still be rejected"
        );
        let insert_credential = |kind: &str, ext: &str| {
            format!(
                "INSERT INTO credential (id, tenant_id, user_id, kind, data, external_id,
                                         created_at, updated_at)
                      VALUES ('{}', '{tenant}', '{user}', '{kind}', 'x', {ext}, now(), now())",
                Uuid::now_v7()
            )
        };
        exec(&mut conn, &insert_credential("webauthn", "'\\x01'::bytea"))
            .await
            .expect("a passkey row is accepted");
        assert!(
            exec(&mut conn, &insert_credential("webauthn", "'\\x01'::bytea"))
                .await
                .is_err(),
            "a WebAuthn credential id is unique per tenant"
        );
        assert!(
            exec(&mut conn, &insert_credential("password", "NULL"))
                .await
                .is_err(),
            "a second password is rejected"
        );
        assert!(
            exec(&mut conn, &insert_credential("bogus", "NULL"))
                .await
                .is_err(),
            "an unknown credential kind must still be rejected"
        );
        conn.close().await.expect("close");
    }

    /// Tenant isolation is enforced by the schema, like SQLite: every user-owned row carries a
    /// composite foreign key `(tenant_id, user_id) → "user"(tenant_id, id)`, so a row written
    /// under tenant A for a user of tenant B is rejected by the database itself (raw SQL, no
    /// repository pre-check involved).
    #[tokio::test]
    async fn composite_tenant_foreign_keys_reject_cross_tenant_rows() {
        let container = Postgres::default()
            .with_tag("18-alpine")
            .start()
            .await
            .expect("docker must be running for Postgres migration tests");
        let host = container.get_host().await.expect("host");
        let port = container.get_host_port_ipv4(5432).await.expect("port");
        // Default credentials of the throwaway testcontainers image, not a secret.
        let url = format!("postgres://postgres:postgres@{host}:{port}/postgres");
        let mut conn = connect(&url).await;
        migrator_up_to(i64::MAX)
            .run(&mut conn)
            .await
            .expect("all migrations must apply");

        let (a, b, user_b) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
        let family = Uuid::now_v7();
        exec(
            &mut conn,
            &format!(
                "INSERT INTO tenant (id, slug, display_name, created_at)
                      VALUES ('{a}', 'a', 'A', now()), ('{b}', 'b', 'B', now());
                 INSERT INTO \"user\" (id, tenant_id, email, email_verified, status, created_at,
                                       updated_at)
                      VALUES ('{user_b}', '{b}', 'b@example.test', true, 'active', now(), now());
                 INSERT INTO token_family (id, tenant_id, client_id, user_id, scope, amr,
                                           created_at, absolute_expires_at)
                      VALUES ('{family}', '{b}', 'web', '{user_b}', 'openid', ARRAY['pwd'], now(),
                              now() + interval '30 days');"
            ),
        )
        .await
        .expect("seeding two tenants");

        // One insert per user-owned table; `{t}` is the tenant written on the row.
        type InsertFor = Box<dyn Fn(Uuid) -> String>;
        let rows: [(&str, InsertFor); 6] = [
            (
                "credential",
                Box::new(move |t| {
                    format!(
                        "INSERT INTO credential (id, tenant_id, user_id, kind, data, created_at,
                                                 updated_at)
                              VALUES ('{}', '{t}', '{user_b}', 'totp', 'x', now(), now())",
                        Uuid::now_v7()
                    )
                }),
            ),
            (
                "recovery_code",
                Box::new(move |t| {
                    format!(
                        "INSERT INTO recovery_code (tenant_id, user_id, code_hash, created_at)
                              VALUES ('{t}', '{user_b}', decode(repeat('ab', 32), 'hex'), now())"
                    )
                }),
            ),
            (
                "consent_grant",
                Box::new(move |t| {
                    format!(
                        "INSERT INTO consent_grant (id, tenant_id, user_id, client_id, scopes,
                                                    created_at, updated_at)
                              VALUES ('{}', '{t}', '{user_b}', 'web', '[]', now(), now())",
                        Uuid::now_v7()
                    )
                }),
            ),
            (
                "self_service_token",
                Box::new(move |t| {
                    format!(
                        "INSERT INTO self_service_token (token_hash, tenant_id, kind, user_id,
                                                         email, created_at, expires_at)
                              VALUES (decode(md5(random()::text) || md5(random()::text), 'hex'),
                                      '{t}', 'verification', '{user_b}', 'b@example.test', now(),
                                      now() + interval '1 hour')"
                    )
                }),
            ),
            (
                "browser_session",
                Box::new(move |t| {
                    format!(
                        "INSERT INTO browser_session (id, tenant_id, user_id, token_hash,
                                                      auth_time, acr, amr, created_at,
                                                      last_seen_at, expires_at, idle_expires_at)
                              VALUES ('{}', '{t}', '{user_b}',
                                      decode(md5(random()::text) || md5(random()::text), 'hex'),
                                      now(), 'urn:anvilid:acr:pwd', ARRAY['pwd'], now(), now(),
                                      now() + interval '1 day', now() + interval '1 hour')",
                        Uuid::now_v7()
                    )
                }),
            ),
            (
                "authorization_code",
                Box::new(move |t| {
                    format!(
                        "INSERT INTO authorization_code (code_hash, tenant_id, client_id,
                                                         redirect_uri, scope, token_family_id,
                                                         user_id, session_id, auth_time, acr, amr,
                                                         expires_at, created_at)
                              VALUES (decode(md5(random()::text) || md5(random()::text), 'hex'),
                                      '{t}', 'web', 'https://rp.example.test/cb', 'openid',
                                      '{family}', '{user_b}', '{}', now(), 'urn:anvilid:acr:pwd',
                                      ARRAY['pwd'], now() + interval '1 minute', now())",
                        Uuid::now_v7()
                    )
                }),
            ),
        ];

        for (table, insert) in &rows {
            let err = exec(&mut conn, &insert(a)).await.expect_err(&format!(
                "{table}: a row for another tenant's user is rejected"
            ));
            let code = err
                .as_database_error()
                .and_then(|d| d.code())
                .map(|c| c.into_owned());
            assert_eq!(
                code.as_deref(),
                Some("23503"),
                "{table}: rejected by a foreign key, got {err}"
            );
            exec(&mut conn, &insert(b))
                .await
                .unwrap_or_else(|e| panic!("{table}: a row in the user's own tenant: {e}"));
        }

        // Deleting the user still cascades to every user-owned row.
        exec(
            &mut conn,
            &format!("DELETE FROM \"user\" WHERE id = '{user_b}'"),
        )
        .await
        .expect("delete user");
        for (table, _) in &rows {
            let left: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
                "SELECT count(*) FROM {table} WHERE user_id = $1"
            )))
            .bind(user_b)
            .fetch_one(&mut conn)
            .await
            .expect("count");
            assert_eq!(left, 0, "{table}: rows cascade with the user");
        }
        conn.close().await.expect("close");
    }
}
