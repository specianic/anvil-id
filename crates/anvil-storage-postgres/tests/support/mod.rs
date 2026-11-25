//! Postgres factory for the shared storage contract suite.
//!
//! One Postgres 18 container per test binary (started lazily, never dropped: it outlives the
//! process and is removed by the test VM or `docker rm`), and a fresh database per test. Each
//! `#[tokio::test]` has its own runtime, so no pool is kept across tests; only the container
//! handle and the admin URL are shared.

use std::sync::Arc;

use anvil_storage::contract::TestStorage;
use anvil_storage_postgres::PostgresStorage;
use sqlx::Connection;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::{ContainerAsync, ImageExt, runners::AsyncRunner};
use uuid::Uuid;

/// Pool size per test database. Must exceed the 32 concurrent consumers of the concurrency test
/// so the competing UPDATEs really overlap in the database.
const MAX_CONNECTIONS: u32 = 40;

static PG: tokio::sync::OnceCell<(ContainerAsync<Postgres>, String)> =
    tokio::sync::OnceCell::const_new();

/// Server URL of the shared container without a database name (`postgres://user:pass@host:port`).
async fn server_url() -> &'static str {
    let (_, url) = PG
        .get_or_init(|| async {
            let container = Postgres::default()
                .with_tag("18-alpine")
                .with_cmd(["postgres", "-c", "max_connections=500"])
                .start()
                .await
                .expect("docker must be running for Postgres contract tests");
            let host = container
                .get_host()
                .await
                .expect("container host must be available");
            let port = container
                .get_host_port_ipv4(5432)
                .await
                .expect("container port 5432 must be mapped");
            // Default credentials of the throwaway testcontainers image, not a secret.
            let url = format!("postgres://postgres:postgres@{host}:{port}");
            (container, url)
        })
        .await;
    url
}

/// A fresh, migrated database on the shared container. The guard holds the database URL
/// (`String`) so row-inspection tests can open their own connection.
pub async fn postgres() -> TestStorage {
    let server = server_url().await;
    let db = format!("test_{}", Uuid::now_v7().simple());

    // Create the database through a short-lived admin connection to `postgres` (never template1).
    let mut admin = sqlx::PgConnection::connect(&format!("{server}/postgres"))
        .await
        .expect("admin connection to the test Postgres must succeed");
    // `db` is built only from a UUID's hex digits, so interpolating it is safe.
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {db}")))
        .execute(&mut admin)
        .await
        .expect("creating the per-test database must succeed");
    admin
        .close()
        .await
        .expect("closing the admin connection must succeed");

    let url = format!("{server}/{db}");
    let storage = PostgresStorage::connect(&url, MAX_CONNECTIONS)
        .await
        .expect("connecting to the per-test database must succeed");
    storage.migrate().await.expect("migrations must apply");

    TestStorage {
        storage: Arc::new(storage),
        _guard: Box::new(url),
    }
}
