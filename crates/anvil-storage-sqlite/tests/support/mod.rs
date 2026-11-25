//! Factories for the shared storage contract suite.

use std::sync::Arc;

use anvil_storage::contract::TestStorage;
use anvil_storage_sqlite::SqliteStorage;

async fn open(url: &str) -> SqliteStorage {
    let storage = SqliteStorage::connect(url)
        .await
        .expect("connecting to SQLite must succeed");
    storage.migrate().await.expect("migrations must apply");
    storage
}

/// A fresh in-memory database (one shared connection).
pub async fn sqlite_memory() -> TestStorage {
    TestStorage {
        storage: Arc::new(open("sqlite::memory:").await),
        _guard: Box::new(()),
    }
}

/// A fresh file-backed database in a temporary directory (WAL, writer + reader pools).
pub async fn sqlite_file() -> TestStorage {
    let dir = tempfile::tempdir().expect("creating a temp dir must succeed");
    let path = dir.path().join("anvil.db");
    let url = format!("sqlite://{}", path.display());
    TestStorage {
        storage: Arc::new(open(&url).await),
        _guard: Box::new(dir),
    }
}
