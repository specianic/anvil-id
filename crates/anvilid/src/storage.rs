//! Storage backend selection. `anvilid` is the only crate that knows the concrete backends.

use std::sync::Arc;

use anvil_core::ports::Storage;
use anvil_storage_postgres::PostgresStorage;
use anvil_storage_sqlite::SqliteStorage;
use anyhow::{Context, bail};

/// Maximum Postgres pool size.
const POSTGRES_MAX_CONNECTIONS: u32 = 10;

/// Backend selected by the database URL scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Backend {
    Sqlite,
    Postgres,
}

impl Backend {
    fn from_url(url: &str) -> anyhow::Result<Self> {
        if url.starts_with("sqlite:") {
            Ok(Self::Sqlite)
        } else if url.starts_with("postgres://") || url.starts_with("postgresql://") {
            Ok(Self::Postgres)
        } else {
            // Never echo the URL: it may contain a password.
            bail!("unsupported database URL scheme (expected sqlite: or postgres://)")
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Sqlite => "sqlite",
            Self::Postgres => "postgres",
        }
    }
}

/// Opens the backend selected by the URL scheme and applies its migrations.
///
/// Only the backend kind is logged; the URL may hold credentials.
pub async fn open_storage(url: &str) -> anyhow::Result<Arc<dyn Storage>> {
    let backend = Backend::from_url(url)?;
    tracing::info!(backend = backend.name(), "opening storage");
    let storage: Arc<dyn Storage> = match backend {
        Backend::Sqlite => {
            let s = SqliteStorage::connect(url)
                .await
                .context("failed to open sqlite database")?;
            s.migrate()
                .await
                .context("failed to migrate sqlite database")?;
            Arc::new(s)
        }
        Backend::Postgres => {
            let s = PostgresStorage::connect(url, POSTGRES_MAX_CONNECTIONS)
                .await
                .context("failed to connect to postgres")?;
            s.migrate()
                .await
                .context("failed to migrate postgres database")?;
            Arc::new(s)
        }
    };
    tracing::info!(
        backend = backend.name(),
        "storage ready (migrations applied)"
    );
    Ok(storage)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_backend_by_scheme() {
        for (url, want) in [
            ("sqlite::memory:", Backend::Sqlite),
            ("sqlite:///var/lib/anvil.db?mode=rwc", Backend::Sqlite),
            ("postgres://u@localhost/anvil", Backend::Postgres),
            ("postgresql://u@localhost/anvil", Backend::Postgres),
        ] {
            assert_eq!(Backend::from_url(url).expect(url), want, "{url}");
        }
    }

    #[test]
    fn rejects_unknown_scheme_without_echoing_url() {
        for bad in [
            "mysql://user:s3cret@db/anvil",
            "",
            "anvil.db",
            "postgres:/x",
        ] {
            let err = Backend::from_url(bad).expect_err(bad).to_string();
            assert!(err.contains("unsupported database URL scheme"), "{err}");
            assert!(!err.contains("s3cret"), "error leaked the URL: {err}");
        }
    }
}
