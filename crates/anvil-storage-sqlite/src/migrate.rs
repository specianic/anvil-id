//! Schema migrations with a destructive-migration guard (OPS-04).
//!
//! Migrations run automatically, but a pending migration whose file is named
//! `NNNN_destructive_*.sql` is refused unless the operator passes
//! [`MigrateOptions::allow_destructive`]. sqlx derives a migration's description from the file
//! name with underscores turned into spaces, so `0005_destructive_drop_x.sql` has version 5 and
//! description `destructive drop x`.
//!
//! The pending set is computed on the writer connection that then runs the migrations. File
//! databases have exactly one writer connection per process, so nothing else in this process can
//! migrate in between. Across processes the check cannot be bypassed either: the pending set only
//! shrinks, and the migrator runs the same embedded list it was checked against.

use std::collections::HashSet;
use std::fmt;

use anvil_core::ports::StorageError;
use sqlx::SqliteConnection;
use sqlx::migrate::{Migrate, Migrator};

use crate::SqliteStorage;
use crate::convert::map_err;

/// Description prefix that marks a migration as destructive (from `NNNN_destructive_*.sql`).
const DESTRUCTIVE_PREFIX: &str = "destructive";

/// How migrations may run.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MigrateOptions {
    /// Apply pending destructive migrations instead of refusing to start.
    pub allow_destructive: bool,
}

/// A migration not yet applied to the database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingMigration {
    pub version: i64,
    /// sqlx's description: the file name after the version, underscores as spaces.
    pub description: String,
}

impl PendingMigration {
    /// `NNNN_destructive_*` migrations.
    pub fn is_destructive(&self) -> bool {
        self.description == DESTRUCTIVE_PREFIX
            || self
                .description
                .strip_prefix(DESTRUCTIVE_PREFIX)
                .is_some_and(|rest| rest.starts_with(' '))
    }
}

impl fmt::Display for PendingMigration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04} {}", self.version, self.description)
    }
}

/// Why migrations did not run.
#[derive(Debug, thiserror::Error)]
pub enum MigrateError {
    /// Pending destructive migrations and no explicit permission; nothing was applied.
    #[error("pending destructive migrations: {}", list(.0))]
    Destructive(Vec<PendingMigration>),
    #[error(transparent)]
    Storage(#[from] StorageError),
}

fn list(pending: &[PendingMigration]) -> String {
    pending
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn backend(e: sqlx::migrate::MigrateError) -> MigrateError {
    MigrateError::Storage(StorageError::Backend(Box::new(e)))
}

/// The destructive migrations among `pending`.
pub fn destructive(pending: &[PendingMigration]) -> Vec<PendingMigration> {
    pending
        .iter()
        .filter(|m| m.is_destructive())
        .cloned()
        .collect()
}

/// Up migrations of `migrator` not recorded in its bookkeeping table. Creates nothing: a database
/// without the table has every migration pending.
pub(crate) async fn pending(
    migrator: &Migrator,
    conn: &mut SqliteConnection,
) -> Result<Vec<PendingMigration>, MigrateError> {
    let table = migrator.table_name.as_ref();
    let exists: i64 =
        sqlx::query_scalar("SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?1")
            .bind(table)
            .fetch_one(&mut *conn)
            .await
            .map_err(map_err)?;
    let applied: HashSet<i64> = if exists > 0 {
        conn.list_applied_migrations(table)
            .await
            .map_err(backend)?
            .into_iter()
            .map(|m| m.version)
            .collect()
    } else {
        HashSet::new()
    };
    Ok(migrator
        .iter()
        .filter(|m| !m.migration_type.is_down_migration() && !applied.contains(&m.version))
        .map(|m| PendingMigration {
            version: m.version,
            description: m.description.to_string(),
        })
        .collect())
}

/// Runs `migrator` on `conn` after checking its pending migrations against `opts`. A refusal
/// happens before anything is applied.
pub(crate) async fn run_guarded(
    migrator: &Migrator,
    conn: &mut SqliteConnection,
    opts: MigrateOptions,
) -> Result<(), MigrateError> {
    let pending = pending(migrator, conn).await?;
    if pending.is_empty() {
        return Ok(());
    }
    let destructive = destructive(&pending);
    if !destructive.is_empty() && !opts.allow_destructive {
        return Err(MigrateError::Destructive(destructive));
    }
    migrator.run(&mut *conn).await.map_err(backend)
}

impl SqliteStorage {
    /// Runs the embedded migrations on the writer, refusing pending destructive migrations
    /// unless `opts.allow_destructive` is set.
    pub async fn migrate_with(&self, opts: MigrateOptions) -> Result<(), MigrateError> {
        let mut conn = self.writer.acquire().await.map_err(map_err)?;
        run_guarded(&sqlx::migrate!(), &mut conn, opts).await
    }

    /// [`Self::migrate_with`] with the defaults: destructive migrations are refused.
    pub async fn migrate(&self) -> Result<(), MigrateError> {
        self.migrate_with(MigrateOptions::default()).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/destructive");

    async fn fixture_migrator() -> Migrator {
        Migrator::new(std::path::Path::new(FIXTURES))
            .await
            .expect("fixture migrations")
    }

    async fn storage() -> SqliteStorage {
        SqliteStorage::connect("sqlite::memory:")
            .await
            .expect("connect")
    }

    async fn tables(s: &SqliteStorage) -> Vec<String> {
        sqlx::query_scalar(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
              ORDER BY name",
        )
        .fetch_all(&s.writer)
        .await
        .expect("list tables")
    }

    #[test]
    fn only_destructive_named_migrations_are_destructive() {
        let m = |v, d: &str| PendingMigration {
            version: v,
            description: d.to_owned(),
        };
        assert!(m(2, "destructive drop x").is_destructive());
        assert!(m(2, "destructive").is_destructive());
        assert!(!m(2, "destructiveness").is_destructive());
        assert!(!m(2, "release 0 2").is_destructive());
        assert!(!m(2, "drop destructive x").is_destructive());
        assert_eq!(
            m(2, "destructive drop x").to_string(),
            "0002 destructive drop x"
        );
    }

    #[tokio::test]
    async fn migrate_refuses_pending_destructive_migration_and_changes_nothing() {
        let s = storage().await;
        let migrator = fixture_migrator().await;
        let mut conn = s.writer.acquire().await.expect("acquire");
        let err = run_guarded(&migrator, &mut conn, MigrateOptions::default())
            .await
            .expect_err("a destructive migration must be refused");
        drop(conn);
        match &err {
            MigrateError::Destructive(list) => {
                assert_eq!(list.len(), 1);
                assert_eq!(list[0].to_string(), "0002 destructive drop x");
            }
            other => panic!("unexpected error: {other}"),
        }
        assert!(err.to_string().contains("0002 destructive drop x"), "{err}");
        // Not even the harmless 0001 ran, and no bookkeeping table was created.
        assert!(tables(&s).await.is_empty(), "{:?}", tables(&s).await);
    }

    #[tokio::test]
    async fn migrate_applies_destructive_migration_when_allowed() {
        let s = storage().await;
        let migrator = fixture_migrator().await;
        let mut conn = s.writer.acquire().await.expect("acquire");
        run_guarded(
            &migrator,
            &mut conn,
            MigrateOptions {
                allow_destructive: true,
            },
        )
        .await
        .expect("allowed");
        let pending = pending(&migrator, &mut conn).await.expect("pending");
        drop(conn);
        assert!(pending.is_empty(), "{pending:?}");
        assert_eq!(tables(&s).await, ["_sqlx_migrations", "kept"]);
    }

    #[tokio::test]
    async fn migrate_does_not_block_on_already_applied_destructive_migration() {
        let s = storage().await;
        let migrator = fixture_migrator().await;
        let mut conn = s.writer.acquire().await.expect("acquire");
        run_guarded(
            &migrator,
            &mut conn,
            MigrateOptions {
                allow_destructive: true,
            },
        )
        .await
        .expect("allowed");
        // A later start without the flag: the destructive migration is history, not pending.
        run_guarded(&migrator, &mut conn, MigrateOptions::default())
            .await
            .expect("already applied destructive migrations never block");
    }

    #[tokio::test]
    async fn migrate_with_nothing_pending_is_a_no_op() {
        let s = storage().await;
        s.migrate().await.expect("embedded migrations apply");
        let before = tables(&s).await;
        let mut conn = s.writer.acquire().await.expect("acquire");
        let pending = pending(&sqlx::migrate!(), &mut conn)
            .await
            .expect("pending");
        drop(conn);
        assert!(pending.is_empty(), "{pending:?}");
        s.migrate().await.expect("second run is a no-op");
        assert_eq!(tables(&s).await, before);
    }

    #[tokio::test]
    async fn migrate_embedded_migrations_are_not_destructive() {
        let s = storage().await;
        let mut conn = s.writer.acquire().await.expect("acquire");
        let pending = pending(&sqlx::migrate!(), &mut conn)
            .await
            .expect("pending");
        assert!(!pending.is_empty());
        assert!(destructive(&pending).is_empty(), "{pending:?}");
    }
}
