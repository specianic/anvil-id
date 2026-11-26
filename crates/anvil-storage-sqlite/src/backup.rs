//! Online backups of a SQLite database file (OPS-07).
//!
//! [`backup_into`] runs `VACUUM INTO` on its own connection to the live database. SQLite builds
//! the copy inside one read transaction, so the result is a transactionally consistent snapshot
//! even while a server keeps writing (WAL mode: readers never block the writer). [`inspect`] opens
//! a backup file read-only and reports its integrity and the newest applied migration, which the
//! binary compares with [`latest_migration_version`] before a restore.
//!
//! This module only runs SQL; choosing temporary names, fsync and renames is the caller's job.

use std::path::Path;
use std::str::FromStr as _;
use std::time::Duration;

use sqlx::sqlite::SqliteConnectOptions;
use sqlx::{ConnectOptions as _, Connection as _, SqliteConnection};

/// What a backup file contains, read back from the file itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupManifest {
    /// Version of the newest successfully applied migration (`_sqlx_migrations`).
    pub migration_version: i64,
    /// Number of tenants (a cheap sanity figure for operators).
    pub tenants: i64,
}

/// Why a backup could not be written or read.
#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    /// The file is not an SQLite database, or is truncated or damaged.
    #[error("not a usable AnvilID SQLite database: {0}")]
    Corrupt(String),
    /// `PRAGMA integrity_check` found problems (first message only).
    #[error("integrity check failed: {0}")]
    Integrity(String),
    /// The file is an SQLite database but has no AnvilID migrations.
    #[error("not an AnvilID database (no applied migrations)")]
    NotAnvil,
    /// The backup was written by a newer binary (more migrations than this one knows).
    #[error(
        "made by a newer AnvilID (migration version {found} > {supported} supported by this \
         binary); upgrade anvilid first"
    )]
    TooNew { found: i64, supported: i64 },
    /// The destination already exists (`VACUUM INTO` never overwrites).
    #[error("destination {0} already exists")]
    DestinationExists(String),
    #[error("sqlite: {0}")]
    Sqlite(#[from] sqlx::Error),
}

/// Version of the newest migration embedded in this binary.
pub fn latest_migration_version() -> i64 {
    sqlx::migrate!()
        .iter()
        .filter(|m| !m.migration_type.is_down_migration())
        .map(|m| m.version)
        .max()
        .unwrap_or(0)
}

/// Writes a consistent copy of the database at `source_url` (a `sqlite:` file URL) to `dest`
/// with `VACUUM INTO`, then verifies the copy with [`inspect`]. `dest` must not exist. The source
/// is opened on a dedicated connection (never created), so this works next to a running server.
pub async fn backup_into(source_url: &str, dest: &Path) -> Result<BackupManifest, BackupError> {
    if dest.exists() {
        return Err(BackupError::DestinationExists(dest.display().to_string()));
    }
    let dest_str = dest
        .to_str()
        .ok_or_else(|| BackupError::Corrupt("destination path is not valid UTF-8".to_owned()))?;
    let mut conn = SqliteConnectOptions::from_str(source_url)?
        .create_if_missing(false)
        .busy_timeout(Duration::from_secs(30))
        .connect()
        .await?;
    // One statement, one read transaction: a point-in-time snapshot of the whole database.
    let vacuum = sqlx::query("VACUUM INTO ?1")
        .bind(dest_str)
        .execute(&mut conn)
        .await;
    conn.close().await?;
    vacuum?;
    inspect(dest).await
}

/// Opens `path` read-only and checks it: `PRAGMA integrity_check` must answer `ok`, and the
/// newest applied migration is read from `_sqlx_migrations`. Truncated or foreign files are
/// [`BackupError::Corrupt`] / [`BackupError::NotAnvil`].
pub async fn inspect(path: &Path) -> Result<BackupManifest, BackupError> {
    if !path.is_file() {
        return Err(BackupError::Corrupt(format!(
            "{} is not a file",
            path.display()
        )));
    }
    let mut conn = SqliteConnectOptions::new()
        .filename(path)
        .read_only(true)
        .create_if_missing(false)
        .connect()
        .await
        .map_err(|e| BackupError::Corrupt(e.to_string()))?;
    let result = inspect_conn(&mut conn).await;
    let _ = conn.close().await;
    result
}

/// [`inspect`] plus the restore rule: a backup whose newest migration is newer than
/// [`latest_migration_version`] is [`BackupError::TooNew`] (this binary could not run on it). An
/// older backup is fine: `serve` migrates it on start.
pub async fn inspect_for_restore(path: &Path) -> Result<BackupManifest, BackupError> {
    let manifest = inspect(path).await?;
    let supported = latest_migration_version();
    if manifest.migration_version > supported {
        return Err(BackupError::TooNew {
            found: manifest.migration_version,
            supported,
        });
    }
    Ok(manifest)
}

async fn inspect_conn(conn: &mut SqliteConnection) -> Result<BackupManifest, BackupError> {
    let rows: Vec<String> = sqlx::query_scalar("PRAGMA integrity_check")
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| BackupError::Corrupt(e.to_string()))?;
    match rows.first().map(String::as_str) {
        Some("ok") if rows.len() == 1 => {}
        Some(first) => return Err(BackupError::Integrity(first.to_owned())),
        None => return Err(BackupError::Integrity("no result".to_owned())),
    }
    let has_table: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = '_sqlx_migrations'",
    )
    .fetch_one(&mut *conn)
    .await?;
    if has_table == 0 {
        return Err(BackupError::NotAnvil);
    }
    let version: Option<i64> =
        sqlx::query_scalar("SELECT max(version) FROM _sqlx_migrations WHERE success = 1")
            .fetch_one(&mut *conn)
            .await?;
    let migration_version = version.ok_or(BackupError::NotAnvil)?;
    let tenants: i64 = sqlx::query_scalar("SELECT count(*) FROM tenant")
        .fetch_one(&mut *conn)
        .await
        .map_err(|_| BackupError::NotAnvil)?;
    Ok(BackupManifest {
        migration_version,
        tenants,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SqliteStorage;

    async fn migrated(dir: &Path) -> (String, SqliteStorage) {
        let url = format!("sqlite://{}?mode=rwc", dir.join("live.db").display());
        let storage = SqliteStorage::connect(&url).await.expect("connect");
        storage.migrate().await.expect("migrate");
        (url, storage)
    }

    #[tokio::test]
    async fn backup_of_a_migrated_database_reports_the_latest_version() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (url, _storage) = migrated(dir.path()).await;
        let dest = dir.path().join("copy.db");
        let manifest = backup_into(&url, &dest).await.expect("backup");
        assert_eq!(manifest.migration_version, latest_migration_version());
        assert_eq!(inspect(&dest).await.expect("inspect"), manifest);
    }

    #[tokio::test]
    async fn backup_refuses_an_existing_destination() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (url, _storage) = migrated(dir.path()).await;
        let dest = dir.path().join("copy.db");
        std::fs::write(&dest, b"keep me").expect("write");
        let err = backup_into(&url, &dest).await.expect_err("exists");
        assert!(matches!(err, BackupError::DestinationExists(_)), "{err}");
        assert_eq!(std::fs::read(&dest).expect("read"), b"keep me");
    }

    #[tokio::test]
    async fn backup_never_creates_a_missing_source() {
        let dir = tempfile::tempdir().expect("tempdir");
        let url = format!("sqlite://{}", dir.path().join("missing.db").display());
        backup_into(&url, &dir.path().join("copy.db"))
            .await
            .expect_err("missing source");
        assert!(!dir.path().join("missing.db").exists());
    }

    /// Writers commit two rows per transaction while backups run: every copy holds an even
    /// number of rows (a point in time), passes the integrity check and has the latest version.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn backup_while_writing_is_a_consistent_snapshot() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (url, storage) = migrated(dir.path()).await;
        // Test-only scratch table, written on the storage's own single writer.
        sqlx::query("CREATE TABLE backup_pairs (n INTEGER NOT NULL)")
            .execute(&storage.writer)
            .await
            .expect("scratch table");
        let writer = storage.writer.clone();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_w = stop.clone();
        let task = tokio::spawn(async move {
            let mut n = 0_i64;
            while !stop_w.load(std::sync::atomic::Ordering::Relaxed) {
                let mut tx = writer.begin().await.expect("begin");
                for _ in 0..2 {
                    sqlx::query("INSERT INTO backup_pairs (n) VALUES (?1)")
                        .bind(n)
                        .execute(&mut *tx)
                        .await
                        .expect("insert");
                    n += 1;
                }
                tx.commit().await.expect("commit");
            }
            n
        });
        let mut seen = Vec::new();
        for i in 0..5 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            let dest = dir.path().join(format!("copy-{i}.db"));
            let manifest = backup_into(&url, &dest).await.expect("backup");
            assert_eq!(manifest.migration_version, latest_migration_version());
            let mut conn = SqliteConnectOptions::new()
                .filename(&dest)
                .read_only(true)
                .connect()
                .await
                .expect("open copy");
            let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM backup_pairs")
                .fetch_one(&mut conn)
                .await
                .expect("count");
            conn.close().await.expect("close");
            assert_eq!(rows % 2, 0, "copy {i} holds half a transaction: {rows}");
            seen.push(rows);
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let written = task.await.expect("writer");
        assert!(written > 0, "the writer never ran");
        assert!(seen.windows(2).all(|w| w[0] <= w[1]), "{seen:?}");
    }

    #[tokio::test]
    async fn restore_inspection_refuses_a_backup_from_a_newer_binary() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (url, _storage) = migrated(dir.path()).await;
        let dest = dir.path().join("copy.db");
        backup_into(&url, &dest).await.expect("backup");
        assert_eq!(
            inspect_for_restore(&dest)
                .await
                .expect("current version")
                .migration_version,
            latest_migration_version()
        );

        // Pretend a newer binary applied one more migration to the backed-up database.
        let mut conn = SqliteConnectOptions::new()
            .filename(&dest)
            .connect()
            .await
            .expect("open copy");
        sqlx::query(
            "INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time)
             VALUES (?1, 'from the future', 1, x'00', 0)",
        )
        .bind(latest_migration_version() + 1)
        .execute(&mut conn)
        .await
        .expect("future migration row");
        conn.close().await.expect("close");

        let err = inspect_for_restore(&dest).await.expect_err("too new");
        assert!(
            matches!(err, BackupError::TooNew { found, supported }
                if found == supported + 1 && supported == latest_migration_version()),
            "{err}"
        );
        // Plain inspection still reads it (the rule is restore-specific).
        inspect(&dest).await.expect("inspect");
    }

    #[tokio::test]
    async fn inspect_rejects_truncated_and_foreign_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (url, _storage) = migrated(dir.path()).await;
        let good = dir.path().join("copy.db");
        backup_into(&url, &good).await.expect("backup");

        let bytes = std::fs::read(&good).expect("read");
        let truncated = dir.path().join("truncated.db");
        std::fs::write(&truncated, &bytes[..bytes.len() / 2]).expect("write");
        let err = inspect(&truncated).await.expect_err("truncated");
        assert!(
            matches!(err, BackupError::Corrupt(_) | BackupError::Integrity(_)),
            "{err}"
        );

        let garbage = dir.path().join("garbage.db");
        std::fs::write(&garbage, b"definitely not sqlite").expect("write");
        let err = inspect(&garbage).await.expect_err("garbage");
        assert!(matches!(err, BackupError::Corrupt(_)), "{err}");

        let empty_db = dir.path().join("empty.db");
        let conn = SqliteConnectOptions::new()
            .filename(&empty_db)
            .create_if_missing(true)
            .connect()
            .await
            .expect("create");
        conn.close().await.expect("close");
        let err = inspect(&empty_db).await.expect_err("no migrations");
        assert!(matches!(err, BackupError::NotAnvil), "{err}");

        let err = inspect(&dir.path().join("missing.db"))
            .await
            .expect_err("missing");
        assert!(matches!(err, BackupError::Corrupt(_)), "{err}");
    }
}
