//! `anvilid backup create|restore` (OPS-07).
//!
//! - **create** runs next to a live server: the SQLite storage crate writes a `VACUUM INTO`
//!   snapshot to a temporary file in the destination directory, checks it (integrity, migration
//!   version), fsyncs it and renames it into place. The KEK is never part of a backup.
//! - **restore** is offline: it takes `serve.lock` (so it refuses while a server runs and no server
//!   can start during the restore), refuses corrupt files and backups from a newer binary, checks
//!   that the configured KEK opens the backup's signing keys, then replaces the database
//!   atomically (temporary copy, fsync, `-wal`/`-shm` removed, rename, directory fsync).
//!
//! Postgres has its own tooling (pg_dump, base backups and PITR); both commands refuse it with a
//! pointer to the documentation instead of pretending to back it up.
//!
//! No SQL lives here: `anvil_storage_sqlite::backup` runs it.

use std::fs::File;
use std::path::{Path, PathBuf};

use anvil_core::model::{PageRequest, SIGNING_KEY_PURPOSE, signing_key_aad};
use anvil_core::ports::Storage as _;
use anvil_jose::Kek;
use anvil_storage_sqlite::SqliteStorage;
use anvil_storage_sqlite::backup::{self as sqlite_backup, BackupManifest};
use anyhow::{Context, bail};
use secrecy::ExposeSecret;

use crate::config::{CliOverrides, Config};
use crate::datadir::{self, OnMissing};
use crate::storage::{self, Backend};

/// Where operators find the Postgres backup procedure.
pub const POSTGRES_DOCS: &str = "docs/OPERATIONS.md#postgres";

/// `backup create` arguments.
#[derive(Debug, clap::Args)]
pub struct CreateArgs {
    #[command(flatten)]
    pub config: CliOverrides,

    /// File to write the backup to (must not exist).
    #[arg(long, short, value_name = "FILE")]
    pub output: PathBuf,
}

/// `backup restore` arguments.
#[derive(Debug, clap::Args)]
pub struct RestoreArgs {
    #[command(flatten)]
    pub config: CliOverrides,

    /// Backup file written by `anvilid backup create`.
    #[arg(long, short, value_name = "FILE")]
    pub input: PathBuf,

    /// Replace an existing database without asking.
    #[arg(long)]
    pub yes: bool,
}

fn postgres_refusal(action: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "`anvilid backup {action}` supports SQLite only; back up Postgres with pg_dump/pg_restore \
         or base backups with point-in-time recovery, see {POSTGRES_DOCS}"
    )
}

/// The SQLite database file of `cfg`, or an error for Postgres and in-memory databases.
fn sqlite_db(cfg: &Config, action: &str) -> anyhow::Result<PathBuf> {
    let url = cfg.database_url.expose_secret();
    match Backend::from_url(url)? {
        Backend::Postgres => Err(postgres_refusal(action)),
        Backend::Sqlite => storage::sqlite_file(url)
            .context("an in-memory database cannot be backed up or restored"),
    }
}

/// A temporary name next to `target` (same directory, so the final rename is atomic).
fn temp_beside(target: &Path, tag: &str) -> anyhow::Result<PathBuf> {
    let name = target
        .file_name()
        .and_then(|n| n.to_str())
        .with_context(|| format!("{} has no usable file name", target.display()))?;
    Ok(target.with_file_name(format!(".{name}.{tag}-{}", uuid::Uuid::now_v7().simple())))
}

/// The directory holding `path` (`.` for a bare file name).
fn parent_dir(path: &Path) -> &Path {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    }
}

/// Backups and databases hold password hashes and sealed secrets: owner-only.
fn restrict(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to restrict permissions of {}", path.display()))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn fsync_file(path: &Path) -> anyhow::Result<()> {
    File::open(path)
        .and_then(|f| f.sync_all())
        .with_context(|| format!("failed to sync {}", path.display()))
}

fn fsync_dir(dir: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    File::open(dir)
        .and_then(|f| f.sync_all())
        .with_context(|| format!("failed to sync directory {}", dir.display()))?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

fn remove_if_exists(path: &Path) -> anyhow::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("failed to remove {}", path.display())),
    }
}

/// `{db}-wal` / `{db}-shm`.
fn sidecar(db: &Path, suffix: &str) -> PathBuf {
    let mut s = db.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

/// Removes a temporary file (and any SQLite sidecars) when dropped, unless disarmed.
struct TempGuard(Option<PathBuf>);

impl TempGuard {
    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for TempGuard {
    fn drop(&mut self) {
        if let Some(p) = self.0.take() {
            for path in [sidecar(&p, "-wal"), sidecar(&p, "-shm"), p] {
                let _ = std::fs::remove_file(path);
            }
        }
    }
}

/// `anvilid backup create --output FILE`.
pub async fn create(cfg: &Config, args: &CreateArgs) -> anyhow::Result<()> {
    let db = sqlite_db(cfg, "create")?;
    if !db.exists() {
        bail!(
            "database {} does not exist; start `anvilid serve` once to install",
            db.display()
        );
    }
    let output = &args.output;
    if output.exists() {
        bail!("{} already exists; choose a new file", output.display());
    }
    let dir = parent_dir(output);
    if !dir.is_dir() {
        bail!("directory {} does not exist", dir.display());
    }
    let tmp = temp_beside(output, "partial")?;
    let mut guard = TempGuard(Some(tmp.clone()));
    let manifest = sqlite_backup::backup_into(cfg.database_url.expose_secret(), &tmp)
        .await
        .context("backup failed")?;
    restrict(&tmp)?;
    fsync_file(&tmp)?;
    if output.exists() {
        bail!(
            "{} appeared during the backup; not overwriting it",
            output.display()
        );
    }
    std::fs::rename(&tmp, output)
        .with_context(|| format!("failed to move the backup to {}", output.display()))?;
    guard.disarm();
    fsync_dir(dir)?;

    println!(
        "backup written to {} (migration version {}, {} tenants)",
        output.display(),
        manifest.migration_version,
        manifest.tenants
    );
    eprintln!(
        "warning: the KEK is not included in the backup. Keep a copy of {} (or the ANVILID_KEK \
         value) in a separate safe place: without it the backup's signing keys and sealed \
         secrets cannot be decrypted",
        cfg.kek_file.display()
    );
    Ok(())
}

/// Checks that `kek` opens a signing key of the database at `path`. Returns `Ok(false)` when the
/// check could not run (no keys, or a schema this binary cannot read yet), `Err` when the KEK is
/// wrong.
async fn kek_opens_backup(path: &Path, kek: &Kek, kek_file: &Path) -> anyhow::Result<bool> {
    let url = format!("sqlite://{}", path.display());
    let storage = SqliteStorage::connect(&url)
        .await
        .context("failed to open the restored copy")?;
    let result = async {
        let tenants = storage
            .tenants()
            .list(PageRequest {
                after: None,
                limit: 100,
            })
            .await?;
        for tenant in &tenants.items {
            if let Some(key) = storage.keys().list(tenant.id).await?.into_iter().next() {
                return Ok::<_, anvil_core::ports::StorageError>(Some(
                    kek.open(
                        SIGNING_KEY_PURPOSE,
                        &signing_key_aad(key.id),
                        &key.private_key_enc,
                    )
                    .is_ok(),
                ));
            }
        }
        Ok(None)
    }
    .await;
    storage.close().await;
    match result {
        Ok(Some(true)) => Ok(true),
        Ok(Some(false)) => bail!(
            "the configured KEK cannot decrypt the backup's signing keys; restore the KEK that \
             was in use when the backup was made (ANVILID_KEK or {}) and retry",
            kek_file.display()
        ),
        Ok(None) => Ok(false),
        Err(e) => {
            tracing::debug!(error = %e, "KEK check could not read the backup");
            Ok(false)
        }
    }
}

/// `anvilid backup restore --input FILE [--yes]`.
pub async fn restore(cfg: &Config, args: &RestoreArgs) -> anyhow::Result<()> {
    let db = sqlite_db(cfg, "restore")?;
    let manifest: BackupManifest = sqlite_backup::inspect_for_restore(&args.input)
        .await
        .with_context(|| format!("refusing to restore {}", args.input.display()))?;
    let latest = sqlite_backup::latest_migration_version();

    // The serve lock: refuses while a server runs, and keeps one from starting mid-restore.
    datadir::ensure_dir(&cfg.data_dir)?;
    let _lock = datadir::lock(&cfg.data_dir)
        .context("refusing to restore while the server is running; stop `anvilid serve` first")?;
    let (kek, _) = datadir::load_kek(
        cfg.kek.as_ref(),
        &cfg.kek_file,
        OnMissing::RefuseNotInstalled,
    )
    .context("restore the KEK of the backed-up installation before the database")?;
    if db.exists() && !args.yes {
        bail!(
            "{} exists; re-run with --yes to replace it with the backup",
            db.display()
        );
    }

    let dir = parent_dir(&db).to_owned();
    if !dir.is_dir() {
        datadir::ensure_dir(&dir)?;
    }
    let tmp = temp_beside(&db, "restore")?;
    let mut guard = TempGuard(Some(tmp.clone()));
    std::fs::copy(&args.input, &tmp)
        .with_context(|| format!("failed to copy {}", args.input.display()))?;
    restrict(&tmp)?;
    let verified = kek_opens_backup(&tmp, &kek, &cfg.kek_file).await?;
    // Re-check the copy that is about to become the database.
    sqlite_backup::inspect_for_restore(&tmp)
        .await
        .context("the copied backup failed its integrity check")?;
    // Every connection to the copy is closed (the KEK check's writer closed last and
    // checkpointed); drop the empty sidecars SQLite left beside it.
    remove_if_exists(&sidecar(&tmp, "-wal"))?;
    remove_if_exists(&sidecar(&tmp, "-shm"))?;
    fsync_file(&tmp)?;

    // The old database's WAL must not be replayed onto the restored file.
    remove_if_exists(&sidecar(&db, "-wal"))?;
    remove_if_exists(&sidecar(&db, "-shm"))?;
    std::fs::rename(&tmp, &db)
        .with_context(|| format!("failed to move the restored database to {}", db.display()))?;
    guard.disarm();
    fsync_dir(&dir)?;

    if !verified {
        eprintln!(
            "warning: could not verify the KEK against the backup (no signing keys readable by \
             this version); make sure the KEK matches the backed-up installation"
        );
    }
    let note = if manifest.migration_version < latest {
        "; `anvilid serve` applies the newer migrations on start"
    } else {
        ""
    };
    println!(
        "restored {} into {} (migration version {}, {} tenants){note}",
        args.input.display(),
        db.display(),
        manifest.migration_version,
        manifest.tenants
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn temp_names_stay_in_the_target_directory() {
        let t = temp_beside(Path::new("/srv/backups/anvil.db"), "partial").expect("temp");
        assert_eq!(t.parent(), Some(Path::new("/srv/backups")));
        let name = t.file_name().and_then(|n| n.to_str()).expect("name");
        assert!(name.starts_with(".anvil.db.partial-"), "{name}");
        assert_eq!(parent_dir(Path::new("x.db")), Path::new("."));
    }

    #[test]
    fn sidecars_append_the_suffix() {
        assert_eq!(
            sidecar(Path::new("/d/anvilid.db"), "-wal"),
            PathBuf::from("/d/anvilid.db-wal")
        );
    }

    #[test]
    fn postgres_refusal_points_to_the_docs() {
        let msg = postgres_refusal("create").to_string();
        assert!(msg.contains(POSTGRES_DOCS), "{msg}");
        assert!(msg.contains("pg_dump"), "{msg}");
    }
}
