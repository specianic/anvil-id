//! The data directory: creation (0700), the key-encryption key (KEK) file (0600) and the
//! `serve.lock` that keeps two servers off one SQLite database.

use std::fs::{File, TryLockError};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anvil_jose::Kek;
use anyhow::{Context, bail};
use secrecy::{ExposeSecret, SecretString};

/// Creates the data directory (and parents) if missing. New directories get mode 0700.
pub fn ensure_dir(path: &Path) -> anyhow::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder
        .create(path)
        .with_context(|| format!("failed to create data directory {}", path.display()))
}

/// Where the KEK came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KekOrigin {
    /// The `kek` setting (environment or config file).
    Configured,
    /// An existing KEK file.
    File(PathBuf),
    /// Generated now into the KEK file.
    Generated(PathBuf),
}

/// What to do when neither a configured KEK nor a KEK file exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnMissing {
    /// Generate one into the KEK file (single-node SQLite installations).
    Generate,
    /// Refuse: several nodes sharing one database would each generate a different KEK.
    RefuseSharedDatabase,
    /// Refuse: the caller only uses an existing installation.
    RefuseNotInstalled,
}

/// Resolves the KEK: the configured value, else the KEK file if it exists, else (if allowed) a new
/// KEK written to the KEK file with mode 0600.
pub fn load_kek(
    configured: Option<&SecretString>,
    kek_file: &Path,
    on_missing: OnMissing,
) -> anyhow::Result<(Kek, KekOrigin)> {
    if let Some(value) = configured {
        let kek = Kek::from_base64(value.expose_secret())
            .map_err(|_| anyhow::anyhow!("kek: must be 32 bytes, base64-encoded"))?;
        return Ok((kek, KekOrigin::Configured));
    }
    if kek_file.exists() {
        let contents = SecretString::from(
            std::fs::read_to_string(kek_file)
                .with_context(|| format!("failed to read KEK file {}", kek_file.display()))?,
        );
        let kek = Kek::from_base64(contents.expose_secret()).map_err(|_| {
            anyhow::anyhow!(
                "KEK file {} must hold 32 bytes, base64-encoded",
                kek_file.display()
            )
        })?;
        warn_if_readable_by_others(kek_file);
        return Ok((kek, KekOrigin::File(kek_file.to_owned())));
    }
    match on_missing {
        OnMissing::Generate => {
            let kek = Kek::generate();
            write_new_secret_file(kek_file, kek.to_base64().expose_secret())?;
            Ok((kek, KekOrigin::Generated(kek_file.to_owned())))
        }
        OnMissing::RefuseSharedDatabase => bail!(
            "no KEK configured: set ANVILID_KEK (32 random bytes, base64) or provide the KEK file \
             {}. A KEK is never generated for Postgres, because every node sharing the database \
             must use the same KEK",
            kek_file.display()
        ),
        OnMissing::RefuseNotInstalled => bail!(
            "no KEK found (ANVILID_KEK is unset and {} does not exist); start `anvilid serve` once \
             to install",
            kek_file.display()
        ),
    }
}

/// Writes `contents` to a new file (never overwrites) with mode 0600.
fn write_new_secret_file(path: &Path, contents: &str) -> anyhow::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(path)
        .with_context(|| format!("failed to create KEK file {}", path.display()))?;
    file.write_all(contents.as_bytes())
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all())
        .with_context(|| format!("failed to write KEK file {}", path.display()))
}

fn warn_if_readable_by_others(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if let Ok(meta) = std::fs::metadata(path)
            && meta.permissions().mode() & 0o077 != 0
        {
            tracing::warn!(
                path = %path.display(),
                "the KEK file is accessible by other users; restrict it with chmod 600"
            );
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// An exclusive lock on `{data_dir}/serve.lock`, held for the server's lifetime. The operating
/// system releases it when the process exits, however it exits.
#[derive(Debug)]
pub struct ServeLock {
    _file: File,
}

/// Takes the serve lock. A second `serve` on the same data directory fails with a clear error.
pub fn lock(data_dir: &Path) -> anyhow::Result<ServeLock> {
    let path = data_dir.join("serve.lock");
    let file = File::options()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    match file.try_lock() {
        Ok(()) => Ok(ServeLock { _file: file }),
        Err(TryLockError::WouldBlock) => bail!(
            "another `anvilid serve` is already running on the data directory {} ({} is locked)",
            data_dir.display(),
            path.display()
        ),
        Err(TryLockError::Error(e)) => {
            Err(e).with_context(|| format!("failed to lock {}", path.display()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_once_with_mode_0600_then_reloads() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("kek");
        let (k1, origin) = load_kek(None, &path, OnMissing::Generate).expect("generate");
        assert_eq!(origin, KekOrigin::Generated(path.clone()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).expect("meta").permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let (k2, origin) = load_kek(None, &path, OnMissing::Generate).expect("reload");
        assert_eq!(origin, KekOrigin::File(path.clone()));
        assert_eq!(
            k1.to_base64().expose_secret(),
            k2.to_base64().expose_secret()
        );
    }

    #[test]
    fn configured_kek_wins_and_is_validated() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("kek");
        let configured = Kek::generate().to_base64();
        let (_, origin) =
            load_kek(Some(&configured), &path, OnMissing::Generate).expect("configured");
        assert_eq!(origin, KekOrigin::Configured);
        assert!(!path.exists(), "a configured KEK must not create a file");

        let bad = SecretString::from("dG9vLXNob3J0");
        let err = load_kek(Some(&bad), &path, OnMissing::Generate)
            .expect_err("short")
            .to_string();
        assert!(err.contains("32 bytes"), "{err}");
        assert!(!err.contains("dG9vLXNob3J0"), "{err}");
    }

    #[test]
    fn refuses_to_generate_for_shared_databases() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("kek");
        let err = load_kek(None, &path, OnMissing::RefuseSharedDatabase)
            .expect_err("postgres without KEK")
            .to_string();
        assert!(err.contains("KEK"), "{err}");
        assert!(!path.exists());
        // An existing file is fine.
        load_kek(None, &path, OnMissing::Generate).expect("generate");
        load_kek(None, &path, OnMissing::RefuseSharedDatabase).expect("existing file");
    }

    #[test]
    fn rejects_corrupt_kek_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("kek");
        std::fs::write(&path, "not base64!").expect("write");
        assert!(load_kek(None, &path, OnMissing::Generate).is_err());
    }

    #[test]
    fn second_lock_on_same_dir_fails() {
        let dir = tempfile::tempdir().expect("tempdir");
        let first = lock(dir.path()).expect("first lock");
        let err = lock(dir.path()).expect_err("second lock").to_string();
        assert!(err.contains("already running"), "{err}");
        drop(first);
        lock(dir.path()).expect("lock after release");
    }

    #[test]
    fn creates_nested_data_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        let nested = dir.path().join("a").join("b");
        ensure_dir(&nested).expect("create");
        ensure_dir(&nested).expect("idempotent");
        assert!(nested.is_dir());
    }
}
