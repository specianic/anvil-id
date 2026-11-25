//! Server startup: data directory, serve lock and KEK → storage → production adapters →
//! bootstrap (first start prints the one-time setup URL) → the full router.

use std::sync::Arc;

use anvil_core::clock::SystemClock;
use anvil_core::policy::PasswordPolicy;
use anvil_core::ports::{Clock, PasswordHasher, Storage};
use anvil_core::service::bootstrap::{BootstrapService, InstallResult};
use anvil_jose::Kek;
use anvil_web::adapters::{Argon2Pool, breach_checker};
use anvil_web::{AppConfig, AppDeps};
use anyhow::Context;
use axum::Router;
use secrecy::{ExposeSecret, SecretString};

use crate::config::{Config, LogFormat};
use crate::datadir::{self, KekOrigin, OnMissing, ServeLock};
use crate::storage::{self, Backend};

/// Everything `serve` runs on after startup.
pub struct Started {
    pub app: Router,
    pub storage: Arc<dyn Storage>,
    pub clock: Arc<dyn Clock>,
    /// The one KEK shared by the web layer (flows, users, keys) and the outbox worker. A second
    /// KEK would make every outbox payload undecryptable.
    pub kek: Arc<Kek>,
    /// Held for the server's lifetime (SQLite only).
    pub lock: Option<ServeLock>,
}

/// Data directory, serve lock and KEK, in that order: the lock is taken before a KEK could be
/// generated, so two concurrent first starts cannot write two KEKs.
pub fn prepare_data_dir(
    cfg: &Config,
    backend: Backend,
) -> anyhow::Result<(Option<ServeLock>, Kek)> {
    let (lock, on_missing) = match backend {
        Backend::Sqlite => {
            datadir::ensure_dir(&cfg.data_dir)?;
            (Some(datadir::lock(&cfg.data_dir)?), OnMissing::Generate)
        }
        // Postgres: no data directory is needed (the KEK comes from the environment or an
        // existing file), and several nodes may share the database.
        Backend::Postgres => (None, OnMissing::RefuseSharedDatabase),
    };
    let (kek, origin) = datadir::load_kek(cfg.kek.as_ref(), &cfg.kek_file, on_missing)?;
    match origin {
        KekOrigin::Configured => tracing::info!("using the configured KEK"),
        KekOrigin::File(path) => tracing::info!(path = %path.display(), "using the KEK file"),
        KekOrigin::Generated(path) => tracing::warn!(
            path = %path.display(),
            "generated a new KEK; back up {}: losing it makes signing keys unrecoverable",
            path.display()
        ),
    }
    Ok((lock, kek))
}

/// Argon2 concurrency: one hashing slot per available CPU.
fn argon2_permits() -> usize {
    std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
}

/// Runs startup up to (not including) binding the listener.
pub async fn start(cfg: &Config) -> anyhow::Result<Started> {
    let url = cfg.database_url.expose_secret();
    let backend = Backend::from_url(url)?;
    let (lock, kek) = prepare_data_dir(cfg, backend)?;
    let kek = Arc::new(kek);
    let storage = storage::open_storage(url, cfg.migrate).await?;
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let hasher: Arc<dyn PasswordHasher> = Arc::new(Argon2Pool::new(
        Argon2Pool::owasp_params(),
        argon2_permits(),
    )?);
    let policy = PasswordPolicy::default();

    let bootstrap = BootstrapService {
        storage: Arc::clone(&storage),
        clock: Arc::clone(&clock),
        kek: Arc::clone(&kek),
        hasher: Arc::clone(&hasher),
        policy,
        public_url: cfg.public_url.clone(),
    };
    match bootstrap
        .ensure_installed()
        .await
        .context("failed to install")?
    {
        InstallResult::Installed { setup_url } => announce_setup_url(&setup_url, cfg.log_format),
        InstallResult::AlreadyInstalled => tracing::info!("installation found"),
    }

    // `AppConfig::new` supplies defaults for the fields not set here (trusted proxies: loopback
    // in development mode, none otherwise; mapped from operator config in 03-24).
    let mut app_config = AppConfig::new(cfg.public_url.clone());
    app_config.theme_dir = cfg.theme_dir.clone();
    app_config.password_policy = policy;
    app_config.insecure_http = cfg.insecure_http;
    let deps = AppDeps {
        storage: Arc::clone(&storage),
        clock: Arc::clone(&clock),
        hasher,
        breach: breach_checker(cfg.breach_check.clone()),
        kek: Arc::clone(&kek),
    };
    let app = anvil_web::app(app_config, deps).context("failed to build the application")?;
    Ok(Started {
        app,
        storage,
        clock,
        kek,
        lock,
    })
}

/// The one deliberate place a setup token is logged: the operator needs it to create the first
/// administrator. With JSON logs it is also printed as a plain line on stdout, so scripts can
/// grep `Setup URL:` from either stream.
fn announce_setup_url(url: &SecretString, format: LogFormat) {
    tracing::info!("installed; open the setup URL within 1 hour to create the first administrator");
    tracing::info!("Setup URL: {}", url.expose_secret());
    if format == LogFormat::Json {
        println!("Setup URL: {}", url.expose_secret());
    }
}
