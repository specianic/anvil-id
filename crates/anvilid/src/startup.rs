//! Server startup: data directory, serve lock and KEK → storage → production adapters →
//! bootstrap (first start prints the one-time setup URL) → reconciliation (console client,
//! signing keys for every tenant's enabled algorithms) → the full router.

use std::sync::Arc;

use anvil_core::clock::SystemClock;
use anvil_core::model::PageRequest;
use anvil_core::policy::PasswordPolicy;
use anvil_core::ports::{Clock, PasswordHasher, Storage};
use anvil_core::service::bootstrap::{BootstrapService, InstallResult};
use anvil_core::service::key_rotation::KeyRotationService;
use anvil_jose::Kek;
use anvil_web::adapters::backchannel::LogoutDeliveryWorker;
use anvil_web::adapters::{Argon2Pool, OutboundClient, breach_checker_with};
use anvil_web::observability::{MetricsEndpoint, TraceContextHook};
use anvil_web::{AppConfig, AppDeps, AppState};
use anyhow::{Context, bail};
use axum::Router;
use secrecy::{ExposeSecret, SecretString};

use crate::config::{Config, LogFormat};
use crate::datadir::{self, KekOrigin, OnMissing, ServeLock};
use crate::jobs::BackgroundWorker;
use crate::limiter;
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
    /// The application state behind `app` (readiness is cleared on it at shutdown).
    pub state: AppState,
    /// Continuous workers spawned on every node by `jobs::spawn_workers`: the back-channel
    /// logout worker (wired to `AppState::logout_wake` and the state's outbound client), and
    /// later workers pushed here.
    pub workers: Vec<Box<dyn BackgroundWorker>>,
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

/// Opens storage (no migrations) and the KEK for a CLI command that runs next to a running
/// server (`admin setup-url`, `keys rotate`): no serve lock is taken, nothing is installed, and
/// a missing database or KEK is an error.
pub async fn open_for_cli(cfg: &Config) -> anyhow::Result<(Arc<dyn Storage>, Kek)> {
    let url = cfg.database_url.expose_secret();
    if Backend::from_url(url)? == Backend::Sqlite {
        match storage::sqlite_file(url) {
            Some(file) if !file.exists() => bail!(
                "database {} does not exist; start `anvilid serve` once to install",
                file.display()
            ),
            Some(_) => {}
            None => bail!("an in-memory database cannot be reached from another process"),
        }
    }
    let (kek, _) = datadir::load_kek(
        cfg.kek.as_ref(),
        &cfg.kek_file,
        OnMissing::RefuseNotInstalled,
    )?;
    // No migrations and no serve.lock: this runs next to a running server (Pitfall P10).
    let storage =
        storage::open_storage(url, storage::Migrations::Skip, cfg.database_max_connections).await?;
    Ok((storage, kek))
}

/// Tenants are reconciled in pages of this size.
const TENANT_PAGE: u32 = 100;

/// Generates an active signing key for every enabled algorithm of every tenant that has none.
/// A tenant that fails is logged and does not stop the others or the start.
pub async fn ensure_signing_keys(rotation: &KeyRotationService) -> anyhow::Result<u32> {
    let mut generated = 0;
    let mut after = None;
    loop {
        let page = rotation
            .storage
            .tenants()
            .list(PageRequest {
                after,
                limit: TENANT_PAGE,
            })
            .await
            .context("failed to list tenants")?;
        for tenant in &page.items {
            match rotation.ensure_tenant(tenant).await {
                Ok(n) => generated += n,
                Err(e) => tracing::error!(
                    tenant = %tenant.slug,
                    error = %e,
                    "failed to ensure signing keys"
                ),
            }
        }
        match page.next_cursor {
            Some(c) => after = Some(c),
            None => break,
        }
    }
    Ok(generated)
}

/// Argon2 concurrency: one hashing slot per available CPU.
fn argon2_permits() -> usize {
    std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
}

/// What telemetry hands to the web layer.
#[derive(Default)]
pub struct Observability {
    /// The installed exporter's renderer (when metrics are exposed); the main router serves it
    /// only with `metrics_on_main_port`.
    pub metrics: Option<MetricsEndpoint>,
    /// Continues trusted proxies' trace context (when traces are exported).
    pub trace_context: Option<TraceContextHook>,
}

/// Runs startup up to (not including) binding the listener.
pub async fn start(cfg: &Config, observability: Observability) -> anyhow::Result<Started> {
    let url = cfg.database_url.expose_secret();
    let backend = Backend::from_url(url)?;
    let (lock, kek) = prepare_data_dir(cfg, backend)?;
    let kek = Arc::new(kek);
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    // The one limiter construction site; an unsupported backend fails before the database opens.
    let limiter = limiter::build_limiter(cfg, Arc::clone(&clock), &kek).await?;
    let storage =
        storage::open_storage(url, cfg.migrations(), cfg.database_max_connections).await?;
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
    // The console client follows the public URL (created or updated, audited).
    bootstrap
        .ensure_console_client(&cfg.public_url)
        .await
        .context("failed to reconcile the console client")?;
    let rotation = KeyRotationService {
        storage: Arc::clone(&storage),
        kek: Arc::clone(&kek),
        clock: Arc::clone(&clock),
        policy: cfg.rotation,
    };
    let generated = ensure_signing_keys(&rotation).await?;
    if generated > 0 {
        tracing::info!(keys = generated, "generated missing signing keys");
    }

    // `AppConfig::new` supplies defaults for the fields not set here.
    let mut app_config = AppConfig::new(cfg.public_url.clone());
    app_config.theme_dir = cfg.theme_dir.clone();
    app_config.password_policy = policy;
    app_config.insecure_http = cfg.insecure_http;
    app_config.installation_smtp = cfg.smtp_url.is_some();
    app_config.trusted_proxies = cfg.trusted_proxies.clone();
    app_config.rate_limits = cfg.rate_limits.clone();
    app_config.metrics = observability.metrics.filter(|_| cfg.metrics_on_main_port);
    app_config.trace_context = observability.trace_context;
    // Outbound (SSRF guard): an explicit allow-list replaces the dev-mode loopback default;
    // plain http (to allow-listed destinations only) follows development mode, including
    // `insecure_http` setups.
    if let Some(cidrs) = &cfg.outbound_allow_cidrs {
        app_config.outbound.allow_cidrs = cidrs.clone();
    }
    app_config.outbound.extra_ca_pem = cfg.outbound_ca_pem.clone();
    app_config.outbound.allow_http = app_config.dev_mode();
    let outbound = Arc::new(
        OutboundClient::new(&app_config.outbound)
            .context("failed to build the outbound HTTP client")?,
    );
    let deps = AppDeps {
        storage: Arc::clone(&storage),
        clock: Arc::clone(&clock),
        hasher,
        breach: breach_checker_with(cfg.breach_check.clone(), outbound),
        kek: Arc::clone(&kek),
    };
    let public_url = app_config.public_url.clone();
    let state = AppState::new_with_limiter(app_config, deps, limiter)
        .context("failed to build the application")?;
    // Logouts wake the worker through the state's Notify; deliveries go through the state's
    // outbound client (no second client).
    let logout_worker = LogoutDeliveryWorker::new(
        Arc::clone(&storage),
        Arc::clone(&clock),
        Arc::clone(&kek),
        public_url,
        state.outbound_arc(),
        state.logout_wake(),
    );
    let workers: Vec<Box<dyn BackgroundWorker>> = vec![Box::new(logout_worker)];
    let app = anvil_web::router(state.clone());
    Ok(Started {
        app,
        storage,
        clock,
        kek,
        lock,
        state,
        workers,
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
