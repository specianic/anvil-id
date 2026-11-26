//! The `anvilid` binary: CLI entry point and wiring of concrete adapters.

mod backup;
mod config;
mod datadir;
mod healthcheck;
mod jobs;
mod keys;
mod limiter;
mod recover;
mod server;
mod startup;
mod storage;
mod telemetry;
mod tenant_config;
mod users_export;
mod users_import;

use std::sync::Arc;

use anvil_core::clock::SystemClock;
use anvil_core::model::WEBHOOK_TIMEOUT;
use anvil_core::policy::PasswordPolicy;
use anvil_core::service::bootstrap::BootstrapService;
use anvil_web::adapters::Argon2Pool;
use anyhow::Context;
use clap::{Parser, Subcommand};
use secrecy::ExposeSecret;
use tokio::sync::watch;

use crate::config::{CliOverrides, Config, Layers};
use crate::storage::Backend;

/// Slack on top of [`WEBHOOK_TIMEOUT`] for the jobs to record the outcome of their last request.
const JOBS_SHUTDOWN_MARGIN: std::time::Duration = std::time::Duration::from_secs(5);

/// Time background jobs get to finish their current batch after the server stopped: long enough
/// for an in-flight webhook request (bounded by [`WEBHOOK_TIMEOUT`]) to finish. Derived, so a
/// change of `WEBHOOK_TIMEOUT` follows. Delivery stays at-least-once regardless: an interrupted
/// row is re-claimed when its lease expires and re-sent with the same `webhook-id`.
const JOBS_SHUTDOWN_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(WEBHOOK_TIMEOUT.as_secs() + JOBS_SHUTDOWN_MARGIN.as_secs());

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[derive(Debug, Parser)]
#[command(name = "anvilid", version, about = "AnvilID identity provider")]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the server (installs on first start and prints a one-time setup URL).
    Serve(CliOverrides),
    /// Apply database migrations and exit.
    Migrate(CliOverrides),
    /// Inspect the configuration.
    Config {
        #[command(subcommand)]
        cmd: ConfigCommand,
    },
    /// Administrative commands.
    Admin {
        #[command(subcommand)]
        cmd: AdminCommand,
    },
    /// Signing-key commands.
    Keys {
        #[command(subcommand)]
        cmd: KeysCommand,
    },
    /// SQLite backup and restore (Postgres: see docs/OPERATIONS.md#postgres).
    Backup {
        #[command(subcommand)]
        cmd: BackupCommand,
    },
    /// Declarative tenant configuration as YAML: export, plan and apply (secret references
    /// `{env: NAME}` / `{file: path}` are resolved locally). Applies are audited.
    Tenant {
        #[command(subcommand)]
        cmd: TenantCommand,
    },
    /// Probe the local server's readiness (exit 0 ready, 1 not ready, 2 usage error); loopback
    /// only, for container health checks.
    Healthcheck(healthcheck::HealthcheckArgs),
    /// Bulk user import and export (NDJSON) through the same services as the management API.
    /// Audited.
    Users {
        #[command(subcommand)]
        cmd: UsersCommand,
    },
}

#[derive(Debug, Subcommand)]
enum UsersCommand {
    /// Import users from an NDJSON file into a tenant.
    Import(users_import::ImportArgs),
    /// Export a tenant's users, one user, or one user's GDPR bundle.
    Export(users_export::ExportArgs),
}

#[derive(Debug, Subcommand)]
enum TenantCommand {
    /// Write a tenant's configuration as a YAML document (secrets are never exported).
    Export(tenant_config::ExportArgs),
    /// Validate a YAML document and print the plan against the stored state (changes nothing).
    Plan(tenant_config::PlanArgs),
    /// Print the plan, then apply it (confirmation or --yes; deletions only with --prune).
    Apply(tenant_config::ApplyArgs),
}

#[derive(Debug, Subcommand)]
enum BackupCommand {
    /// Write a consistent copy of the SQLite database while the server runs. The KEK is not
    /// included: keep it separately.
    Create(backup::CreateArgs),
    /// Replace the SQLite database with a backup (the server must be stopped).
    Restore(backup::RestoreArgs),
}

#[derive(Debug, Subcommand)]
enum KeysCommand {
    /// Rotate a tenant's signing key: prepublish a next key, or with --immediate replace the
    /// active key at once (compromise). Audited.
    Rotate(keys::RotateArgs),
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Print the effective configuration with the source of each value (secrets redacted).
    Show(CliOverrides),
    /// Validate the configuration; exits non-zero if it is invalid.
    Validate(CliOverrides),
}

#[derive(Debug, Subcommand)]
enum AdminCommand {
    /// Print a new one-time setup URL (valid 1 h) for creating the first administrator.
    SetupUrl(CliOverrides),
    /// Recover administrator access from a shell on the host (no network equivalent): a
    /// one-time password-reset URL for --email, or a new-administrator setup URL when no
    /// administrator is left. Audited.
    Recover(recover::RecoverArgs),
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Command::Serve(args) => serve(&load(&args)?),
        Command::Migrate(args) => migrate(&load(&args)?),
        Command::Config {
            cmd: ConfigCommand::Show(args),
        } => {
            let layers = Layers::from_process(&args)?;
            let raw = layers.raw()?;
            print!("{}", config::show(&layers, &raw));
            Ok(())
        }
        Command::Config {
            cmd: ConfigCommand::Validate(args),
        } => {
            let cfg = load(&args)?;
            for w in &cfg.warnings {
                eprintln!("warning: {w}");
            }
            println!("configuration is valid");
            Ok(())
        }
        Command::Admin {
            cmd: AdminCommand::SetupUrl(args),
        } => setup_url(&load(&args)?),
        Command::Keys {
            cmd: KeysCommand::Rotate(args),
        } => keys_rotate(&load(&args.config)?, &args),
        Command::Backup {
            cmd: BackupCommand::Create(args),
        } => backup_create(&load(&args.config)?, &args),
        Command::Backup {
            cmd: BackupCommand::Restore(args),
        } => backup_restore(&load(&args.config)?, &args),
        Command::Admin {
            cmd: AdminCommand::Recover(args),
        } => admin_recover(&load(&args.config)?, &args),
        Command::Tenant {
            cmd: TenantCommand::Export(args),
        } => tenant_export(&load(&args.config)?, &args),
        Command::Tenant {
            cmd: TenantCommand::Plan(args),
        } => tenant_plan(&load(&args.config)?, &args),
        Command::Tenant {
            cmd: TenantCommand::Apply(args),
        } => tenant_apply(&load(&args.config)?, &args),
        Command::Users {
            cmd: UsersCommand::Import(args),
        } => users_import(&load(&args.config)?, &args),
        Command::Users {
            cmd: UsersCommand::Export(args),
        } => users_export(&load(&args.config)?, &args),
        Command::Healthcheck(args) => {
            let target = match &args.url {
                Some(url) => healthcheck::target_from_url(url),
                None => load(&args.config)
                    .map_err(|e| format!("{e:#}"))
                    .and_then(|cfg| {
                        if cfg.tls.is_some() {
                            Err(
                                "the server listens with TLS and the healthcheck speaks plain \
                                 HTTP; pass --url for a plain-HTTP loopback listener"
                                    .to_owned(),
                            )
                        } else {
                            healthcheck::target_from_listen(cfg.listen)
                        }
                    }),
            };
            std::process::exit(healthcheck::run(target));
        }
    }
}

fn load(args: &CliOverrides) -> anyhow::Result<Config> {
    Config::resolve(Layers::from_process(args)?.raw()?)
}

fn log_warnings(cfg: &Config) {
    for w in &cfg.warnings {
        tracing::warn!("{w}");
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn migrate(cfg: &Config) -> anyhow::Result<()> {
    let _telemetry = telemetry::init_tracing(cfg.log_format, None)?;
    let url = cfg.database_url.expose_secret();
    if Backend::from_url(url)? == Backend::Sqlite
        && let Some(parent) = storage::sqlite_file(url)
            .as_deref()
            .and_then(std::path::Path::parent)
            .filter(|p| !p.as_os_str().is_empty())
    {
        datadir::ensure_dir(parent)?;
    }
    storage::open_storage(
        url,
        storage::Migrations::Run {
            allow_destructive: cfg.allow_destructive_migrations,
        },
        cfg.database_max_connections,
    )
    .await?;
    println!("migrations applied");
    Ok(())
}

#[tokio::main(flavor = "multi_thread")]
async fn setup_url(cfg: &Config) -> anyhow::Result<()> {
    let _telemetry = telemetry::init_tracing(cfg.log_format, None)?;
    let (storage, kek) = startup::open_for_cli(cfg).await?;
    let bootstrap = BootstrapService {
        storage,
        clock: Arc::new(SystemClock),
        kek: Arc::new(kek),
        hasher: Arc::new(Argon2Pool::new(Argon2Pool::owasp_params(), 1)?),
        policy: PasswordPolicy::default(),
        public_url: cfg.public_url.clone(),
    };
    let url = bootstrap
        .new_setup_url()
        .await
        .context("failed to create a setup URL")?;
    println!("Setup URL: {}", url.expose_secret());
    Ok(())
}

#[tokio::main(flavor = "multi_thread")]
async fn keys_rotate(cfg: &Config, args: &keys::RotateArgs) -> anyhow::Result<()> {
    let _telemetry = telemetry::init_tracing(cfg.log_format, None)?;
    keys::rotate(cfg, args).await
}

#[tokio::main(flavor = "multi_thread")]
async fn admin_recover(cfg: &Config, args: &recover::RecoverArgs) -> anyhow::Result<()> {
    let _telemetry = telemetry::init_tracing(cfg.log_format, None)?;
    recover::recover(cfg, args).await
}

#[tokio::main(flavor = "multi_thread")]
async fn tenant_export(cfg: &Config, args: &tenant_config::ExportArgs) -> anyhow::Result<()> {
    let _telemetry = telemetry::init_tracing(cfg.log_format, None)?;
    tenant_config::export(cfg, args).await
}

#[tokio::main(flavor = "multi_thread")]
async fn users_import(cfg: &Config, args: &users_import::ImportArgs) -> anyhow::Result<()> {
    let _telemetry = telemetry::init_tracing(cfg.log_format, None)?;
    users_import::run(cfg, args).await
}

#[tokio::main(flavor = "multi_thread")]
async fn users_export(cfg: &Config, args: &users_export::ExportArgs) -> anyhow::Result<()> {
    let _telemetry = telemetry::init_tracing(cfg.log_format, None)?;
    users_export::run(cfg, args).await
}

#[tokio::main(flavor = "multi_thread")]
async fn tenant_plan(cfg: &Config, args: &tenant_config::PlanArgs) -> anyhow::Result<()> {
    let _telemetry = telemetry::init_tracing(cfg.log_format, None)?;
    tenant_config::plan(cfg, args).await
}

#[tokio::main(flavor = "multi_thread")]
async fn tenant_apply(cfg: &Config, args: &tenant_config::ApplyArgs) -> anyhow::Result<()> {
    let _telemetry = telemetry::init_tracing(cfg.log_format, None)?;
    tenant_config::apply(cfg, args).await
}

#[tokio::main(flavor = "multi_thread")]
async fn backup_create(cfg: &Config, args: &backup::CreateArgs) -> anyhow::Result<()> {
    let _telemetry = telemetry::init_tracing(cfg.log_format, None)?;
    backup::create(cfg, args).await
}

#[tokio::main(flavor = "multi_thread")]
async fn backup_restore(cfg: &Config, args: &backup::RestoreArgs) -> anyhow::Result<()> {
    let _telemetry = telemetry::init_tracing(cfg.log_format, None)?;
    backup::restore(cfg, args).await
}

#[tokio::main(flavor = "multi_thread")]
async fn serve(cfg: &Config) -> anyhow::Result<()> {
    let telemetry =
        telemetry::init_tracing(cfg.log_format, telemetry::OtelConfig::from_config(cfg))?;
    log_warnings(cfg);
    // The development-mode warning is logged by the web layer (AppState::new).
    // Fail on a bad certificate before touching the data directory or the database.
    let tls = cfg.tls.as_ref().map(server::tls_config).transpose()?;

    // The process-wide recorder exists only when metrics are exposed.
    let metrics = if cfg.metrics_listen.is_some() || cfg.metrics_on_main_port {
        Some(telemetry::install_metrics()?)
    } else {
        None
    };
    let started = startup::start(
        cfg,
        startup::Observability {
            metrics: metrics.clone().map(telemetry::endpoint),
            trace_context: telemetry.trace_context_hook(),
        },
    )
    .await?;

    let listener = tokio::net::TcpListener::bind(cfg.listen)
        .await
        .with_context(|| format!("failed to bind {}", cfg.listen))?;
    let addr = listener
        .local_addr()
        .context("failed to read local address")?;

    let (stop_tx, stop_rx) = watch::channel(false);
    let stop_tx = Arc::new(stop_tx);
    let jobs_config = jobs::JobsConfig {
        smtp_url: cfg.smtp_url.clone(),
        smtp_from: cfg.smtp_from.clone(),
        theme_dir: cfg.theme_dir.clone(),
        rotation: cfg.rotation,
        audit_retention: cfg.audit_retention,
        domain_txt: started.state.domain_txt_arc(),
    };
    let mut jobs = jobs::spawn(
        &jobs_config,
        &started.storage,
        &started.clock,
        &started.kek,
        &stop_rx,
    )?;
    jobs::spawn_workers(&mut jobs, started.workers, &stop_rx);
    let mut metrics_server = None;
    if let Some(handle) = &metrics {
        jobs.spawn(telemetry::upkeep(handle.clone(), stop_rx.clone()));
        if let Some(metrics_addr) = cfg.metrics_listen {
            let metrics_listener = tokio::net::TcpListener::bind(metrics_addr)
                .await
                .with_context(|| format!("failed to bind metrics_listen {metrics_addr}"))?;
            let bound = metrics_listener
                .local_addr()
                .context("failed to read the metrics address")?;
            tracing::info!("metrics on http://{bound}/metrics");
            metrics_server = Some(tokio::spawn(server::run_metrics(
                metrics_listener,
                telemetry::endpoint(handle.clone()),
                stop_rx.clone(),
            )));
        }
    }
    let signal_tx = Arc::clone(&stop_tx);
    let state = started.state.clone();
    let drain = cfg.shutdown_drain;
    tokio::spawn(async move {
        shutdown_signal().await;
        // Readiness turns 503 first so load balancers stop routing here; requests keep being
        // served during the drain, then the graceful shutdown starts.
        state.set_ready(false);
        if !drain.is_zero() {
            tracing::info!(
                drain_ms = u64::try_from(drain.as_millis()).unwrap_or(u64::MAX),
                "readiness is 503; draining before shutdown"
            );
            tokio::time::sleep(drain).await;
        }
        let _ = signal_tx.send(true);
    });

    let scheme = if tls.is_some() { "https" } else { "http" };
    tracing::info!(public_url = %cfg.public_url, "listening on {scheme}://{addr}");
    let result = server::run(listener, started.app, tls, stop_rx).await;

    // The server stopped: make sure the jobs and the metrics listener stop too (also when the
    // server failed).
    let _ = stop_tx.send(true);
    if let Some(task) = metrics_server {
        match task.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::warn!(error = %e, "metrics listener failed"),
            Err(e) => tracing::warn!(error = %e, "metrics listener task failed"),
        }
    }
    let jobs_done = async { while jobs.join_next().await.is_some() {} };
    if tokio::time::timeout(JOBS_SHUTDOWN_TIMEOUT, jobs_done)
        .await
        .is_err()
    {
        tracing::warn!("background jobs did not stop in time");
    }
    drop(started.lock);
    result?;
    tracing::info!("shut down cleanly");
    // Flush pending spans (blocking HTTP export) off the async workers.
    if let Err(e) = tokio::task::spawn_blocking(move || telemetry.shutdown()).await {
        tracing::warn!(error = %e, "trace flush task failed");
    }
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(err) = tokio::signal::ctrl_c().await {
            tracing::error!(%err, "failed to listen for ctrl-c");
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(err) => {
                tracing::error!(%err, "failed to listen for SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => tracing::info!("received ctrl-c, shutting down"),
        () = terminate => tracing::info!("received SIGTERM, shutting down"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_is_well_formed() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }

    #[test]
    fn jobs_shutdown_timeout_covers_a_webhook_request() {
        assert!(JOBS_SHUTDOWN_TIMEOUT >= WEBHOOK_TIMEOUT + std::time::Duration::from_secs(5));
        assert_eq!(JOBS_SHUTDOWN_TIMEOUT, std::time::Duration::from_secs(20));
    }
}
