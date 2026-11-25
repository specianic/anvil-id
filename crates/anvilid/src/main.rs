//! The `anvilid` binary: CLI entry point and wiring of concrete adapters.

mod config;
mod datadir;
mod jobs;
mod server;
mod startup;
mod storage;

use std::io::IsTerminal as _;
use std::sync::Arc;

use anvil_core::clock::SystemClock;
use anvil_core::policy::PasswordPolicy;
use anvil_core::service::bootstrap::BootstrapService;
use anvil_web::adapters::Argon2Pool;
use anyhow::Context;
use clap::{Parser, Subcommand};
use secrecy::ExposeSecret;
use tokio::sync::watch;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::Layer as _;
use tracing_subscriber::filter::{FilterExt as _, LevelFilter, Targets, filter_fn};
use tracing_subscriber::layer::{Context as LayerContext, SubscriberExt as _};
use tracing_subscriber::util::SubscriberInitExt as _;

use crate::config::{CliOverrides, Config, Layers, LogFormat};
use crate::storage::Backend;

/// Time background jobs get to finish their current batch after the server stopped.
const JOBS_SHUTDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

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
    }
}

fn load(args: &CliOverrides) -> anyhow::Result<Config> {
    Config::resolve(Layers::from_process(args)?.raw()?)
}

/// Tracing target of the audit stream (ADM-04).
const AUDIT_TARGET: &str = "audit";

/// The audit mirror of this binary: every recorded audit event becomes an `info` event on the
/// `audit` target, which [`AuditStdout`] prints.
struct TracingMirror;

impl anvil_core::ports::AuditMirror for TracingMirror {
    fn emit(&self, event_json: &str) {
        tracing::info!(target: AUDIT_TARGET, event = %event_json);
    }
}

/// Prints the `event` field of every `audit`-target event as one raw JSON line on stdout. The
/// JSON comes from `anvil_core::service::audit::event_json`, which holds only typed, secret-free
/// fields.
struct AuditStdout;

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for AuditStdout {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: LayerContext<'_, S>) {
        struct EventField(Option<String>);
        impl tracing::field::Visit for EventField {
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                if field.name() == "event" {
                    self.0 = Some(value.to_owned());
                }
            }
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "event" {
                    self.0 = Some(format!("{value:?}"));
                }
            }
        }
        if event.metadata().target() != AUDIT_TARGET {
            return;
        }
        let mut field = EventField(None);
        event.record(&mut field);
        if let Some(json) = field.0 {
            use std::io::Write as _;
            let mut out = std::io::stdout().lock();
            let _ = writeln!(out, "{json}");
            let _ = out.flush();
        }
    }
}

/// Logs go to stderr, filtered by `RUST_LOG` (default `info`). Audit events go to stdout as JSON
/// lines through a separate layer that is always enabled at `info` for the `audit` target,
/// independent of `RUST_LOG`, and are excluded from the stderr log. Stdout otherwise carries only
/// command output (`config show`, `admin setup-url`, `keys rotate`).
fn init_tracing(format: LogFormat) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let general = tracing_subscriber::fmt::layer().with_writer(std::io::stderr);
    let general = match format {
        LogFormat::Json => general.json().boxed(),
        LogFormat::Pretty => general.with_ansi(std::io::stderr().is_terminal()).boxed(),
    };
    let general = general.with_filter(filter.and(filter_fn(|meta| meta.target() != AUDIT_TARGET)));
    let audit =
        AuditStdout.with_filter(Targets::new().with_target(AUDIT_TARGET, LevelFilter::INFO));
    tracing_subscriber::registry()
        .with(general)
        .with(audit)
        .init();
    anvil_core::service::audit::install_mirror(Box::new(TracingMirror));
}

fn log_warnings(cfg: &Config) {
    for w in &cfg.warnings {
        tracing::warn!("{w}");
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn migrate(cfg: &Config) -> anyhow::Result<()> {
    init_tracing(cfg.log_format);
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
    )
    .await?;
    println!("migrations applied");
    Ok(())
}

#[tokio::main(flavor = "multi_thread")]
async fn setup_url(cfg: &Config) -> anyhow::Result<()> {
    init_tracing(cfg.log_format);
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
async fn serve(cfg: &Config) -> anyhow::Result<()> {
    init_tracing(cfg.log_format);
    log_warnings(cfg);
    // The development-mode warning is logged by the web layer (AppState::new).
    // Fail on a bad certificate before touching the data directory or the database.
    let tls = cfg.tls.as_ref().map(server::tls_config).transpose()?;

    let started = startup::start(cfg).await?;

    let listener = tokio::net::TcpListener::bind(cfg.listen)
        .await
        .with_context(|| format!("failed to bind {}", cfg.listen))?;
    let addr = listener
        .local_addr()
        .context("failed to read local address")?;

    let (stop_tx, stop_rx) = watch::channel(false);
    let stop_tx = Arc::new(stop_tx);
    let mut jobs = jobs::spawn(
        cfg,
        &started.storage,
        &started.clock,
        &started.kek,
        &stop_rx,
    )?;
    let signal_tx = Arc::clone(&stop_tx);
    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = signal_tx.send(true);
    });

    let scheme = if tls.is_some() { "https" } else { "http" };
    tracing::info!(public_url = %cfg.public_url, "listening on {scheme}://{addr}");
    let result = server::run(listener, started.app, tls, stop_rx).await;

    // The server stopped: make sure the jobs stop too (also when the server failed).
    let _ = stop_tx.send(true);
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
}
