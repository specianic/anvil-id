//! The `anvilid` binary: CLI entry point and wiring of concrete adapters.

mod config;
mod datadir;
mod storage;

use std::io::IsTerminal as _;
use std::sync::Arc;

use anvil_core::clock::SystemClock;
use anvil_core::policy::PasswordPolicy;
use anvil_core::service::bootstrap::BootstrapService;
use anvil_web::adapters::Argon2Pool;
use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use secrecy::ExposeSecret;
use tracing_subscriber::EnvFilter;

use crate::config::{CliOverrides, Config, Layers, LogFormat};
use crate::datadir::{KekOrigin, OnMissing};
use crate::storage::Backend;

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

/// Logs go to stderr, so stdout carries only command output (`config show`, `admin setup-url`).
fn init_tracing(format: LogFormat) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr);
    match format {
        LogFormat::Json => builder.json().init(),
        LogFormat::Pretty => builder.with_ansi(std::io::stderr().is_terminal()).init(),
    }
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
    storage::open_storage(url, true).await?;
    println!("migrations applied");
    Ok(())
}

#[tokio::main(flavor = "multi_thread")]
async fn setup_url(cfg: &Config) -> anyhow::Result<()> {
    init_tracing(cfg.log_format);
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
    let storage = storage::open_storage(url, false).await?;
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

/// Data directory, serve lock and KEK, in that order: the lock is taken before a KEK could be
/// generated, so two concurrent first starts cannot write two KEKs.
fn prepare_data_dir(
    cfg: &Config,
    backend: Backend,
) -> anyhow::Result<(Option<datadir::ServeLock>, anvil_jose::Kek)> {
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

#[tokio::main(flavor = "multi_thread")]
async fn serve(cfg: &Config) -> anyhow::Result<()> {
    init_tracing(cfg.log_format);
    log_warnings(cfg);
    let url = cfg.database_url.expose_secret();
    let backend = Backend::from_url(url)?;
    let (_lock, _kek) = prepare_data_dir(cfg, backend)?;
    // Held for the server's lifetime; the next task passes it into the web state.
    let _storage = storage::open_storage(url, cfg.migrate).await?;

    let listener = tokio::net::TcpListener::bind(cfg.listen)
        .await
        .with_context(|| format!("failed to bind {}", cfg.listen))?;
    let addr = listener
        .local_addr()
        .context("failed to read local address")?;
    tracing::info!(public_url = %cfg.public_url, "listening on {addr}");

    let issuer: url::Url = cfg
        .public_url
        .as_str()
        .parse()
        .context("public_url is not a valid URL")?;
    let app = anvil_web::router(anvil_web::WebConfig { issuer });
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server error")?;

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
