//! The `anvilid` binary: CLI entry point and wiring of concrete adapters.

use std::net::SocketAddr;

use anvil_web::WebConfig;
use anyhow::{Context, bail};
use clap::{Args, Parser, Subcommand};
use tracing_subscriber::EnvFilter;

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
    /// Run the HTTP server.
    Serve(ServeArgs),
}

#[derive(Debug, Args)]
struct ServeArgs {
    /// Socket address to listen on.
    #[arg(long, env = "ANVILID_LISTEN", default_value = "127.0.0.1:9090")]
    listen: SocketAddr,

    /// Public issuer URL; endpoint URLs in the discovery document are derived from it.
    #[arg(long, env = "ANVILID_ISSUER")]
    issuer: url::Url,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    init_tracing();
    match cli.cmd {
        Command::Serve(args) => serve(args),
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    if std::env::var("ANVILID_LOG_FORMAT").is_ok_and(|v| v.eq_ignore_ascii_case("json")) {
        builder.json().init();
    } else {
        builder.init();
    }
}

fn validate_issuer(issuer: &url::Url) -> anyhow::Result<()> {
    if issuer.query().is_some() || issuer.fragment().is_some() {
        bail!("issuer must not contain a query or fragment: {issuer}");
    }
    if !matches!(issuer.scheme(), "http" | "https") {
        bail!("issuer must use http or https: {issuer}");
    }
    Ok(())
}

#[tokio::main(flavor = "multi_thread")]
async fn serve(args: ServeArgs) -> anyhow::Result<()> {
    validate_issuer(&args.issuer)?;

    let listener = tokio::net::TcpListener::bind(args.listen)
        .await
        .with_context(|| format!("failed to bind {}", args.listen))?;
    let addr = listener
        .local_addr()
        .context("failed to read local address")?;
    tracing::info!(issuer = %args.issuer, "listening on {addr}");

    let app = anvil_web::router(WebConfig {
        issuer: args.issuer,
    });
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

    #[test]
    fn rejects_issuer_with_query_or_fragment() {
        for bad in [
            "https://example.test/?a=b",
            "https://example.test/#frag",
            "ftp://example.test/",
        ] {
            let url: url::Url = bad.parse().expect("parses as url");
            assert!(validate_issuer(&url).is_err(), "{bad}");
        }
        for good in ["https://example.test", "http://127.0.0.1:9090/t/acme"] {
            let url: url::Url = good.parse().expect("parses as url");
            assert!(validate_issuer(&url).is_ok(), "{good}");
        }
    }
}
