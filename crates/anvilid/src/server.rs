//! HTTP listeners: plain `axum::serve`, or the built-in TLS listener (rustls with the aws-lc-rs
//! provider, ALPN h2 and http/1.1). Both shut down gracefully when the shutdown channel flips.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use axum::Router;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use hyper_util::service::TowerToHyperService;
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;

use crate::config::TlsFiles;

/// Time allowed for a TLS handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Time open TLS connections get to finish after shutdown starts.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

/// Resolves when the shutdown channel is set (or its sender is gone).
pub async fn wait_for_shutdown(mut rx: watch::Receiver<bool>) {
    let _ = rx.wait_for(|stop| *stop).await;
}

/// Loads the certificate chain and private key into a rustls server configuration.
pub fn tls_config(files: &TlsFiles) -> anyhow::Result<Arc<ServerConfig>> {
    let certs = CertificateDer::pem_file_iter(&files.cert)
        .with_context(|| format!("failed to read TLS certificate {}", files.cert.display()))?
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("invalid TLS certificate {}", files.cert.display()))?;
    if certs.is_empty() {
        bail!("no certificate found in {}", files.cert.display());
    }
    let key = PrivateKeyDer::from_pem_file(&files.key)
        .with_context(|| format!("failed to read TLS private key {}", files.key.display()))?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("TLS protocol configuration")?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("TLS certificate and key do not form a usable pair")?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// Serves `app` on `listener` until shutdown.
pub async fn run(
    listener: TcpListener,
    app: Router,
    tls: Option<Arc<ServerConfig>>,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    match tls {
        None => axum::serve(listener, app)
            .with_graceful_shutdown(wait_for_shutdown(shutdown))
            .await
            .context("server error"),
        Some(config) => run_tls(listener, app, TlsAcceptor::from(config), shutdown).await,
    }
}

async fn run_tls(
    listener: TcpListener,
    app: Router,
    acceptor: TlsAcceptor,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let mut connections = JoinSet::new();
    let stop = wait_for_shutdown(shutdown.clone());
    tokio::pin!(stop);
    loop {
        let (stream, peer) = tokio::select! {
            () = &mut stop => break,
            accepted = listener.accept() => match accepted {
                Ok(conn) => conn,
                Err(e) => {
                    // Transient (for example EMFILE): back off briefly instead of spinning.
                    tracing::warn!(error = %e, "accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
        };
        // Reap finished connection tasks so the set does not grow without bound.
        while connections.try_join_next().is_some() {}
        let acceptor = acceptor.clone();
        let service = TowerToHyperService::new(app.clone());
        let conn_shutdown = shutdown.clone();
        connections.spawn(async move {
            let tls = match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                Ok(Ok(tls)) => tls,
                Ok(Err(e)) => {
                    tracing::debug!(%peer, error = %e, "TLS handshake failed");
                    return;
                }
                Err(_) => {
                    tracing::debug!(%peer, "TLS handshake timed out");
                    return;
                }
            };
            let builder = auto::Builder::new(TokioExecutor::new());
            let conn = builder.serve_connection_with_upgrades(TokioIo::new(tls), service);
            tokio::pin!(conn);
            tokio::select! {
                res = conn.as_mut() => {
                    if let Err(e) = res {
                        tracing::debug!(%peer, error = %e, "connection error");
                    }
                }
                () = wait_for_shutdown(conn_shutdown) => {
                    conn.as_mut().graceful_shutdown();
                    if let Err(e) = conn.await {
                        tracing::debug!(%peer, error = %e, "connection error during shutdown");
                    }
                }
            }
        });
    }
    drop(listener);
    let drain = async { while connections.join_next().await.is_some() {} };
    if tokio::time::timeout(DRAIN_TIMEOUT, drain).await.is_err() {
        tracing::warn!("open connections did not finish in time; closing them");
        connections.abort_all();
    }
    Ok(())
}
