//! HTTP listeners: plain `axum::serve`, or the built-in TLS listener (rustls with the aws-lc-rs
//! provider, ALPN h2 and http/1.1). Both shut down gracefully when the shutdown channel flips.
//! Both give every request its TCP peer address as `ConnectInfo<SocketAddr>` (the client-IP
//! extractor of anvil-web requires it).

use std::net::SocketAddr;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use anyhow::{Context, bail};
use axum::Router;
use axum::extract::ConnectInfo;
use axum::http::Request;
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
use tower::Service;

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
        None => axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(wait_for_shutdown(shutdown))
        .await
        .context("server error"),
        Some(config) => run_tls(listener, app, TlsAcceptor::from(config), shutdown).await,
    }
}

/// Serves only `GET /metrics` (plain HTTP) on the separate metrics listener until shutdown.
pub async fn run_metrics(
    listener: TcpListener,
    endpoint: anvil_web::observability::MetricsEndpoint,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    axum::serve(
        listener,
        anvil_web::observability::metrics_router(endpoint).into_make_service(),
    )
    .with_graceful_shutdown(wait_for_shutdown(shutdown))
    .await
    .context("metrics server error")
}

/// The router of one connection: inserts the connection's peer address into every request.
#[derive(Clone)]
struct WithPeer {
    app: Router,
    peer: SocketAddr,
}

impl<B> Service<Request<B>> for WithPeer
where
    Router: Service<Request<B>>,
{
    type Response = <Router as Service<Request<B>>>::Response;
    type Error = <Router as Service<Request<B>>>::Error;
    type Future = <Router as Service<Request<B>>>::Future;

    fn poll_ready(&mut self, cx: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
        Service::<Request<B>>::poll_ready(&mut self.app, cx)
    }

    fn call(&mut self, mut req: Request<B>) -> Self::Future {
        req.extensions_mut().insert(ConnectInfo(self.peer));
        self.app.call(req)
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
        let service = TowerToHyperService::new(WithPeer {
            app: app.clone(),
            peer,
        });
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::routing::get;
    use tower::ServiceExt as _;

    async fn peer_of(ConnectInfo(peer): ConnectInfo<SocketAddr>) -> String {
        peer.ip().to_string()
    }

    fn peer_router() -> Router {
        Router::new().route("/peer", get(peer_of))
    }

    #[tokio::test]
    async fn tls_connection_service_inserts_the_peer_address() {
        let peer = SocketAddr::from(([198, 51, 100, 7], 4711));
        let resp = WithPeer {
            app: peer_router(),
            peer,
        }
        .oneshot(Request::get("/peer").body(Body::empty()).expect("request"))
        .await
        .expect("infallible");
        assert_eq!(resp.status(), 200);
        let body = axum::body::to_bytes(resp.into_body(), 1024)
            .await
            .expect("body");
        assert_eq!(&body[..], b"198.51.100.7");
    }

    #[tokio::test]
    async fn plain_listener_provides_the_peer_address() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (tx, rx) = watch::channel(false);
        let server = tokio::spawn(run(listener, peer_router(), None, rx));
        let body = reqwest::get(format!("http://{addr}/peer"))
            .await
            .expect("request")
            .error_for_status()
            .expect("handler got ConnectInfo")
            .text()
            .await
            .expect("body");
        assert_eq!(body, "127.0.0.1");
        tx.send(true).expect("shutdown");
        server.await.expect("join").expect("clean shutdown");
    }
}
