//! Background jobs (ARCHITECTURE.md §14): the expired-row purge and the outbox worker. Both
//! stop when the shutdown channel flips. The worker always runs: tenants with their own SMTP
//! settings get mail even when the installation SMTP (`smtp_url`) is not configured.

use std::sync::Arc;
use std::time::Duration;

use anvil_core::ports::{Clock, Storage};
use anvil_jose::Kek;
use anvil_mail::worker::SmtpTransportFactory;
use anvil_mail::{EmailRenderer, MailTransport, OutboxWorker, SmtpTransport, StorageOutbox};
use anyhow::Context;
use secrecy::ExposeSecret;
use tokio::sync::watch;
use tokio::task::JoinSet;

use crate::config::Config;
use crate::server::wait_for_shutdown;

/// Interval of the expired-row purge.
pub const PURGE_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// Starts the background jobs. Must run inside the Tokio runtime (the SMTP connection pool
/// spawns its maintenance task on construction).
pub fn spawn(
    cfg: &Config,
    storage: &Arc<dyn Storage>,
    clock: &Arc<dyn Clock>,
    kek: &Arc<Kek>,
    shutdown: &watch::Receiver<bool>,
) -> anyhow::Result<JoinSet<()>> {
    let mut jobs = JoinSet::new();
    jobs.spawn(purge_loop(
        Arc::clone(storage),
        Arc::clone(clock),
        shutdown.clone(),
    ));

    let transport: Option<Arc<dyn MailTransport>> = match &cfg.smtp_url {
        Some(url) => Some(Arc::new(
            SmtpTransport::from_url(url.expose_secret(), &cfg.smtp_from).context("smtp_url")?,
        )),
        None => {
            tracing::warn!(
                "installation SMTP is not configured (smtp_url): only tenants with their own SMTP \
                 settings can receive mail; other emails fail and are retried with backoff"
            );
            None
        }
    };
    let renderer = match &cfg.theme_dir {
        Some(dir) => EmailRenderer::with_theme_dir(dir),
        None => EmailRenderer::embedded(),
    };
    let worker = OutboxWorker {
        source: Arc::new(StorageOutbox(Arc::clone(storage))),
        transport,
        transports: Arc::new(SmtpTransportFactory::new(Arc::clone(kek))),
        renderer,
        clock: Arc::clone(clock),
        from: cfg.smtp_from.clone(),
        kek: Arc::clone(kek),
    };
    tracing::info!("outbox worker started");
    jobs.spawn(worker.run(wait_for_shutdown(shutdown.clone())));
    Ok(jobs)
}

async fn purge_loop(
    storage: Arc<dyn Storage>,
    clock: Arc<dyn Clock>,
    shutdown: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(PURGE_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let stop = wait_for_shutdown(shutdown);
    tokio::pin!(stop);
    loop {
        tokio::select! {
            () = &mut stop => break,
            _ = interval.tick() => {}
        }
        match storage.purge_expired(clock.now()).await {
            Ok(0) => {}
            Ok(n) => tracing::info!(rows = n, "purged expired rows"),
            Err(e) => tracing::warn!(error = %e, "purge of expired rows failed"),
        }
    }
}
