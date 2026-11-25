//! Background jobs (ARCHITECTURE.md §14).
//!
//! - **Leased periodic jobs**: signing-key rotation (hourly), the expired-row purge (every
//!   5 minutes) and audit retention (daily, only when a retention is configured). Each run is
//!   wrapped in lease acquire → run → release through [`JobRepo`](anvil_core::ports::JobRepo):
//!   when several nodes share one Postgres database, at most one of them runs a given job at a
//!   time. Each process has a random node id. Intervals have a small random start delay
//!   (jitter) so nodes started together do not race for every lease.
//! - **The outbox worker** runs continuously on every node (rows are claimed individually). It
//!   always runs: tenants with their own SMTP settings get mail even when the installation SMTP
//!   (`smtp_url`) is not configured.
//!
//! Everything stops when the shutdown channel flips.
//!
//! This module depends only on library crates (no `crate::` items) so the integration tests can
//! include it directly.

use std::future::Future;
use std::hash::{BuildHasher as _, Hasher as _};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use anvil_core::model::JobName;
use anvil_core::ports::{Clock, Storage};
use anvil_core::service::key_rotation::{KeyRotationService, RotationPolicy};
use anvil_jose::Kek;
use anvil_mail::worker::SmtpTransportFactory;
use anvil_mail::{EmailRenderer, MailTransport, OutboxWorker, SmtpTransport, StorageOutbox};
use anyhow::Context;
use secrecy::{ExposeSecret, SecretString};
use tokio::sync::watch;
use tokio::task::JoinSet;

/// Interval of the expired-row purge.
pub const PURGE_INTERVAL: Duration = Duration::from_secs(5 * 60);
/// Interval of the key-rotation job.
pub const ROTATION_INTERVAL: Duration = Duration::from_secs(60 * 60);
/// Interval of the audit-retention job.
pub const AUDIT_RETENTION_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
/// How long a job lease is held at most. A node that dies mid-run blocks the job for at most
/// this long; a run that takes longer may overlap with another node's run (all jobs are
/// idempotent).
pub const JOB_LEASE: Duration = Duration::from_secs(15 * 60);
/// Upper bound of the random start delay of each periodic job.
const MAX_JITTER: Duration = Duration::from_secs(30);

/// How often each periodic job runs. Production uses [`JobIntervals::default`]; tests pass
/// shorter intervals to [`spawn_periodic`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JobIntervals {
    pub rotation: Duration,
    pub purge: Duration,
    pub audit_retention: Duration,
}

impl Default for JobIntervals {
    fn default() -> Self {
        Self {
            rotation: ROTATION_INTERVAL,
            purge: PURGE_INTERVAL,
            audit_retention: AUDIT_RETENTION_INTERVAL,
        }
    }
}

/// What the jobs need from the configuration.
pub struct JobsConfig {
    pub smtp_url: Option<SecretString>,
    pub smtp_from: String,
    pub theme_dir: Option<PathBuf>,
    pub rotation: RotationPolicy,
    /// `None` keeps audit events forever (no retention job).
    pub audit_retention: Option<time::Duration>,
}

/// A periodic job. `run` logs its own failures (a failed run is retried at the next interval).
pub trait PeriodicJob: Send + Sync + 'static {
    /// The lease name (see [`JobName`]).
    fn name(&self) -> &'static str;
    fn run(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}

/// Runs jobs under their lease for one node.
pub struct LeaseRunner {
    pub storage: Arc<dyn Storage>,
    pub clock: Arc<dyn Clock>,
    /// Lease owner; unique per process.
    pub node_id: String,
    pub lease: Duration,
}

impl LeaseRunner {
    /// A runner with a random node id and the production lease length.
    pub fn new(storage: Arc<dyn Storage>, clock: Arc<dyn Clock>) -> Self {
        Self {
            storage,
            clock,
            node_id: format!("node-{}", uuid::Uuid::now_v7().simple()),
            lease: JOB_LEASE,
        }
    }

    /// Runs `job` once if this node gets its lease, then releases the lease. Returns whether
    /// the job ran.
    pub async fn run_once(&self, job: &dyn PeriodicJob) -> bool {
        let now = self.clock.now();
        let lease = time::Duration::try_from(self.lease).unwrap_or(time::Duration::MINUTE);
        match self
            .storage
            .jobs()
            .try_lease(job.name(), &self.node_id, now + lease, now)
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                tracing::debug!(job = job.name(), "job lease held by another node");
                return false;
            }
            Err(e) => {
                tracing::warn!(job = job.name(), error = %e, "failed to take the job lease");
                return false;
            }
        }
        job.run().await;
        if let Err(e) = self.storage.jobs().release(job.name(), &self.node_id).await {
            // The lease expires on its own.
            tracing::warn!(job = job.name(), error = %e, "failed to release the job lease");
        }
        true
    }

    /// Runs `job` every `interval` (first run after a random delay of up to a tenth of the
    /// interval, at most 30 s) until shutdown.
    pub async fn schedule(
        self: Arc<Self>,
        job: Arc<dyn PeriodicJob>,
        interval: Duration,
        shutdown: watch::Receiver<bool>,
    ) {
        let stop = stopped(shutdown);
        tokio::pin!(stop);
        tokio::select! {
            () = &mut stop => return,
            () = tokio::time::sleep(jitter(interval)) => {}
        }
        let mut ticks = tokio::time::interval(interval);
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                () = &mut stop => break,
                _ = ticks.tick() => {}
            }
            // A run in progress finishes its batch; shutdown waits for it (bounded in main).
            self.run_once(job.as_ref()).await;
        }
    }
}

/// A random delay in `[0, min(interval / 10, 30 s))`.
fn jitter(interval: Duration) -> Duration {
    let max = (interval / 10).min(MAX_JITTER);
    let nanos = u64::try_from(max.as_nanos()).unwrap_or(u64::MAX);
    if nanos == 0 {
        return Duration::ZERO;
    }
    let random = std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish();
    Duration::from_nanos(random % nanos)
}

async fn stopped(mut rx: watch::Receiver<bool>) {
    let _ = rx.wait_for(|stop| *stop).await;
}

/// Scheduled signing-key rotation (SEC-02).
pub struct RotationJob(pub KeyRotationService);

impl PeriodicJob for RotationJob {
    fn name(&self) -> &'static str {
        JobName::KEY_ROTATION
    }

    fn run(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            match self.0.run_once().await {
                Ok(report) => {
                    for (tenant, error) in &report.failures {
                        tracing::error!(%tenant, %error, "key rotation failed for tenant");
                    }
                    if report.generated + report.promoted > 0 || report.deleted > 0 {
                        tracing::info!(
                            tenants = report.tenants,
                            generated = report.generated,
                            promoted = report.promoted,
                            deleted = report.deleted,
                            "key rotation ran"
                        );
                    }
                }
                Err(e) => tracing::error!(error = %e, "key rotation failed"),
            }
        })
    }
}

/// Batch deletion of expired rows.
pub struct PurgeJob {
    pub storage: Arc<dyn Storage>,
    pub clock: Arc<dyn Clock>,
}

impl PeriodicJob for PurgeJob {
    fn name(&self) -> &'static str {
        JobName::PURGE_EXPIRED
    }

    fn run(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            match self.storage.purge_expired(self.clock.now()).await {
                Ok(0) => {}
                Ok(n) => tracing::info!(rows = n, "purged expired rows"),
                Err(e) => tracing::warn!(error = %e, "purge of expired rows failed"),
            }
        })
    }
}

/// Deletes audit events older than the retention (installation-wide).
pub struct AuditRetentionJob {
    pub storage: Arc<dyn Storage>,
    pub clock: Arc<dyn Clock>,
    pub retention: time::Duration,
}

impl PeriodicJob for AuditRetentionJob {
    fn name(&self) -> &'static str {
        JobName::AUDIT_RETENTION
    }

    fn run(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            let cutoff = self.clock.now() - self.retention;
            match self.storage.audit().purge_before(cutoff).await {
                Ok(0) => {}
                Ok(n) => tracing::info!(rows = n, "purged audit events past retention"),
                Err(e) => tracing::warn!(error = %e, "audit retention purge failed"),
            }
        })
    }
}

/// Spawns the leased periodic jobs on `runner` into `jobs`.
pub fn spawn_periodic(
    jobs: &mut JoinSet<()>,
    runner: &Arc<LeaseRunner>,
    kek: &Arc<Kek>,
    rotation: RotationPolicy,
    audit_retention: Option<time::Duration>,
    intervals: JobIntervals,
    shutdown: &watch::Receiver<bool>,
) {
    let storage = &runner.storage;
    let clock = &runner.clock;
    let rotation: Arc<dyn PeriodicJob> = Arc::new(RotationJob(KeyRotationService {
        storage: Arc::clone(storage),
        kek: Arc::clone(kek),
        clock: Arc::clone(clock),
        policy: rotation,
    }));
    jobs.spawn(Arc::clone(runner).schedule(rotation, intervals.rotation, shutdown.clone()));
    let purge: Arc<dyn PeriodicJob> = Arc::new(PurgeJob {
        storage: Arc::clone(storage),
        clock: Arc::clone(clock),
    });
    jobs.spawn(Arc::clone(runner).schedule(purge, intervals.purge, shutdown.clone()));
    match audit_retention {
        Some(retention) => {
            let job: Arc<dyn PeriodicJob> = Arc::new(AuditRetentionJob {
                storage: Arc::clone(storage),
                clock: Arc::clone(clock),
                retention,
            });
            jobs.spawn(Arc::clone(runner).schedule(
                job,
                intervals.audit_retention,
                shutdown.clone(),
            ));
        }
        None => tracing::info!("audit retention is 0: audit events are kept forever"),
    }
}

/// Starts the background jobs. Must run inside the Tokio runtime (the SMTP connection pool
/// spawns its maintenance task on construction).
pub fn spawn(
    cfg: &JobsConfig,
    storage: &Arc<dyn Storage>,
    clock: &Arc<dyn Clock>,
    kek: &Arc<Kek>,
    shutdown: &watch::Receiver<bool>,
) -> anyhow::Result<JoinSet<()>> {
    let mut jobs = JoinSet::new();
    let runner = Arc::new(LeaseRunner::new(Arc::clone(storage), Arc::clone(clock)));
    tracing::info!(node = %runner.node_id, "background jobs started");
    spawn_periodic(
        &mut jobs,
        &runner,
        kek,
        cfg.rotation,
        cfg.audit_retention,
        JobIntervals::default(),
        shutdown,
    );

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
    jobs.spawn(worker.run(stopped(shutdown.clone())));
    Ok(jobs)
}
