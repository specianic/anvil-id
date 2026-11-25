//! Leased background jobs on SQLite: two runners sharing one storage never run the same job
//! concurrently, a held lease blocks other nodes, and the production jobs (rotation, purge,
//! audit retention) do their work when scheduled with short intervals.

#[path = "../src/jobs.rs"]
#[allow(dead_code, reason = "the test uses only part of the module")]
mod jobs;

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anvil_core::clock::{Clock, SystemClock};
use anvil_core::model::{
    AuditAction, AuditActor, AuditDetails, AuditOutcome, AuditQuery, NewTenant, RequestContext,
    TenantId, TenantSettings,
};
use anvil_core::ports::Storage;
use anvil_core::service::audit::AuditService;
use anvil_core::service::key_rotation::RotationPolicy;
use anvil_jose::Kek;
use anvil_storage_sqlite::SqliteStorage;
use jobs::{JobIntervals, LeaseRunner, PeriodicJob};
use time::OffsetDateTime;
use tokio::sync::watch;
use tokio::task::JoinSet;

async fn storage(dir: &tempfile::TempDir) -> Arc<dyn Storage> {
    let url = format!("sqlite://{}", dir.path().join("jobs.db").display());
    let s = SqliteStorage::connect(&url).await.expect("connect");
    s.migrate().await.expect("migrate");
    Arc::new(s)
}

fn runner(storage: &Arc<dyn Storage>, node: &str) -> Arc<LeaseRunner> {
    Arc::new(LeaseRunner {
        storage: Arc::clone(storage),
        clock: Arc::new(SystemClock),
        node_id: node.to_owned(),
        lease: Duration::from_secs(60),
    })
}

/// Counts runs and records the highest number of runs in progress at once.
#[derive(Default)]
struct CountingJob {
    runs: AtomicUsize,
    running: AtomicUsize,
    max_running: AtomicUsize,
}

impl PeriodicJob for CountingJob {
    fn name(&self) -> &'static str {
        "counting_job"
    }

    fn run(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            let now = self.running.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_running.fetch_max(now, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(30)).await;
            self.running.fetch_sub(1, Ordering::SeqCst);
            self.runs.fetch_add(1, Ordering::SeqCst);
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_runners_never_run_the_same_job_concurrently() {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = storage(&dir).await;
    let job = Arc::new(CountingJob::default());
    let (stop_tx, stop_rx) = watch::channel(false);
    let mut set = JoinSet::new();
    for node in ["node-a", "node-b"] {
        let r = runner(&storage, node);
        let job: Arc<dyn PeriodicJob> = Arc::clone(&job) as Arc<dyn PeriodicJob>;
        set.spawn(r.schedule(job, Duration::from_millis(5), stop_rx.clone()));
    }
    tokio::time::sleep(Duration::from_millis(1500)).await;
    stop_tx.send(true).expect("stop");
    while set.join_next().await.is_some() {}

    let runs = job.runs.load(Ordering::SeqCst);
    assert!(runs >= 5, "the job ran only {runs} times");
    assert_eq!(
        job.max_running.load(Ordering::SeqCst),
        1,
        "two runners ran the job at the same time"
    );
}

#[tokio::test]
async fn a_held_lease_blocks_other_nodes_until_released() {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = storage(&dir).await;
    let now = SystemClock.now();
    assert!(
        storage
            .jobs()
            .try_lease(
                "counting_job",
                "node-a",
                now + time::Duration::minutes(5),
                now
            )
            .await
            .expect("lease")
    );
    let job = CountingJob::default();
    let b = runner(&storage, "node-b");
    assert!(
        !b.run_once(&job).await,
        "node-b ran while node-a held the lease"
    );
    assert_eq!(job.runs.load(Ordering::SeqCst), 0);

    storage
        .jobs()
        .release("counting_job", "node-a")
        .await
        .expect("release");
    assert!(b.run_once(&job).await);
    assert_eq!(job.runs.load(Ordering::SeqCst), 1);
    // run_once releases its lease: node-a can take it again.
    let a = runner(&storage, "node-a");
    assert!(a.run_once(&job).await);
}

/// A clock fixed at one instant (records old audit events).
struct FixedClock(OffsetDateTime);

impl Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        self.0
    }
}

async fn audit_count(storage: &Arc<dyn Storage>, tenant: TenantId) -> usize {
    storage
        .audit()
        .query(
            tenant,
            &AuditQuery {
                limit: 200,
                ..AuditQuery::default()
            },
        )
        .await
        .expect("query")
        .items
        .len()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn production_jobs_rotate_purge_and_apply_audit_retention() {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = storage(&dir).await;
    let now = SystemClock.now();
    let tenant = storage
        .tenants()
        .create(&NewTenant {
            id: TenantId::new_v7(),
            slug: "acme".to_owned(),
            display_name: "Acme".to_owned(),
            host: None,
            settings: TenantSettings::default(),
            created_at: now,
        })
        .await
        .expect("tenant");
    assert!(
        storage
            .keys()
            .active(tenant.id, "RS256")
            .await
            .expect("active")
            .is_none()
    );

    // One event older than the retention, one recent.
    for at in [now - time::Duration::days(400), now] {
        AuditService {
            storage: Arc::clone(&storage),
            clock: Arc::new(FixedClock(at)),
        }
        .record(
            tenant.id,
            AuditActor::system(),
            AuditAction::TenantUpdated,
            None,
            AuditOutcome::Success,
            &RequestContext::system(),
            AuditDetails::empty(),
        )
        .await
        .expect("record");
    }
    assert_eq!(audit_count(&storage, tenant.id).await, 2);

    let (stop_tx, stop_rx) = watch::channel(false);
    let mut set = JoinSet::new();
    let r = runner(&storage, "node-a");
    jobs::spawn_periodic(
        &mut set,
        &r,
        &Arc::new(Kek::generate()),
        RotationPolicy::default(),
        Some(time::Duration::days(365)),
        JobIntervals {
            rotation: Duration::from_millis(50),
            purge: Duration::from_millis(50),
            audit_retention: Duration::from_millis(50),
        },
        &stop_rx,
    );

    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let rotated = storage
            .keys()
            .active(tenant.id, "RS256")
            .await
            .expect("active")
            .is_some();
        // The rotation job audits key_generated/key_activated; retention removed the old event.
        let events = storage
            .audit()
            .query(
                tenant.id,
                &AuditQuery {
                    limit: 200,
                    ..AuditQuery::default()
                },
            )
            .await
            .expect("query")
            .items;
        let old_gone = events
            .iter()
            .all(|e| e.at > now - time::Duration::days(365));
        if rotated && old_gone {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "jobs did not run: rotated={rotated} old_gone={old_gone}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    stop_tx.send(true).expect("stop");
    tokio::time::timeout(Duration::from_secs(10), async {
        while set.join_next().await.is_some() {}
    })
    .await
    .expect("jobs stop on shutdown");
    // Leases are released after each run.
    let later = SystemClock.now();
    for name in ["key_rotation", "purge_expired", "audit_retention"] {
        assert!(
            storage
                .jobs()
                .try_lease(name, "node-b", later + time::Duration::minutes(1), later)
                .await
                .expect("lease"),
            "{name} lease still held"
        );
    }
}
